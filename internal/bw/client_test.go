package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeCall records one runner invocation.
type fakeCall struct {
	Args  []string
	Stdin []byte
	Env   []string
}

// fakeRunner answers by joined-args key and records every call.
type fakeRunner struct {
	Calls     []fakeCall
	Responses map[string][]byte
	Errs      map[string]error
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, env []string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, fakeCall{Args: args, Stdin: stdin, Env: env})
	key := strings.Join(args, " ")
	if err := f.Errs[key]; err != nil {
		return nil, err
	}
	return f.Responses[key], nil
}

func (f *fakeRunner) callKeys() []string {
	keys := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		keys = append(keys, strings.Join(c.Args, " "))
	}
	return keys
}

func TestClientUnlock_PasswordViaEnvOnly(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"unlock --passwordenv BW_PASSWORD --raw": []byte("session-token\n"),
		"sync":                                   nil,
	}}
	c := NewClient(r)
	if err := c.Unlock(context.Background(), "hunter2"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	call := r.Calls[0]
	for _, a := range call.Args {
		if strings.Contains(a, "hunter2") {
			t.Fatalf("master password leaked into argv: %v", call.Args)
		}
	}
	if len(call.Env) != 1 || call.Env[0] != "BW_PASSWORD=hunter2" {
		t.Fatalf("env = %v, want BW_PASSWORD only", call.Env)
	}
	// Subsequent calls must carry the trimmed session via env.
	if err := c.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	syncCall := r.Calls[1]
	if len(syncCall.Env) != 1 || syncCall.Env[0] != "BW_SESSION=session-token" {
		t.Fatalf("sync env = %v, want BW_SESSION=session-token", syncCall.Env)
	}
}

func TestClientUnlock_EmptySessionFails(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"unlock --passwordenv BW_PASSWORD --raw": []byte("  \n"),
	}}
	if err := NewClient(r).Unlock(context.Background(), "pw"); err == nil {
		t.Fatal("want error for empty session token")
	}
}

func TestEnsureSession_ValidEnvSessionWins(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"status": []byte(`{"serverUrl":"https://v.example","status":"unlocked"}`),
	}}
	c := NewClient(r)
	err := c.EnsureSession(context.Background(), "env-token", func(context.Context) (string, error) {
		t.Fatal("password must not be read when the env session is valid")
		return "", nil
	})
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}
	if got := r.Calls[0].Env[0]; got != "BW_SESSION=env-token" {
		t.Fatalf("status env = %q, want inherited session", got)
	}
}

func TestEnsureSession_StaleEnvSessionFallsBackToUnlock(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"status":                                 []byte(`{"serverUrl":"https://v.example","status":"locked"}`),
		"unlock --passwordenv BW_PASSWORD --raw": []byte("fresh-token"),
	}}
	c := NewClient(r)
	err := c.EnsureSession(context.Background(), "stale-token", func(context.Context) (string, error) {
		return "master-pw", nil
	})
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}
	if c.session != "fresh-token" {
		t.Fatalf("session = %q, want fresh-token", c.session)
	}
}

func TestEnsureSession_UnauthenticatedFailsWithLoginHint(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"status": []byte(`{"serverUrl":"https://v.example","status":"unauthenticated"}`),
	}}
	err := NewClient(r).EnsureSession(context.Background(), "", func(context.Context) (string, error) {
		t.Fatal("password must not be read when not logged in")
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "bw login") {
		t.Fatalf("err = %v, want bw-login hint", err)
	}
}

func TestCreateItem_PayloadViaStdinNotArgv(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"create item": []byte(`{"id":"new-id","type":1,"name":"a","folderId":"f1"}`),
	}}
	c := NewClient(r)
	c.session = "tok"
	in := Item{Type: TypeLogin, Name: "a", FolderID: "f1", Login: &Login{Password: "s3cr3t"}}
	created, err := c.CreateItem(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	if created.ID != "new-id" {
		t.Fatalf("created.ID = %q, want new-id", created.ID)
	}
	call := r.Calls[0]
	if strings.Join(call.Args, " ") != "create item" {
		t.Fatalf("args = %v, want bare create item (payload via stdin)", call.Args)
	}
	raw, err := base64.StdEncoding.DecodeString(string(call.Stdin))
	if err != nil {
		t.Fatalf("stdin is not base64: %v", err)
	}
	var sent Item
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("stdin payload is not item JSON: %v", err)
	}
	if sent.Login == nil || sent.Login.Password != "s3cr3t" {
		t.Fatalf("payload round-trip lost the password slot: %+v", sent)
	}
}

func TestEditItem_IDInArgvPayloadInStdin(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{}}
	c := NewClient(r)
	if err := c.EditItem(context.Background(), "item-1", Item{Type: TypeLogin, Name: "a"}); err != nil {
		t.Fatalf("EditItem: %v", err)
	}
	call := r.Calls[0]
	if strings.Join(call.Args, " ") != "edit item item-1" {
		t.Fatalf("args = %v", call.Args)
	}
	if len(call.Stdin) == 0 {
		t.Fatal("edit payload must travel via stdin")
	}
}

func TestFetchRemoteState_OnlyNamespaceFoldersAreRead(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"list folders": []byte(`[
			{"id":"f1","name":"mys/jasp"},
			{"id":"f2","name":"Private Stuff"},
			{"id":"f3","name":"mys"}
		]`),
		"list items --folderid f1": []byte(`[{"id":"i1","type":1,"name":"a","folderId":"f1"}]`),
		"list items --folderid f3": []byte(`[]`),
	}}
	rs, err := FetchRemoteState(context.Background(), NewClient(r), "")
	if err != nil {
		t.Fatalf("FetchRemoteState: %v", err)
	}
	if len(rs.Folders) != 2 || len(rs.Items) != 1 {
		t.Fatalf("state = %+v, want 2 namespace folders, 1 item", rs)
	}
	for _, key := range r.callKeys() {
		if strings.Contains(key, "f2") {
			t.Fatal("items of a non-namespace folder were read")
		}
	}
	if rs.FolderNames["f1"] != "mys/jasp" {
		t.Errorf("FolderNames = %v", rs.FolderNames)
	}
}

func TestFetchRemoteState_OrgFilterRestrictsToOneFolder(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"list folders": []byte(`[
			{"id":"f1","name":"mys/jasp"},
			{"id":"f3","name":"mys/zuhause"}
		]`),
		"list items --folderid f1": []byte(`[]`),
	}}
	rs, err := FetchRemoteState(context.Background(), NewClient(r), "jasp")
	if err != nil {
		t.Fatalf("FetchRemoteState: %v", err)
	}
	if len(rs.Folders) != 1 || rs.Folders[0].Name != "mys/jasp" {
		t.Fatalf("folders = %+v, want only mys/jasp", rs.Folders)
	}
	for _, key := range r.callKeys() {
		if strings.Contains(key, "f3") {
			t.Fatal("filtered-out org folder was read")
		}
	}
}

func TestExecutePush_ResolvesCreatedFolderIDs(t *testing.T) {
	r := &fakeRunner{Responses: map[string][]byte{
		"create folder": []byte(`{"id":"srv-folder","name":"mys/jasp"}`),
		"create item":   []byte(`{"id":"srv-item"}`),
	}}
	c := NewClient(r)
	plan := PushPlan{
		CreateFolders: []string{"mys/jasp"},
		Creates: []PlannedWrite{{
			Path: "jasp/a", Folder: "mys/jasp",
			Item: Item{Type: TypeLogin, Name: "a", Login: &Login{Password: "x"}},
		}},
	}
	res, err := ExecutePush(context.Background(), c, plan, RemoteState{})
	if err != nil {
		t.Fatalf("ExecutePush: %v", err)
	}
	if res.CreatedFolders != 1 || res.Created != 1 {
		t.Fatalf("res = %+v", res)
	}
	// The pushed item must carry the SERVER-assigned folder id, not the
	// deterministic export id.
	raw, _ := base64.StdEncoding.DecodeString(string(r.Calls[1].Stdin))
	var sent Item
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatalf("item payload: %v", err)
	}
	if sent.FolderID != "srv-folder" {
		t.Fatalf("FolderID = %q, want srv-folder", sent.FolderID)
	}
}

func TestExecutePush_AbortsOnFirstErrorWithPartialResult(t *testing.T) {
	r := &fakeRunner{
		Responses: map[string][]byte{},
		Errs:      map[string]error{"delete item i2": errors.New("boom")},
	}
	c := NewClient(r)
	plan := PushPlan{Prunes: []PlannedPrune{{ID: "i1", Path: "a"}, {ID: "i2", Path: "b"}, {ID: "i3", Path: "c"}}}
	res, err := ExecutePush(context.Background(), c, plan, RemoteState{})
	if err == nil {
		t.Fatal("want error")
	}
	if res.Pruned != 1 {
		t.Fatalf("Pruned = %d, want 1 (partial progress reported)", res.Pruned)
	}
	if len(r.Calls) != 2 {
		t.Fatalf("calls = %v, must stop at first failure", r.callKeys())
	}
}
