package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// stubBWRunner is a canned-response bw.Runner for cmd-level push tests.
type stubBWRunner struct {
	Calls     [][]string
	Envs      [][]string
	Responses map[string][]byte
}

func (s *stubBWRunner) Run(_ context.Context, _ []byte, env []string, args ...string) ([]byte, error) {
	s.Calls = append(s.Calls, args)
	s.Envs = append(s.Envs, env)
	return s.Responses[strings.Join(args, " ")], nil
}

func (s *stubBWRunner) called(prefix string) bool {
	for _, c := range s.Calls {
		if strings.HasPrefix(strings.Join(c, " "), prefix) {
			return true
		}
	}
	return false
}

// unlockedStatus is the canned `bw status` payload for a ready vault.
var unlockedStatus = []byte(`{"serverUrl":"https://vault.example","userEmail":"t@e.local","status":"unlocked"}`)

// mirrorItemJSON renders entries the way a previous push left them in
// the vault: one JSON array of mapped items with server ids.
func mirrorItemJSON(t *testing.T, folderID string, entries ...*store.Entry) []byte {
	t.Helper()
	items := make([]bw.Item, 0, len(entries))
	for i, e := range entries {
		it, err := bw.ItemFromEntry(e)
		if err != nil {
			t.Fatalf("ItemFromEntry: %v", err)
		}
		it.ID = string(rune('a' + i))
		it.FolderID = folderID
		items = append(items, it)
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bwPushRows(t *testing.T, a *app.App) []audit.Entry {
	t.Helper()
	rows, err := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionBWPush})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	return rows
}

func TestBwPushCmd_RefusesAICallersAndAuditsIt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	prev := openAuditOnly
	openAuditOnly = func() (*app.App, error) {
		l, err := audit.Open(dbPath)
		if err != nil {
			return nil, err
		}
		return &app.App{Audit: l, Override: "ai"}, nil
	}
	t.Cleanup(func() { openAuditOnly = prev })

	req := "ai"
	c := bwPushCmd(&req)
	c.SetArgs([]string{})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "refused for AI callers") {
		t.Errorf("err = %v, want AI refusal", err)
	}
	l, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen audit: %v", err)
	}
	defer l.Close()
	rows, err := l.Tail(context.Background(), audit.Filter{Action: audit.ActionBWPush})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("rows = %+v, want exactly one denied bw_push row", rows)
	}
}

func TestRunBwPush_NoOpWhenVaultInSync(t *testing.T) {
	e := &store.Entry{Path: "jasp/a", Org: "jasp", Username: "u", Password: "x"}
	a := fakeApp(t, e)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": mirrorItemJSON(t, "f1", e),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: "tok", Prune: true})
	if err != nil {
		t.Fatalf("runBwPush: %v", err)
	}
	for _, mutating := range []string{"create", "edit", "delete"} {
		if r.called(mutating) {
			t.Errorf("in-sync run must not call bw %s", mutating)
		}
	}
	rows := bwPushRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK || !strings.Contains(rows[0].Reason, "no-op") {
		t.Fatalf("rows = %+v, want one ok no-op row", rows)
	}
	if !strings.Contains(stdout.String(), "already in sync") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunBwPush_DryRunPlansButWritesNothing(t *testing.T) {
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":       unlockedStatus,
		"list folders": []byte(`[]`),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: "tok", DryRun: true})
	if err != nil {
		t.Fatalf("runBwPush: %v", err)
	}
	if r.called("create") {
		t.Error("dry-run must not create anything")
	}
	out := stdout.String()
	if !strings.Contains(out, "+ jasp/a") || !strings.Contains(out, "+ folder mys/jasp") {
		t.Errorf("plan output missing create lines:\n%s", out)
	}
	if strings.Contains(out, "x") && strings.Contains(out, "password") {
		t.Errorf("plan output must never carry values:\n%s", out)
	}
	rows := bwPushRows(t, a)
	if len(rows) != 1 || !strings.Contains(rows[0].Reason, "dry-run") || !strings.Contains(rows[0].Reason, "create=1") {
		t.Fatalf("rows = %+v, want one dry-run row with create=1", rows)
	}
}

func TestRunBwPush_CreatesAndAudits(t *testing.T) {
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Password: "s3cr3t"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":        unlockedStatus,
		"list folders":  []byte(`[]`),
		"create folder": []byte(`{"id":"srv-f","name":"mys/jasp"}`),
		"create item":   []byte(`{"id":"srv-i"}`),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: "tok", Yes: true})
	if err != nil {
		t.Fatalf("runBwPush: %v", err)
	}
	if !r.called("create folder") || !r.called("create item") {
		t.Fatalf("calls = %v, want folder + item creation", r.Calls)
	}
	rows := bwPushRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK ||
		!strings.Contains(rows[0].Reason, "create=1") ||
		!strings.Contains(rows[0].Reason, "server=https://vault.example") {
		t.Fatalf("rows = %+v, want ok row with server + create=1", rows)
	}
	if !strings.Contains(stdout.String(), "1 created") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestRunBwPush_AbortsWithoutConfirmation(t *testing.T) {
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":       unlockedStatus,
		"list folders": []byte(`[]`),
	}}
	var stdout, stderr bytes.Buffer
	// Non-TTY stdin without --yes must abort before any write.
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: "tok"})
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("err = %v, want abort", err)
	}
	if r.called("create") {
		t.Error("aborted run must not write")
	}
	rows := bwPushRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("rows = %+v, want one denied (aborted) row", rows)
	}
}

func TestRunBwPush_ServerMismatchRefuses(t *testing.T) {
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status": unlockedStatus,
	}}
	var stdout, stderr bytes.Buffer
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{Session: "tok", Config: &bw.Config{ServerURL: "https://other.example"}})
	if err == nil || !strings.Contains(err.Error(), "server mismatch") {
		t.Fatalf("err = %v, want server-mismatch refusal", err)
	}
	if r.called("sync") || r.called("list") {
		t.Error("mismatch must refuse before reading anything")
	}
	rows := bwPushRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("rows = %+v, want one error row", rows)
	}
}

func TestRunBwPush_UnlockReadsMasterPasswordViaAuditedGet(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"},
		&store.Entry{Path: bw.DefaultMasterPasswordPath, Org: "private", Password: "master-pw"},
	)
	locked := []byte(`{"serverUrl":"https://vault.example","userEmail":"t@e.local","status":"locked"}`)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                                 locked,
		"unlock --passwordenv BW_PASSWORD --raw": []byte("fresh-tok"),
		"list folders":                           []byte(`[]`),
	}}
	var stdout, stderr bytes.Buffer
	// --org jasp keeps the master-password entry itself out of the
	// mirrored slice, so the only get row for its path is the unlock read.
	err := runBwPush(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwPushOptions{DryRun: true, Org: "jasp"})
	if err != nil {
		t.Fatalf("runBwPush: %v", err)
	}
	// The unlock call must carry the password via env only.
	found := false
	for i, c := range r.Calls {
		if strings.HasPrefix(strings.Join(c, " "), "unlock") {
			found = true
			if len(r.Envs[i]) != 1 || r.Envs[i][0] != "BW_PASSWORD=master-pw" {
				t.Fatalf("unlock env = %v", r.Envs[i])
			}
		}
	}
	if !found {
		t.Fatal("unlock was never called")
	}
	// The master-password read must show up as a normal audited get.
	rows, err := a.Audit.Tail(context.Background(),
		audit.Filter{Action: audit.ActionGet, Path: bw.DefaultMasterPasswordPath})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("rows = %+v, want one ok get row for the master password", rows)
	}
}
