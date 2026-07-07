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
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// phoneItemJSON renders login items the way phone-created entries look
// in the vault: inside a mys/* folder but without the mys-path key.
func phoneItemJSON(t *testing.T, folderID string, names ...string) []byte {
	t.Helper()
	items := make([]bw.Item, 0, len(names))
	for i, n := range names {
		items = append(items, bw.Item{
			ID: string(rune('p' + i)), Type: bw.TypeLogin, Name: n,
			FolderID: folderID, Login: &bw.Login{Username: "pu", Password: "phone-pw-value"},
		})
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bwImportRows(t *testing.T, a *app.App) []audit.Entry {
	t.Helper()
	rows, err := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionBWImport})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	return rows
}

func addRows(t *testing.T, a *app.App) []audit.Entry {
	t.Helper()
	rows, err := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionAdd})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	return rows
}

func TestBwImportCmd_RefusesAICallersAndAuditsIt(t *testing.T) {
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
	c := bwImportCmd(&req)
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
	rows, err := l.Tail(context.Background(), audit.Filter{Action: audit.ActionBWImport})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("rows = %+v, want exactly one denied bw_import row", rows)
	}
}

func TestBwImportCmd_RejectsNestedOrg(t *testing.T) {
	req := "human"
	c := bwImportCmd(&req)
	c.SetArgs([]string{"--org", "jasp/stage"})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "top-level org") {
		t.Errorf("err = %v, want nested-org refusal", err)
	}
}

func TestRunBwImport_DiffOnlyWritesNothing(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword, Password: "old-pw-value"},
		&store.Entry{Path: "jasp/only", Org: "jasp", Kind: store.KindPassword, Password: "only-pw-value"},
	)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":       unlockedStatus,
		"sync":         nil,
		"list folders": []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": combineItemJSON(t,
			mirrorItemJSON(t, "f1", &store.Entry{Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword, Password: "new-pw-value"}),
			phoneItemJSON(t, "f1", "phone"),
		),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok"})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "CHANGED") || !strings.Contains(out, "jasp/changed (password)") {
		t.Errorf("diff output missing CHANGED row:\n%s", out)
	}
	if !strings.Contains(out, "NEW") || !strings.Contains(out, "jasp/phone") {
		t.Errorf("diff output missing NEW row:\n%s", out)
	}
	if !strings.Contains(out, "STORE-ONLY") || !strings.Contains(out, "jasp/only") {
		t.Errorf("diff output missing STORE-ONLY row:\n%s", out)
	}
	for _, v := range []string{"old-pw-value", "new-pw-value", "phone-pw-value", "only-pw-value"} {
		if strings.Contains(out, v) || strings.Contains(stderr.String(), v) {
			t.Errorf("output must never carry secret values (%q):\n%s", v, out)
		}
	}
	for _, mutating := range []string{"create", "edit", "delete"} {
		if r.called(mutating) {
			t.Errorf("diff-only run must not call bw %s", mutating)
		}
	}
	if rows := addRows(t, a); len(rows) != 0 {
		t.Errorf("diff-only run must not write to the store: %+v", rows)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK ||
		!strings.Contains(rows[0].Reason, "diff-only") ||
		!strings.Contains(rows[0].Reason, "new=1 changed=1 store_only=1") {
		t.Fatalf("rows = %+v, want one ok diff-only row with counts", rows)
	}
}

func TestRunBwImport_ApplyYesWritesViaAdd(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword,
			Username: "keep-user", Password: "old-pw-value", Notes: "keep-note"},
	)
	remote := mirrorItemJSON(t, "f1", &store.Entry{Path: "jasp/changed", Org: "jasp", Kind: store.KindPassword,
		Username: "keep-user", Password: "new-pw-value", Notes: "keep-note"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"},{"id":"f2","name":"mys/zuhause"}]`),
		"list items --folderid f1": remote,
		"list items --folderid f2": phoneItemJSON(t, "f2", "router"),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok", Apply: true, Yes: true})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	got, err := a.Store.Get(context.Background(), "jasp/changed")
	if err != nil {
		t.Fatalf("store get: %v", err)
	}
	if got.Password != "new-pw-value" || got.Username != "keep-user" || got.Notes != "keep-note" {
		t.Errorf("CHANGED apply must overwrite exactly the diffed fields: %+v", got)
	}
	created, err := a.Store.Get(context.Background(), "zuhause/router")
	if err != nil {
		t.Fatalf("NEW apply must create the entry: %v", err)
	}
	if created.Password != "phone-pw-value" || created.Username != "pu" {
		t.Errorf("created entry = %+v", created)
	}
	if rows := addRows(t, a); len(rows) != 2 {
		t.Errorf("want one add row per applied entry, got %+v", rows)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK ||
		!strings.Contains(rows[0].Reason, "applied=2 skipped=0 failed=0") {
		t.Fatalf("rows = %+v, want one ok row with applied=2", rows)
	}
	for _, mutating := range []string{"create", "edit", "delete"} {
		if r.called(mutating) {
			t.Errorf("import must never write to Bitwarden (bw %s called)", mutating)
		}
	}
}

func TestRunBwImport_PolicyInvisiblePathsExcludedFromDiffAndWrite(t *testing.T) {
	// The caller's scope policy hides zuhause/** — vault items mapping
	// there must neither show up in the diff (path leak) nor ever be
	// written. App.Add would refuse the write anyway; this pins the
	// earlier line of defence.
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Kind: store.KindPassword, Password: "x"})
	a.Policy = &policy.Policy{Actors: map[string]policy.Rules{
		"human": {Allow: []string{"jasp/**"}},
	}}
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f2","name":"mys/zuhause"}]`),
		"list items --folderid f2": phoneItemJSON(t, "f2", "router"),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok", Apply: true, Yes: true})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	if strings.Contains(stdout.String(), "zuhause/router") {
		t.Errorf("policy-invisible path must not appear in the diff:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy-invisible") {
		t.Errorf("stderr = %q, want count-only policy-invisible warning", stderr.String())
	}
	if strings.Contains(stderr.String(), "zuhause/router") {
		t.Errorf("the warning must not name the hidden path: %q", stderr.String())
	}
	if _, err := a.Store.Get(context.Background(), "zuhause/router"); err == nil {
		t.Error("policy-hidden item must never reach the store")
	}
	if rows := addRows(t, a); len(rows) != 0 {
		t.Errorf("no add rows expected: %+v", rows)
	}
}

func TestRunBwImport_NonInteractiveWithoutYesAborts(t *testing.T) {
	a := fakeApp(t)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f2","name":"mys/zuhause"}]`),
		"list items --folderid f2": phoneItemJSON(t, "f2", "router"),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok", Apply: true})
	if err == nil || !strings.Contains(err.Error(), "non-interactive") {
		t.Fatalf("err = %v, want non-interactive abort", err)
	}
	if rows := addRows(t, a); len(rows) != 0 {
		t.Errorf("aborted run must not write: %+v", rows)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("rows = %+v, want one denied row", rows)
	}
}

func TestRunBwImport_InteractiveYNQFlow(t *testing.T) {
	a := fakeApp(t)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(t, "f1", "a", "b", "c"),
	}}
	stdin := bytes.NewBufferString("y\nn\nq\n")
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), stdin, &stdout, &stderr,
		bwImportOptions{Session: "tok", Apply: true, Interactive: true})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	if _, err := a.Store.Get(context.Background(), "jasp/a"); err != nil {
		t.Errorf("answer y must apply jasp/a: %v", err)
	}
	for _, p := range []string{"jasp/b", "jasp/c"} {
		if _, err := a.Store.Get(context.Background(), p); err == nil {
			t.Errorf("%s must not be applied (answered n / q)", p)
		}
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK ||
		!strings.Contains(rows[0].Reason, "applied=1 skipped=2 failed=0") {
		t.Fatalf("rows = %+v, want one ok row with applied=1 skipped=2", rows)
	}
}

func TestRunBwImport_MasterPasswordNeverImported(t *testing.T) {
	mp := &store.Entry{Path: bw.DefaultMasterPasswordPath, Org: "private", Kind: store.KindPassword, Password: "master-pw"}
	a := fakeApp(t, mp)
	remote := mirrorItemJSON(t, "f1", &store.Entry{Path: bw.DefaultMasterPasswordPath, Org: "private",
		Kind: store.KindPassword, Password: "tampered-pw"})
	r := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/private"}]`),
		"list items --folderid f1": remote,
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok", Apply: true, Yes: true})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	if !strings.Contains(stderr.String(), "master password is never imported") {
		t.Errorf("stderr = %q, want master-password warning", stderr.String())
	}
	got, err := a.Store.Get(context.Background(), bw.DefaultMasterPasswordPath)
	if err != nil || got.Password != "master-pw" {
		t.Errorf("master password must stay untouched, got %+v (err %v)", got, err)
	}
	if rows := addRows(t, a); len(rows) != 0 {
		t.Errorf("no writes expected: %+v", rows)
	}
}

func TestRunBwImport_ServerMismatchRefuses(t *testing.T) {
	a := fakeApp(t)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status": unlockedStatus,
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{Session: "tok", Config: &bw.Config{ServerURL: "https://other.example"}})
	if err == nil || !strings.Contains(err.Error(), "server mismatch") {
		t.Fatalf("err = %v, want server-mismatch refusal", err)
	}
	if r.called("sync") || r.called("list") {
		t.Error("mismatch must refuse before reading anything")
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("rows = %+v, want one error row", rows)
	}
}

func TestRunBwImport_EarlyFailureWritesSanitizedAuditRow(t *testing.T) {
	a := fakeApp(t)
	r := &stubBWRunner{Responses: map[string][]byte{
		"status": []byte(`{"serverUrl":"https://v.example","status":"unauthenticated"}`),
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(r), &bytes.Buffer{}, &stdout, &stderr,
		bwImportOptions{})
	if err == nil {
		t.Fatal("want session setup error")
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError || rows[0].Reason != "session setup failed" {
		t.Fatalf("rows = %+v, want one sanitized session-setup error row", rows)
	}
}

// combineItemJSON merges multiple JSON item arrays into one.
func combineItemJSON(t *testing.T, arrays ...[]byte) []byte {
	t.Helper()
	var all []json.RawMessage
	for _, a := range arrays {
		var items []json.RawMessage
		if err := json.Unmarshal(a, &items); err != nil {
			t.Fatalf("combine: %v", err)
		}
		all = append(all, items...)
	}
	b, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
