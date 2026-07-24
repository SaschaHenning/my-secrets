package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
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
	c.SetArgs([]string{
		"--org", "jasp",
		"--mount", "jasp-shared",
		"--apply",
		"--yes",
	})
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
	if rows[0].Org != "jasp-shared" {
		t.Fatalf("audit org = %q, want target mount jasp-shared", rows[0].Org)
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

func TestBwImportCmd_ExposesMountAndRejectsArguments(t *testing.T) {
	req := "human"
	c := bwImportCmd(&req)
	if c.Flags().Lookup("mount") == nil {
		t.Fatal("bw-import has no --mount flag")
	}
	c.SetArgs([]string{"unexpected"})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "unknown command") &&
		!strings.Contains(err.Error(), "accepts 0 arg") {
		t.Fatalf("error = %v, want positional-argument refusal", err)
	}
}

func TestValidateBwImportOptions_SharedTargetFailsClosed(t *testing.T) {
	shared := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
	}}}
	tests := []struct {
		name string
		opts bwImportOptions
		want string
	}{
		{
			name: "mount requires source org",
			opts: bwImportOptions{Mount: "jasp-shared", SyncConfig: shared},
			want: "--mount requires --org",
		},
		{
			name: "nested source org",
			opts: bwImportOptions{Org: "jasp/stage", Mount: "jasp-shared", SyncConfig: shared},
			want: "top-level org",
		},
		{
			name: "root cannot be shared target",
			opts: bwImportOptions{Org: "jasp", Mount: syncpkg.DefaultStoreMount, SyncConfig: shared},
			want: "cannot be shared",
		},
		{
			name: "missing config",
			opts: bwImportOptions{Org: "jasp", Mount: "jasp-shared"},
			want: "not configured as shared",
		},
		{
			name: "personal target",
			opts: bwImportOptions{
				Org: "jasp", Mount: "personal",
				SyncConfig: &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
					Mount: "personal", URL: "file:///personal.git",
				}}},
			},
			want: "not configured as shared",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateBwImportOptions(test.opts)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	if err := validateBwImportOptions(bwImportOptions{
		Org: "jasp", Mount: "jasp-shared", SyncConfig: shared,
	}); err != nil {
		t.Fatalf("valid shared target rejected: %v", err)
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

func TestRunBwImport_SharedMountRebasesPullsAndSyncsOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{
		{Mount: "root", URL: "file:///personal.git"},
		{Mount: "jasp-shared", URL: "file:///shared.git", Shared: true},
	}}
	if err := syncpkg.Save("", config); err != nil {
		t.Fatalf("save sync config: %v", err)
	}
	a := fakeApp(t,
		&store.Entry{
			Path: "jasp-shared/changed", Org: "jasp-shared",
			Kind: store.KindPassword, Password: "old-value",
		},
		&store.Entry{
			Path: "jasp/personal", Org: "jasp",
			Kind: store.KindPassword, Password: "keep-personal",
		},
	)
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":       unlockedStatus,
		"sync":         nil,
		"list folders": []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": combineItemJSON(t,
			mirrorItemJSON(t, "f1", &store.Entry{
				Path: "jasp/changed", Org: "jasp",
				Kind: store.KindPassword, Password: "new-value",
			}),
			phoneItemJSON(t, "f1", "phone"),
		),
	}}
	syncRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
		"gopass sync --store jasp-shared":                 {},
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(
		context.Background(),
		a,
		bw.NewClient(bwRunner),
		&bytes.Buffer{},
		&stdout,
		&stderr,
		bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		},
	)
	if err != nil {
		t.Fatalf("runBwImport: %v\nstdout:\n%s\nstderr:\n%s",
			err, stdout.String(), stderr.String())
	}
	changed, err := a.Store.Get(context.Background(), "jasp-shared/changed")
	if err != nil || changed.Password != "new-value" {
		t.Fatalf("shared changed entry = %+v, err=%v", changed, err)
	}
	created, err := a.Store.Get(context.Background(), "jasp-shared/phone")
	if err != nil || created.Password != "phone-pw-value" {
		t.Fatalf("shared phone entry = %+v, err=%v", created, err)
	}
	personal, err := a.Store.Get(context.Background(), "jasp/personal")
	if err != nil || personal.Password != "keep-personal" {
		t.Fatalf("personal entry changed: %+v, err=%v", personal, err)
	}
	if _, err := a.Store.Get(context.Background(), "jasp/phone"); err == nil {
		t.Fatal("source namespace unexpectedly received imported entry")
	}
	var pullCount, syncCount int
	for _, call := range syncRunner.calls {
		if strings.Contains(call, " pull ") {
			pullCount++
		}
		if call == "gopass sync --store jasp-shared" {
			syncCount++
		}
	}
	if pullCount != 1 || syncCount != 1 {
		t.Fatalf("sync calls = %v, want one pull and one final sync", syncRunner.calls)
	}
	remote, ok := config.Remote("jasp-shared")
	if !ok || remote.LastSync.IsZero() {
		t.Fatalf("shared LastSync not updated: %+v", config.Remotes)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultOK ||
		rows[0].Org != "jasp-shared" ||
		!strings.Contains(rows[0].Reason, "source_org=jasp") ||
		!strings.Contains(rows[0].Reason, "target_mount=jasp-shared") {
		t.Fatalf("shared import audit rows = %+v", rows)
	}
	for _, secret := range []string{
		"old-value", "new-value", "phone-pw-value", "keep-personal",
	} {
		if strings.Contains(stdout.String(), secret) ||
			strings.Contains(stderr.String(), secret) ||
			strings.Contains(rows[0].Reason, secret) {
			t.Fatalf("secret %q leaked from shared import", secret)
		}
	}

	var secondOut, secondErr bytes.Buffer
	err = runBwImport(
		context.Background(),
		a,
		bw.NewClient(bwRunner),
		&bytes.Buffer{},
		&secondOut,
		&secondErr,
		bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		},
	)
	if err != nil {
		t.Fatalf("second runBwImport: %v", err)
	}
	if !strings.Contains(secondOut.String(), "store already in sync") {
		t.Fatalf("second output = %q, want explicit no-op", secondOut.String())
	}
	syncCount = 0
	for _, call := range syncRunner.calls {
		if call == "gopass sync --store jasp-shared" {
			syncCount++
		}
	}
	if syncCount != 1 {
		t.Fatalf("second run triggered another shared sync: %v", syncRunner.calls)
	}
	rows = bwImportRows(t, a)
	if len(rows) != 2 ||
		!strings.Contains(rows[0].Reason, "no-op") ||
		rows[0].Result != audit.ResultOK {
		t.Fatalf("second import audit rows = %+v, want latest no-op", rows)
	}
}

func TestRunBwImport_SharedPolicyEvaluatesTargetPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
	}}}
	a := fakeApp(t)
	a.Policy = &policy.Policy{Actors: map[string]policy.Rules{
		"human": {Allow: []string{"jasp/**"}},
	}}
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(t, "f1", "hidden"),
	}}
	syncRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(bwRunner),
		&bytes.Buffer{}, &stdout, &stderr, bwImportOptions{
			Org: "jasp", Mount: "jasp-shared", Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		})
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	if strings.Contains(stdout.String(), "jasp-shared/hidden") ||
		strings.Contains(stderr.String(), "jasp-shared/hidden") {
		t.Fatalf("policy-hidden target path leaked:\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "1 vault item(s) policy-invisible") {
		t.Fatalf("stderr = %q, want anonymous hidden count", stderr.String())
	}
	if rows := addRows(t, a); len(rows) != 0 {
		t.Fatalf("policy-hidden item was written: %+v", rows)
	}
}

func TestRunBwImport_SharedSyncFailureLeavesWriteAndAuditsSanitizedError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount:  "jasp-shared",
		URL:    "https://token-must-not-persist@example.invalid/shared.git",
		Shared: true,
	}}}
	a := fakeApp(t)
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(t, "f1", "phone"),
	}}
	syncRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
		"gopass sync --store jasp-shared": {
			err: errors.New("authentication failed for token-must-not-persist"),
		},
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(bwRunner),
		&bytes.Buffer{}, &stdout, &stderr, bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("error = %v, want surfaced shared sync failure", err)
	}
	if _, getErr := a.Store.Get(context.Background(), "jasp-shared/phone"); getErr != nil {
		t.Fatalf("successful local write was lost: %v", getErr)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("audit rows = %+v, want one error row", rows)
	}
	if strings.Contains(rows[0].Reason, "authentication") ||
		strings.Contains(rows[0].Reason, "token-must-not-persist") ||
		!strings.Contains(rows[0].Reason, "shared sync failed") {
		t.Fatalf("audit reason is not stage-sanitized: %q", rows[0].Reason)
	}
}

type bwImportSyncHookRunner struct {
	base   *stubRunner
	onSync func() error
	called bool
}

func (r *bwImportSyncHookRunner) Run(
	ctx context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	if !r.called && name == "gopass" &&
		strings.Join(args, " ") == "sync --store jasp-shared" {
		r.called = true
		if err := r.onSync(); err != nil {
			return nil, err
		}
	}
	return r.base.Run(ctx, name, args...)
}

func TestRunBwImport_SharedLastSyncPreservesConcurrentConfigChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	initial := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutSingle,
		Owner:   "initial-owner",
		Remotes: []syncpkg.StoreRemote{{
			Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
		}},
	}
	if err := syncpkg.Save("", initial); err != nil {
		t.Fatalf("save initial sync config: %v", err)
	}
	stale, err := syncpkg.Load("")
	if err != nil {
		t.Fatalf("load initial sync config: %v", err)
	}

	a := fakeApp(t)
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(t, "f1", "phone"),
	}}
	baseRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
		"gopass sync --store jasp-shared":                 {},
	}}
	syncRunner := &bwImportSyncHookRunner{
		base: baseRunner,
		onSync: func() error {
			current, loadErr := syncpkg.Load("")
			if loadErr != nil {
				return loadErr
			}
			current.Owner = "concurrent-owner"
			current.Layout = syncpkg.LayoutPerOrg
			current.Remotes = append(current.Remotes, syncpkg.StoreRemote{
				Mount: "personal", URL: "file:///personal.git",
			})
			return syncpkg.Save("", current)
		},
	}

	err = runBwImport(
		context.Background(),
		a,
		bw.NewClient(bwRunner),
		&bytes.Buffer{},
		&bytes.Buffer{},
		&bytes.Buffer{},
		bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: stale, SyncRunner: syncRunner,
		},
	)
	if err != nil {
		t.Fatalf("runBwImport: %v", err)
	}
	persisted, err := syncpkg.Load("")
	if err != nil {
		t.Fatalf("reload sync config: %v", err)
	}
	if persisted.Owner != "concurrent-owner" ||
		persisted.Layout != syncpkg.LayoutPerOrg {
		t.Fatalf(
			"concurrent config fields were overwritten: owner=%q layout=%q",
			persisted.Owner, persisted.Layout,
		)
	}
	if remote, ok := persisted.Remote("personal"); !ok ||
		remote.URL != "file:///personal.git" {
		t.Fatalf("concurrent remote was overwritten: %+v", persisted.Remotes)
	}
	if remote, ok := persisted.Remote("jasp-shared"); !ok ||
		remote.LastSync.IsZero() {
		t.Fatalf("shared LastSync was not persisted: %+v", persisted.Remotes)
	}
}

func TestRunBwImport_SharedSyncStateSaveFailureHasNoOKAudit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
	}}}
	if err := syncpkg.Save("", config); err != nil {
		t.Fatalf("save sync config: %v", err)
	}

	a := fakeApp(t)
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":                   unlockedStatus,
		"sync":                     nil,
		"list folders":             []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(t, "f1", "phone"),
	}}
	baseRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
		"gopass sync --store jasp-shared":                 {},
	}}
	syncRunner := &bwImportSyncHookRunner{
		base: baseRunner,
		onSync: func() error {
			current, err := syncpkg.Load("")
			if err != nil {
				return err
			}
			for i := range current.Remotes {
				if current.Remotes[i].Mount == "jasp-shared" {
					current.Remotes[i].Shared = false
				}
			}
			return syncpkg.Save("", current)
		},
	}

	err := runBwImport(
		context.Background(),
		a,
		bw.NewClient(bwRunner),
		&bytes.Buffer{},
		&bytes.Buffer{},
		&bytes.Buffer{},
		bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		},
	)
	if err == nil || !strings.Contains(
		err.Error(), `mount "jasp-shared" is no longer configured as shared`,
	) {
		t.Fatalf("error = %v, want sync state persistence refusal", err)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError ||
		!strings.Contains(rows[0].Reason, "shared sync state save failed") {
		t.Fatalf("bw-import audit rows = %+v, want one state-save error", rows)
	}
	for _, row := range rows {
		if row.Result == audit.ResultOK {
			t.Fatalf("unexpected OK audit after sync state save failure: %+v", row)
		}
	}
}

type failAfterFirstSetStore struct {
	store.Interface
	setCalls int
}

func (s *failAfterFirstSetStore) Set(ctx context.Context, entry *store.Entry) error {
	s.setCalls++
	if s.setCalls > 1 {
		return errors.New("disk full after first shared write")
	}
	return s.Interface.Set(ctx, entry)
}

func TestRunBwImport_SharedPartialWriteStillSyncsSuccessfulEntries(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
	}}}
	if err := syncpkg.Save("", config); err != nil {
		t.Fatalf("save sync config: %v", err)
	}
	a := fakeApp(t)
	partial := &failAfterFirstSetStore{Interface: a.Store}
	a.Store = partial
	bwRunner := &stubBWRunner{Responses: map[string][]byte{
		"status":       unlockedStatus,
		"sync":         nil,
		"list folders": []byte(`[{"id":"f1","name":"mys/jasp"}]`),
		"list items --folderid f1": phoneItemJSON(
			t, "f1", "first", "second"),
	}}
	syncRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {},
		"gopass sync --store jasp-shared":                 {},
	}}
	var stdout, stderr bytes.Buffer
	err := runBwImport(context.Background(), a, bw.NewClient(bwRunner),
		&bytes.Buffer{}, &stdout, &stderr, bwImportOptions{
			Org: "jasp", Mount: "jasp-shared",
			Apply: true, Yes: true, Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		})
	if err == nil || !strings.Contains(err.Error(), "1 of 2 writes failed") {
		t.Fatalf("error = %v, want partial-write failure", err)
	}
	if _, getErr := a.Store.Get(
		context.Background(), "jasp-shared/first",
	); getErr != nil {
		t.Fatalf("first successful write missing: %v", getErr)
	}
	var syncCount int
	for _, call := range syncRunner.calls {
		if call == "gopass sync --store jasp-shared" {
			syncCount++
		}
	}
	if syncCount != 1 {
		t.Fatalf("sync calls = %v, want one sync after partial write", syncRunner.calls)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError ||
		!strings.Contains(rows[0].Reason, "apply failed") ||
		strings.Contains(rows[0].Reason, "disk full") {
		t.Fatalf("partial import audit rows = %+v", rows)
	}
}

func TestRunBwImport_SharedPullFailurePrecedesBitwardenAccess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mountPath := t.TempDir()
	config := &syncpkg.Config{Version: 1, Remotes: []syncpkg.StoreRemote{{
		Mount: "jasp-shared", URL: "file:///shared.git", Shared: true,
	}}}
	a := fakeApp(t)
	bwRunner := &stubBWRunner{Responses: map[string][]byte{}}
	syncRunner := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp-shared.path": {
			out: []byte(mountPath + "\n"),
		},
		"gopass git --store jasp-shared rev-parse --abbrev-ref HEAD": {
			out: []byte("main\n"),
		},
		"gopass git --store jasp-shared pull origin main": {
			err: errors.New("remote contained token-must-not-persist"),
		},
	}}
	err := runBwImport(context.Background(), a, bw.NewClient(bwRunner),
		&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, bwImportOptions{
			Org: "jasp", Mount: "jasp-shared", Session: "tok",
			SyncConfig: config, SyncRunner: syncRunner,
		})
	if err == nil || !strings.Contains(err.Error(), "token-must-not-persist") {
		t.Fatalf("error = %v, want surfaced pull failure", err)
	}
	if len(bwRunner.Calls) != 0 {
		t.Fatalf("Bitwarden was accessed before shared pull: %v", bwRunner.Calls)
	}
	rows := bwImportRows(t, a)
	if len(rows) != 1 || rows[0].Result != audit.ResultError ||
		rows[0].Reason != "shared pull failed source_org=jasp target_mount=jasp-shared" {
		t.Fatalf("pull failure audit rows = %+v", rows)
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
