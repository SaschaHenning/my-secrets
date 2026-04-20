package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
)

// appWithAuditOnly returns an App suitable for testing the audit/policy
// plumbing without requiring a store. Store-dependent methods fail fast.
func appWithAuditOnly(t *testing.T) *App {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &App{Audit: l, Policy: policy.Default(), Override: "claude-code"}
}

// appWithFake wires in the in-memory fake store plus a temp audit log and
// the default policy. Override controls the actor classification; use
// "claude-code" for AI (denied on private/**) or "human" for a full-access
// actor.
//
// Note: when running under Claude Code, env vars and the parent process
// chain force the classifier to return KindAI regardless of override
// (security feature — a compromised AI cannot downgrade itself to human).
// Tests that need full access therefore use a custom policy that grants
// "claude-code" full access.
func appWithFake(t *testing.T, override string, entries ...*store.Entry) (*App, *fake.Store) {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := fake.NewWithEntries(entries...)
	pol := policy.Default()
	if override == "human" || override == "fullaccess" {
		// Under a test harness we cannot reliably produce actor_kind=human
		// (see comment above). Instead of relying on classification, we
		// expand the policy so whichever kind the classifier picks — in
		// practice "ai" with label "claude-code" — has full access.
		pol = &policy.Policy{Actors: map[string]policy.Rules{
			"human":       {Allow: []string{"**"}},
			"script":      {Allow: []string{"**"}},
			"ai":          {Allow: []string{"**"}},
			"claude-code": {Allow: []string{"**"}},
		}}
		override = "claude-code"
	}
	a := &App{Store: f, Audit: l, Policy: pol, Override: override}
	return a, f
}

func sampleEntries() []*store.Entry {
	return []*store.Entry{
		{Path: "jasp/github", Username: "alice", Password: "p1"},
		{Path: "jasp/aws", Username: "bob", Password: "p2", Notes: "prod"},
		{Path: "zuhause/router", Username: "admin", Password: "p3"},
		{Path: "private/bank", Username: "me", Password: "p4"},
	}
}

func TestAuditInitWritesRow(t *testing.T) {
	a := appWithAuditOnly(t)
	ctx := context.Background()
	a.AuditInit(ctx, "unit-test")

	rows, err := a.Audit.Tail(ctx, audit.Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 audit row, got %d", len(rows))
	}
	if rows[0].Action != audit.ActionInit {
		t.Errorf("action = %q, want init", rows[0].Action)
	}
	if rows[0].ActorKind != "ai" {
		t.Errorf("actor_kind = %q, want ai (override=claude-code)", rows[0].ActorKind)
	}
}

func TestAuditMCPStart(t *testing.T) {
	a := appWithAuditOnly(t)
	a.AuditMCPStart(context.Background())
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionMCPStart, Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("expected one mcp_start row, got %d", len(rows))
	}
}

func TestAuditWebOpen(t *testing.T) {
	a := appWithAuditOnly(t)
	a.AuditWebOpen(context.Background(), "127.0.0.1:9999")
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionWebOpen, Limit: 5})
	if len(rows) != 1 {
		t.Fatal("expected one web_open row")
	}
	if rows[0].Reason == "" {
		t.Error("expected a reason containing the listen address")
	}
}

func TestOrgPathSentinel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"jasp", "org=jasp"},
	}
	for _, tc := range cases {
		got := orgPath(tc.in)
		if got != tc.want {
			t.Errorf("orgPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// fakeSearcher mimics the contract of store.Store.Search: it walks a
// pre-defined path list, applies the allow callback BEFORE "decryption",
// and records which paths the caller attempted to inspect. Decryption
// itself is a no-op — the match is decided by a simple path substring
// test, good enough to prove the filter wiring.
type fakeSearcher struct {
	paths     []string
	decrypted []string // paths that were passed through the allow gate
}

func (f *fakeSearcher) Search(_ context.Context, query string, allow func(path string) bool) ([]string, []string, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil, nil
	}
	allowed := make([]string, 0)
	denied := make([]string, 0)
	for _, p := range f.paths {
		if allow != nil && !allow(p) {
			denied = append(denied, p)
			continue
		}
		// simulate decryption cost only for cleared paths
		f.decrypted = append(f.decrypted, p)
		if strings.Contains(strings.ToLower(p), q) {
			allowed = append(allowed, p)
		}
	}
	sort.Strings(allowed)
	sort.Strings(denied)
	return allowed, denied, nil
}

func TestSearchPrefiltersDeniedPathsBeforeDecrypting(t *testing.T) {
	a := appWithAuditOnly(t) // Override=claude-code, so kind=ai
	ctx := context.Background()

	fs := &fakeSearcher{paths: []string{
		"private/secret1",
		"jasp/foo-secret",
		"zuhause/bar-secret",
	}}

	got, err := a.searchWith(ctx, "secret", fs)
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	// The AI caller must not see private paths.
	for _, p := range got {
		if strings.HasPrefix(p, "private/") {
			t.Errorf("allowed slice leaked denied path %q", p)
		}
	}
	wantAllowed := []string{"jasp/foo-secret", "zuhause/bar-secret"}
	if len(got) != len(wantAllowed) {
		t.Fatalf("allowed = %v, want %v", got, wantAllowed)
	}
	for i := range wantAllowed {
		if got[i] != wantAllowed[i] {
			t.Errorf("allowed[%d] = %q, want %q", i, got[i], wantAllowed[i])
		}
	}

	// Prove that the private path never passed the allow gate, i.e.
	// was never decrypted.
	for _, p := range fs.decrypted {
		if strings.HasPrefix(p, "private/") {
			t.Fatalf("denied path %q was decrypted — policy prefilter bypassed", p)
		}
	}

	// Check the per-path denied audit row exists.
	deniedRows, err := a.Audit.Tail(ctx, audit.Filter{
		Action: audit.ActionSearch,
		Path:   "private/secret1",
		Limit:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range deniedRows {
		if r.SecretPath == "private/secret1" && r.Result == audit.ResultDenied {
			found = true
			if r.Reason == "" {
				t.Error("denied search audit row has empty reason")
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected a denied search audit row for private/secret1, got %+v", deniedRows)
	}

	// The aggregate summary row should also be present.
	summaryRows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSearch, Limit: 20})
	var summarySeen bool
	for _, r := range summaryRows {
		if r.SecretPath == "" && r.Result == audit.ResultOK &&
			strings.Contains(r.Reason, "query=\"secret\"") &&
			strings.Contains(r.Reason, "2 of 3 visible") {
			summarySeen = true
			break
		}
	}
	if !summarySeen {
		t.Errorf("expected aggregate search audit row with '2 of 3 visible', got %+v", summaryRows)
	}
}

// TestSearchNilAllowIsBackwardCompatibleAtStoreLayer documents the
// backward-compat contract of the store-level API: a nil allow must
// inspect every path. App.Search always supplies a non-nil allow, so
// this test exercises the fake searcher directly.
func TestSearchNilAllowIsBackwardCompatibleAtStoreLayer(t *testing.T) {
	fs := &fakeSearcher{paths: []string{"private/a", "jasp/b"}}
	allowed, denied, err := fs.Search(context.Background(), "a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Errorf("denied = %v, want empty with nil allow", denied)
	}
	if len(allowed) == 0 {
		t.Error("allowed should not be empty with nil allow")
	}
}

func TestErrDeniedMessage(t *testing.T) {
	e := &ErrDenied{Path: "private/bank", Reason: "claude-code denied by rule private/**"}
	if e.Error() == "" {
		t.Fatal("empty error message")
	}
	if got := e.Error(); got != `denied: private/bank (claude-code denied by rule private/**)` {
		t.Errorf("unexpected error: %s", got)
	}
}

// --- Store-backed flows via the fake --------------------------------------

func TestGet_OK(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	ctx := context.Background()
	e, err := a.Get(ctx, "jasp/github")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if e.Username != "alice" {
		t.Errorf("username = %q", e.Username)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionGet, Limit: 10})
	if len(rows) != 1 {
		t.Fatalf("want 1 audit row, got %d", len(rows))
	}
	if rows[0].Result != audit.ResultOK {
		t.Errorf("result = %q, want ok", rows[0].Result)
	}
}

func TestGet_Denied(t *testing.T) {
	// AI actor must be denied access to private/**.
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	ctx := context.Background()
	_, err := a.Get(ctx, "private/bank")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionGet, Limit: 10})
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("want one denied audit row, got %+v", rows)
	}
	if rows[0].Org != "private" {
		t.Errorf("org = %q, want private", rows[0].Org)
	}
}

func TestGet_StoreError(t *testing.T) {
	a, f := appWithFake(t, "claude-code", sampleEntries()...)
	f.GetErr = errors.New("gpg locked")
	ctx := context.Background()
	_, err := a.Get(ctx, "jasp/github")
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want one error audit row, got %+v", rows)
	}
}

func TestList_FiltersByPolicy(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	ctx := context.Background()
	paths, err := a.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// private/bank must be filtered out for AI actor.
	for _, p := range paths {
		if p == "private/bank" {
			t.Errorf("AI should not see private/bank in list")
		}
	}
	if len(paths) == 0 {
		t.Error("expected some visible entries")
	}
}

func TestList_OrgFilter(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	ctx := context.Background()
	paths, err := a.List(ctx, "jasp")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if p[:4] != "jasp" {
			t.Errorf("List(jasp) returned %q", p)
		}
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionList, Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("want 1 list row, got %d", len(rows))
	}
	if rows[0].Org != "jasp" {
		t.Errorf("audit org = %q, want jasp", rows[0].Org)
	}
}

func TestList_StoreError(t *testing.T) {
	a, f := appWithFake(t, "claude-code", sampleEntries()...)
	f.ListErr = errors.New("nope")
	_, err := a.List(context.Background(), "")
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want one error audit row, got %+v", rows)
	}
}

func TestSearch_Filters(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	ctx := context.Background()
	// "bank" would match private/bank by path but the policy should hide it.
	paths, err := a.Search(ctx, "bank")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if p == "private/bank" {
			t.Errorf("AI should not see private/bank in search")
		}
	}
	// With human actor the same query should surface it.
	a2, _ := appWithFake(t, "human", sampleEntries()...)
	got, _ := a2.Search(ctx, "bank")
	found := false
	for _, p := range got {
		if p == "private/bank" {
			found = true
		}
	}
	if !found {
		t.Error("human actor should see private/bank via search")
	}
}

func TestSearch_StoreError(t *testing.T) {
	a, f := appWithFake(t, "claude-code", sampleEntries()...)
	f.SearchErr = errors.New("broken")
	_, err := a.Search(context.Background(), "anything")
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionSearch, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want error audit row, got %+v", rows)
	}
}

func TestAdd_OK(t *testing.T) {
	a, f := appWithFake(t, "human")
	ctx := context.Background()
	e := &store.Entry{Path: "jasp/new", Username: "u", Password: "p"}
	if err := a.Add(ctx, e); err != nil {
		t.Fatal(err)
	}
	if f.Len() != 1 {
		t.Errorf("want 1 entry in store, got %d", f.Len())
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionAdd, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("want ok audit row, got %+v", rows)
	}
}

func TestAdd_Denied(t *testing.T) {
	a, _ := appWithFake(t, "claude-code")
	err := a.Add(context.Background(), &store.Entry{Path: "private/foo", Password: "p"})
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionAdd, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("want denied audit row, got %+v", rows)
	}
}

func TestAdd_StoreError(t *testing.T) {
	a, f := appWithFake(t, "human")
	f.SetErr = errors.New("disk full")
	err := a.Add(context.Background(), &store.Entry{Path: "jasp/x", Password: "p"})
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionAdd, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want error audit row, got %+v", rows)
	}
}

func TestRotate_OK(t *testing.T) {
	a, f := appWithFake(t, "human", sampleEntries()...)
	ctx := context.Background()
	if err := a.Rotate(ctx, "jasp/github", "new-pw"); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Get(ctx, "jasp/github")
	if got.Password != "new-pw" {
		t.Errorf("password = %q, want new-pw", got.Password)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionRotate, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("want ok audit row, got %+v", rows)
	}
}

func TestRotate_Denied(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	err := a.Rotate(context.Background(), "private/bank", "new-pw")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestRotate_StoreError(t *testing.T) {
	a, f := appWithFake(t, "human", sampleEntries()...)
	f.GetErr = errors.New("locked")
	err := a.Rotate(context.Background(), "jasp/github", "new-pw")
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionRotate, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want error audit row, got %+v", rows)
	}
}

func TestRemove_OK(t *testing.T) {
	a, f := appWithFake(t, "human", sampleEntries()...)
	ctx := context.Background()
	if err := a.Remove(ctx, "jasp/github"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(ctx, "jasp/github"); err == nil {
		t.Error("entry still in store after remove")
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionRemove, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("want ok audit row, got %+v", rows)
	}
}

func TestRemove_Denied(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", sampleEntries()...)
	err := a.Remove(context.Background(), "private/bank")
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionRemove, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("want denied audit row, got %+v", rows)
	}
}

func TestRemove_StoreError(t *testing.T) {
	a, f := appWithFake(t, "human", sampleEntries()...)
	f.RemoveErr = errors.New("ro")
	err := a.Remove(context.Background(), "jasp/github")
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionRemove, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want error audit row, got %+v", rows)
	}
}

func TestClose_ClosesStoreAndAudit(t *testing.T) {
	a, _ := appWithFake(t, "human", sampleEntries()...)
	if err := a.Close(context.Background()); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestWriteAudit_NilAuditIsNoop(t *testing.T) {
	// Ensures the nil-audit guard path is covered (no panic expected).
	a := &App{Policy: policy.Default(), Override: "human"}
	a.AuditInit(context.Background(), "nope")
}

// --- Auto-sync hook -------------------------------------------------------

// autoSyncRecorder is a sync.Runner that records every invocation and
// returns a canned result. Used by the App-level tests to assert that
// Add/Rotate/Remove reach (or do not reach) the auto-sync path.
type autoSyncRecorder struct {
	calls [][]string
	err   error
}

func (r *autoSyncRecorder) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	return nil, r.err
}

// withTempSyncConfig writes a sync.Config to a tempdir HOME and
// installs a recording runner on the package-level autoSyncRunner. It
// returns the recorder so the test can inspect calls, and restores the
// runner via t.Cleanup.
func withTempSyncConfig(t *testing.T, cfg *syncpkg.Config, runErr error) *autoSyncRecorder {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("MYS_AUTO_SYNC", "")
	path := filepath.Join(dir, ".config", "my-secrets", "sync.yaml")
	if err := syncpkg.Save(path, cfg); err != nil {
		t.Fatalf("save sync config: %v", err)
	}
	rec := &autoSyncRecorder{err: runErr}
	prev := autoSyncRunner
	autoSyncRunner = rec
	t.Cleanup(func() { autoSyncRunner = prev })
	prevFlag := NoSyncFlag
	NoSyncFlag = false
	t.Cleanup(func() { NoSyncFlag = prevFlag })
	return rec
}

// withNoSyncConfig points HOME at an empty tempdir so LoadConfig() sees
// no remotes. Any AutoSync call should skip.
func withNoSyncConfig(t *testing.T) *autoSyncRecorder {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("MYS_AUTO_SYNC", "")
	rec := &autoSyncRecorder{}
	prev := autoSyncRunner
	autoSyncRunner = rec
	t.Cleanup(func() { autoSyncRunner = prev })
	return rec
}

func singleRemoteConfig() *syncpkg.Config {
	return &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutSingle,
		Remotes: []syncpkg.StoreRemote{
			{Mount: syncpkg.DefaultStoreMount, URL: "git@github.com:me/my-secrets-store.git"},
		},
	}
}

func TestApp_Add_AutoSync_Success(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	a, _ := appWithFake(t, "human")
	var stderr bytes.Buffer
	a.Stderr = &stderr
	ctx := context.Background()
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Two audit rows: add + sync_push(ok).
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Limit: 20})
	var sawAdd, sawSync bool
	for _, r := range rows {
		switch r.Action {
		case audit.ActionAdd:
			if r.Result == audit.ResultOK {
				sawAdd = true
			}
		case audit.ActionSyncPush:
			if r.Result == audit.ResultOK {
				sawSync = true
				if !strings.Contains(r.Reason, "auto-sync after add jasp/new") {
					t.Errorf("sync_push reason = %q, want to contain 'auto-sync after add jasp/new'", r.Reason)
				}
			}
		}
	}
	if !sawAdd {
		t.Errorf("expected add ok row, got rows=%+v", rows)
	}
	if !sawSync {
		t.Errorf("expected sync_push ok row, got rows=%+v", rows)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr should be empty on success, got %q", stderr.String())
	}
	if len(rec.calls) == 0 {
		t.Errorf("expected runner to be called at least once")
	}
}

func TestApp_Add_AutoSync_Error(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), errors.New("network unreachable"))
	a, _ := appWithFake(t, "human")
	var stderr bytes.Buffer
	a.Stderr = &stderr
	ctx := context.Background()
	// Add itself must still succeed — write was OK, sync is best-effort.
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err != nil {
		t.Fatalf("add should return nil even when auto-sync fails, got %v", err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Limit: 20})
	var sawAddOK, sawSyncErr bool
	for _, r := range rows {
		if r.Action == audit.ActionAdd && r.Result == audit.ResultOK {
			sawAddOK = true
		}
		if r.Action == audit.ActionSyncPush && r.Result == audit.ResultError {
			sawSyncErr = true
			if !strings.Contains(r.Reason, "network unreachable") {
				t.Errorf("sync_push error reason = %q, want to mention underlying error", r.Reason)
			}
		}
	}
	if !sawAddOK {
		t.Errorf("expected add ok row, rows=%+v", rows)
	}
	if !sawSyncErr {
		t.Errorf("expected sync_push error row, rows=%+v", rows)
	}
	if !strings.Contains(stderr.String(), "warning: auto-sync failed") {
		t.Errorf("stderr must contain the warning, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "mys sync push") {
		t.Errorf("stderr must point the user at 'mys sync push', got %q", stderr.String())
	}
	if len(rec.calls) == 0 {
		t.Error("expected runner to be invoked")
	}
}

func TestApp_Add_AutoSync_NoConfig(t *testing.T) {
	rec := withNoSyncConfig(t)
	a, _ := appWithFake(t, "human")
	var stderr bytes.Buffer
	a.Stderr = &stderr
	ctx := context.Background()
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("expected no sync_push rows when sync is not configured, got %d", len(rows))
	}
	if len(rec.calls) != 0 {
		t.Errorf("runner must not be called when no sync config exists, got %d calls", len(rec.calls))
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr must be empty on skipped path, got %q", stderr.String())
	}
}

func TestApp_Add_AutoSync_EnvOff(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	t.Setenv("MYS_AUTO_SYNC", "0")
	a, _ := appWithFake(t, "human")
	ctx := context.Background()
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("expected no sync_push rows with MYS_AUTO_SYNC=0, got %d", len(rows))
	}
	if len(rec.calls) != 0 {
		t.Errorf("runner must not be called with MYS_AUTO_SYNC=0, got %d calls", len(rec.calls))
	}
}

func TestApp_Add_AutoSync_NoSyncFlag(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	NoSyncFlag = true
	t.Cleanup(func() { NoSyncFlag = false })
	a, _ := appWithFake(t, "human")
	ctx := context.Background()
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("expected no sync_push rows when --no-sync is set, got %d", len(rows))
	}
	if len(rec.calls) != 0 {
		t.Errorf("runner must not be called with --no-sync, got %d calls", len(rec.calls))
	}
}

func TestApp_Rotate_AutoSync(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	a, _ := appWithFake(t, "human", sampleEntries()...)
	ctx := context.Background()
	if err := a.Rotate(ctx, "jasp/github", "new-pw"); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("expected one ok sync_push row after rotate, got %+v", rows)
	}
	if !strings.Contains(rows[0].Reason, "rotate jasp/github") {
		t.Errorf("reason = %q, want to contain 'rotate jasp/github'", rows[0].Reason)
	}
	if len(rec.calls) == 0 {
		t.Error("expected runner to be called")
	}
}

func TestApp_Remove_AutoSync(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	a, _ := appWithFake(t, "human", sampleEntries()...)
	ctx := context.Background()
	if err := a.Remove(ctx, "jasp/github"); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("expected one ok sync_push row after remove, got %+v", rows)
	}
	if !strings.Contains(rows[0].Reason, "remove jasp/github") {
		t.Errorf("reason = %q, want to contain 'remove jasp/github'", rows[0].Reason)
	}
	if len(rec.calls) == 0 {
		t.Error("expected runner to be called")
	}
}

func TestApp_AutoSync_DeniedAddDoesNotSync(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	a, _ := appWithFake(t, "claude-code") // AI cannot write to private/**
	ctx := context.Background()
	err := a.Add(ctx, &store.Entry{Path: "private/foo", Password: "p"})
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("expected no sync_push rows when write itself was denied, got %d", len(rows))
	}
	if len(rec.calls) != 0 {
		t.Errorf("runner must not be invoked after denied write, got %d calls", len(rec.calls))
	}
}

func TestApp_AutoSync_StoreErrorDoesNotSync(t *testing.T) {
	rec := withTempSyncConfig(t, singleRemoteConfig(), nil)
	a, f := appWithFake(t, "human")
	f.SetErr = errors.New("disk full")
	ctx := context.Background()
	if err := a.Add(ctx, &store.Entry{Path: "jasp/new", Password: "p"}); err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSyncPush, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("expected no sync_push rows when write failed, got %d", len(rows))
	}
	if len(rec.calls) != 0 {
		t.Errorf("runner must not be invoked after failed write, got %d calls", len(rec.calls))
	}
}
