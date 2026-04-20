package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

// --- Rotation timestamps --------------------------------------------------

func TestAdd_SetsRotatedAt(t *testing.T) {
	a, f := appWithFake(t, "human")
	ctx := context.Background()
	before := time.Now().UTC()
	e := &store.Entry{Path: "jasp/new", Password: "p", RotateAfter: "90d"}
	if err := a.Add(ctx, e); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	got, err := f.Get(ctx, "jasp/new")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RotatedAt.IsZero() {
		t.Fatal("rotated_at not set after Add")
	}
	// Accept a ±2s slack either side to survive slow CI.
	lower := before.Add(-2 * time.Second)
	upper := after.Add(2 * time.Second)
	if got.RotatedAt.Before(lower) || got.RotatedAt.After(upper) {
		t.Errorf("rotated_at = %v, want within [%v,%v]", got.RotatedAt, lower, upper)
	}
	// RotateAfter must round-trip unchanged.
	if got.RotateAfter != "90d" {
		t.Errorf("rotate_after = %q, want 90d", got.RotateAfter)
	}
}

func TestAdd_OverwritesCallerProvidedRotatedAt(t *testing.T) {
	// Defence-in-depth: the app layer owns the timestamp. Even if a
	// caller pre-fills RotatedAt, Add must stamp "now" instead — the
	// field is book-keeping, not user input.
	a, f := appWithFake(t, "human")
	ctx := context.Background()
	e := &store.Entry{
		Path:      "jasp/x",
		Password:  "p",
		RotatedAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := a.Add(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Get(ctx, "jasp/x")
	if got.RotatedAt.Year() == 2000 {
		t.Errorf("Add should have overwritten the pre-filled rotated_at, got %v", got.RotatedAt)
	}
	if time.Since(got.RotatedAt) > 10*time.Second {
		t.Errorf("rotated_at = %v, want ~now", got.RotatedAt)
	}
}

func TestRotate_UpdatesRotatedAt(t *testing.T) {
	// Seed an entry with a stale rotated_at, rotate it, then assert
	// that the stored rotated_at advanced.
	past := time.Now().UTC().Add(-200 * 24 * time.Hour)
	seed := &store.Entry{
		Path:        "jasp/old",
		Password:    "old",
		RotateAfter: "90d",
		RotatedAt:   past,
	}
	a, f := appWithFake(t, "human", seed)
	ctx := context.Background()
	if err := a.Rotate(ctx, "jasp/old", "new-pw"); err != nil {
		t.Fatal(err)
	}
	got, err := f.Get(ctx, "jasp/old")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.RotatedAt.After(past) {
		t.Errorf("rotated_at did not advance: got %v, was %v", got.RotatedAt, past)
	}
	if got.Password != "new-pw" {
		t.Errorf("password not updated: %q", got.Password)
	}
	// RotateAfter must be preserved through a rotate.
	if got.RotateAfter != "90d" {
		t.Errorf("rotate_after lost across rotate: got %q", got.RotateAfter)
	}
}

// --- TOTP ------------------------------------------------------------------

// totpEntry returns a fully populated TOTP entry using the stable
// base32 seed "JBSWY3DPEHPK3PXP" (the canonical rfc2-style test seed).
func totpEntry(path string) *store.Entry {
	return &store.Entry{
		Path:          path,
		Org:           store.OrgOf(path),
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:    "GitHub",
		TOTPLabel:     "sascha",
		TOTPAlgorithm: "SHA1",
		TOTPDigits:    6,
		TOTPPeriod:    30,
	}
}

func TestGenerateTOTP_OK(t *testing.T) {
	a, _ := appWithFake(t, "human", totpEntry("jasp/github"))
	ctx := context.Background()
	now := time.Unix(1700000000, 0)
	code, secondsLeft, err := a.GenerateTOTP(ctx, "jasp/github", now)
	if err != nil {
		t.Fatalf("GenerateTOTP: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code length = %d, want 6 (%q)", len(code), code)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("code %q has non-digit rune", code)
		}
	}
	if secondsLeft < 1 || secondsLeft > 30 {
		t.Errorf("secondsLeft = %d, want 1..30", secondsLeft)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionTOTPGenerate, Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("want one totp_generate row, got %d", len(rows))
	}
	if rows[0].Result != audit.ResultOK {
		t.Errorf("result = %q, want ok", rows[0].Result)
	}
	if !strings.Contains(rows[0].Reason, "window=") {
		t.Errorf("reason = %q, want to include window=", rows[0].Reason)
	}
	if rows[0].SecretPath != "jasp/github" {
		t.Errorf("secret_path = %q", rows[0].SecretPath)
	}
	code2, _, err := a.GenerateTOTP(ctx, "jasp/github", now)
	if err != nil {
		t.Fatal(err)
	}
	if code2 != code {
		t.Errorf("deterministic generate returned different codes: %q vs %q", code, code2)
	}
}

func TestGenerateTOTP_Denied(t *testing.T) {
	a, _ := appWithFake(t, "claude-code", totpEntry("private/bank-2fa"))
	ctx := context.Background()
	_, _, err := a.GenerateTOTP(ctx, "private/bank-2fa", time.Unix(1700000000, 0))
	var denied *ErrDenied
	if !errors.As(err, &denied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionTOTPGenerate, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("want one denied totp_generate row, got %+v", rows)
	}
	if rows[0].Org != "private" {
		t.Errorf("org = %q, want private", rows[0].Org)
	}
}

func TestGenerateTOTP_NotTOTP(t *testing.T) {
	a, _ := appWithFake(t, "human", &store.Entry{
		Path: "jasp/not-totp", Kind: store.KindPassword, Password: "plain-pw",
	})
	ctx := context.Background()
	_, _, err := a.GenerateTOTP(ctx, "jasp/not-totp", time.Now())
	if err == nil {
		t.Fatal("want error for non-TOTP entry")
	}
	if !strings.Contains(err.Error(), "not a totp entry") {
		t.Errorf("error = %v, want 'not a totp entry' substring", err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionTOTPGenerate, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want one error totp_generate row, got %+v", rows)
	}
}

func TestGenerateTOTP_StoreError(t *testing.T) {
	a, f := appWithFake(t, "human", totpEntry("jasp/github"))
	f.GetErr = errors.New("gpg locked")
	_, _, err := a.GenerateTOTP(context.Background(), "jasp/github", time.Now())
	if err == nil {
		t.Fatal("want error")
	}
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionTOTPGenerate, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultError {
		t.Fatalf("want error row, got %+v", rows)
	}
}

// --- Domain search ---------------------------------------------------------

// domainSeed returns entries covering each tier MatchDomain classifies on.
func domainSeed() []*store.Entry {
	return []*store.Entry{
		{Path: "jasp/aws", Domain: "aws.amazon.com", Password: "p1"},
		{Path: "jasp/site", Domain: "jasp.eu", Password: "p2"},
		{Path: "jasp/mail", Domain: "mail.jasp.eu", Password: "p3"},
		{Path: "jasp/github", Domain: "github.com", Password: "p4"},
	}
}

func TestSearchByDomain_Exact(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	ctx := context.Background()
	matches, sim, err := a.SearchByDomain(ctx, "jasp.eu", false)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (jasp.eu exact + mail.jasp.eu subdomain), got %d: %+v", len(matches), matches)
	}
	paths := map[string]string{}
	for _, m := range matches {
		paths[m.Entry.Path] = m.Tier
	}
	if paths["jasp/site"] != store.TierExact {
		t.Errorf("jasp/site tier = %q, want exact", paths["jasp/site"])
	}
	if paths["jasp/mail"] != store.TierSubdomain {
		t.Errorf("jasp/mail tier = %q, want subdomain", paths["jasp/mail"])
	}
	if len(sim) != 0 {
		t.Errorf("expected no similar when includeSimilar=false, got %+v", sim)
	}
}

func TestSearchByDomain_FuzzyTypo(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	ctx := context.Background()
	matches, sim, err := a.SearchByDomain(ctx, "jazp.eu", true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no direct matches for typo, got %+v", matches)
	}
	var foundFuzzy bool
	for _, m := range sim {
		if m.Entry.Path == "jasp/site" && m.Tier == store.TierFuzzy {
			foundFuzzy = true
			if !strings.Contains(m.Hint, "typo") {
				t.Errorf("fuzzy hint missing 'typo': %q", m.Hint)
			}
		}
	}
	if !foundFuzzy {
		t.Errorf("expected fuzzy match for jasp.eu, got similar=%+v", sim)
	}
}

func TestSearchByDomain_SubstringOnly(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	ctx := context.Background()
	matches, sim, err := a.SearchByDomain(ctx, "amazon", true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no exact/subdomain matches for 'amazon', got %+v", matches)
	}
	var foundSub bool
	for _, m := range sim {
		if m.Entry.Path == "jasp/aws" && m.Tier == store.TierSubstring {
			foundSub = true
		}
	}
	if !foundSub {
		t.Errorf("expected substring match for aws.amazon.com, got similar=%+v", sim)
	}
}

func TestSearchByDomain_ExactWithSimilar(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	ctx := context.Background()
	matches, sim, err := a.SearchByDomain(ctx, "jasp.eu", true)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// matches contain jasp.eu exact + mail.jasp.eu subdomain
	if len(matches) != 2 {
		t.Fatalf("matches = %+v", matches)
	}
	// similar should be empty — every match was covered by primary tiers.
	for _, m := range sim {
		if m.Entry.Path == "jasp/site" || m.Entry.Path == "jasp/mail" {
			t.Errorf("primary-tier match leaked into similar: %+v", m)
		}
	}
}

func TestSearchByDomain_EmptyQuery(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	matches, sim, err := a.SearchByDomain(context.Background(), "   ", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 || len(sim) != 0 {
		t.Errorf("empty query must return empty slices, got %+v / %+v", matches, sim)
	}
}

func TestSearchByDomain_AuditReason(t *testing.T) {
	a, _ := appWithFake(t, "human", domainSeed()...)
	ctx := context.Background()
	_, _, err := a.SearchByDomain(ctx, "jasp.eu", true)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Action: audit.ActionSearch, Limit: 10})
	var found bool
	for _, r := range rows {
		if strings.Contains(r.Reason, "domain=\"jasp.eu\"") && strings.Contains(r.Reason, "exact=1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected domain audit row with tier breakdown, got %+v", rows)
	}
}

func TestAdd_AutoDerivesDomainFromURL(t *testing.T) {
	a, f := appWithFake(t, "human")
	ctx := context.Background()
	e := &store.Entry{Path: "jasp/new", URL: "https://aws.amazon.com:443/console", Password: "p"}
	if err := a.Add(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Get(ctx, "jasp/new")
	if got.Domain != "aws.amazon.com" {
		t.Errorf("domain was not auto-derived: %q", got.Domain)
	}
}

func TestAdd_DoesNotOverwriteExplicitDomain(t *testing.T) {
	a, f := appWithFake(t, "human")
	ctx := context.Background()
	e := &store.Entry{
		Path: "jasp/new", URL: "https://aws.amazon.com", Domain: "override.example.com", Password: "p",
	}
	if err := a.Add(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Get(ctx, "jasp/new")
	if got.Domain != "override.example.com" {
		t.Errorf("explicit domain was overwritten: %q", got.Domain)
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
