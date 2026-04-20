package app

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
)

// appWithAuditOnly returns an App suitable for testing the audit/policy
// plumbing without requiring a real gopass store. Store-dependent methods
// (Get/Add/Rotate/Remove/List/Search) are not exercised here; those paths
// are covered by the E2E script against a real gopass test store.
func appWithAuditOnly(t *testing.T) *App {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &App{Audit: l, Policy: policy.Default(), Override: "claude-code"}
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
