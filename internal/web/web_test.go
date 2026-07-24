package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
)

// Verify that the loopback middleware rejects non-loopback addresses.
func TestLocalhostOnly(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	h := localhostOnly(inner)

	cases := []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:54321", 200},
		{"[::1]:54321", 200},
		{"8.8.8.8:443", 403},
		{"10.0.0.5:22", 403},
		{"[2001:db8::1]:443", 403},
		// SplitHostPort fails → fallback to RemoteAddr-as-host path.
		{"not-a-host", 403},
		{"127.0.0.1", 200},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("remote=%s: status=%d, want %d", tc.remote, w.Code, tc.want)
		}
	}
}

// withStubTouchID replaces requireTouchIDFunc for the duration of t.
// The test Touch-ID prompt is a no-op: CI must not hit the real
// Authorization Services dialog.
func withStubTouchID(t *testing.T, stub func(context.Context) error) {
	t.Helper()
	prev := requireTouchIDFunc
	requireTouchIDFunc = stub
	t.Cleanup(func() { requireTouchIDFunc = prev })
}

// TestAuthGateRedirectsWithoutCookie asserts that any request without a
// valid session cookie is bounced to /login?next=<original request>, so
// a deep link survives the round trip through login.
func TestAuthGateRedirectsWithoutCookie(t *testing.T) {
	store := newSessionStore(time.Minute)
	h := authGate(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("protected"))
	}))

	r := httptest.NewRequest("GET", "/audit", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/login?next=%2Faudit" {
		t.Fatalf("expected redirect to /login?next=%%2Faudit, got %q", got)
	}
}

// TestAuthGateRejectsUnknownCookie verifies that a cookie with a random
// value — not issued by the store — still gets bounced.
func TestAuthGateRejectsUnknownCookie(t *testing.T) {
	store := newSessionStore(time.Minute)
	h := authGate(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("protected"))
	}))

	r := httptest.NewRequest("GET", "/audit", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "deadbeef"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for unknown cookie, got %d", w.Code)
	}
}

// TestAuthGateAcceptsValidCookie verifies that a freshly issued session
// passes the gate and reaches the inner handler.
func TestAuthGateAcceptsValidCookie(t *testing.T) {
	store := newSessionStore(time.Minute)
	id := store.Issue()

	called := false
	h := authGate(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte("protected"))
	}))

	r := httptest.NewRequest("GET", "/audit", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !called {
		t.Fatal("inner handler was not invoked despite valid cookie")
	}
}

// TestLoginGETRendersForm checks that GET /login produces a usable page
// with the Touch-ID form.
func TestLoginGETRendersForm(t *testing.T) {
	store := newSessionStore(time.Minute)
	h := handleLogin(store, time.Minute)

	r := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `form method="post"`) {
		t.Fatal("login page should contain a POST form")
	}
	if !strings.Contains(body, "Touch ID") {
		t.Fatal("login page should mention Touch ID")
	}
}

// TestLoginPOSTIssuesCookie runs the happy path: stub Touch-ID, POST
// /login with no next=, expect a Set-Cookie and a redirect to the
// default landing page (the start page — instant, no decrypt — matching
// the PWA's start_url).
func TestLoginPOSTIssuesCookie(t *testing.T) {
	withStubTouchID(t, func(context.Context) error { return nil })

	store := newSessionStore(time.Minute)
	h := handleLogin(store, time.Minute)

	r := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != defaultLandingPath {
		t.Fatalf("expected redirect to %q, got %q", defaultLandingPath, got)
	}

	resp := w.Result()
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("expected session cookie to be set")
	}
	if !found.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite=%v, want Lax", found.SameSite)
	}
	if found.Path != "/" {
		t.Errorf("session cookie path=%q, want /", found.Path)
	}
	if !store.Validate(found.Value) {
		t.Error("cookie value must be a valid session id")
	}
}

// TestLoginPOSTFailureReturns401 covers the Touch-ID-denied path.
func TestLoginPOSTFailureReturns401(t *testing.T) {
	withStubTouchID(t, func(context.Context) error {
		return context.DeadlineExceeded
	})

	store := newSessionStore(time.Minute)
	h := handleLogin(store, time.Minute)

	r := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			t.Fatal("failed login must not issue a cookie")
		}
	}
}

// TestLoginPOST_SlowTouchIDDoesNotHitWriteTimeout is a regression test
// for a review finding: the server's default WriteTimeout (10s) is
// shorter than defaultRequireTouchID's own timeout (30s, and it
// explicitly supports a slow password-fallback path) — without
// extendWriteDeadline overriding the deadline for this
// request, a legitimate but slow Touch-ID confirmation would have its
// response cut off even though authentication succeeded. This runs a
// real net/http server (httptest.ResponseRecorder does not support
// per-request write deadlines at all, so this can't be a table test)
// and sleeps just past the *old* 10s window.
func TestLoginPOST_SlowTouchIDDoesNotHitWriteTimeout(t *testing.T) {
	withStubTouchID(t, func(ctx context.Context) error {
		select {
		case <-time.After(10500 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	a := newAuditApp(t)
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, a, port, &stdout, time.Minute, time.Second) }()
	t.Cleanup(func() { cancel(); <-done })

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Inspect the login POST's own response, not whatever it
		// redirects to — the point of this test is whether THAT
		// response arrives before the server's write deadline, not
		// whether the redirect chain eventually reaches something.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/login", port), "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("login POST failed, likely truncated by the server's WriteTimeout: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect after a successful, slow Touch-ID confirmation)", resp.StatusCode)
	}
}

// TestHandleReveal_SlowDecryptDoesNotHitWriteTimeout guards the reveal
// write-deadline extension (a regression the reviewer caught): a reveal
// whose decrypt is slow — e.g. a cold gopass agent prompting pinentry —
// must not be truncated by the server's default 10s WriteTimeout after
// App.Get already logged a `get` row. Runs a real server (httptest can't
// exercise write deadlines), logs in to get a session cookie, then
// reveals against a store whose Get sleeps past the old 10s window.
func TestHandleReveal_SlowDecryptDoesNotHitWriteTimeout(t *testing.T) {
	withStubTouchID(t, func(context.Context) error { return nil })
	a, f := newFakeApp(t, "human", &store.Entry{Path: "jasp/github", Org: "jasp", Username: "a", Password: "p1"})

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, a, port, &stdout, time.Minute, time.Second) }()
	t.Cleanup(func() { cancel(); <-done })

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: 20 * time.Second, Jar: jar}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Log in (fast) to obtain a session cookie in the jar.
	loginResp, err := client.Post(base+"/login", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	// Now make the reveal's decrypt slow, past the old 10s window.
	f.GetDelay = 10500 * time.Millisecond

	resp, err := client.Post(base+"/entries/jasp/github", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("reveal POST failed, likely truncated by the server's WriteTimeout: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "p1") {
		t.Errorf("slow-but-successful reveal should still deliver the value: %s", body)
	}
}

// TestSafeNextPath checks the open-redirect guard: same-origin paths
// pass through unchanged, anything that could send the post-login
// redirect off this server falls back to the default.
func TestSafeNextPath(t *testing.T) {
	const def = "/entries"
	cases := map[string]string{
		"":                      def,
		"/entries/jasp/github":  "/entries/jasp/github",
		"/entries?org=jasp":     "/entries?org=jasp",
		"//evil.com":            def,
		"http://evil.com":       def,
		"https://evil.com/path": def,
		"entries":               def,               // must start with "/"
		`/\evil.com`:            def,               // backslash trick
		"/%2F%2Fevil.com":       "/%2F%2Fevil.com", // encoded, not literal // — safe as a path segment
	}
	for next, want := range cases {
		if got := safeNextPath(next, def); got != want {
			t.Errorf("safeNextPath(%q) = %q, want %q", next, got, want)
		}
	}
}

// TestLogin_NextRoundTrip covers the full deep-link flow: an
// unauthenticated request to a specific page redirects to
// /login?next=<page>, the login form echoes it back as a hidden field,
// and a successful POST redirects to that exact page rather than the
// default landing path.
func TestLogin_NextRoundTrip(t *testing.T) {
	store := newSessionStore(time.Minute)

	gateHandler := authGate(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("protected"))
	}))
	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	w := httptest.NewRecorder()
	gateHandler.ServeHTTP(w, r)
	loc := w.Header().Get("Location")
	if loc != "/login?next=%2Fentries%2Fjasp%2Fgithub" {
		t.Fatalf("unexpected redirect from authGate: %q", loc)
	}

	// Follow the redirect: GET /login?next=... must echo it into a
	// hidden form field.
	nextParam := strings.TrimPrefix(loc, "/login?")
	loginGET := httptest.NewRequest("GET", "/login?"+nextParam, nil)
	w2 := httptest.NewRecorder()
	handleLogin(store, time.Minute).ServeHTTP(w2, loginGET)
	if !strings.Contains(w2.Body.String(), `name="next" value="/entries/jasp/github"`) {
		t.Fatalf("login form did not echo next=: %s", w2.Body.String())
	}

	// POST with that hidden field set, as a browser submitting the form
	// would — must redirect to the original destination, not defaultLandingPath.
	withStubTouchID(t, func(context.Context) error { return nil })
	form := strings.NewReader("next=" + url.QueryEscape("/entries/jasp/github"))
	loginPOST := httptest.NewRequest("POST", "/login", form)
	loginPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w3 := httptest.NewRecorder()
	handleLogin(store, time.Minute).ServeHTTP(w3, loginPOST)
	if got := w3.Header().Get("Location"); got != "/entries/jasp/github" {
		t.Errorf("post-login redirect = %q, want the original deep link", got)
	}
}

// TestLoginRejectsOtherMethods confirms DELETE/PUT are rejected.
func TestLoginRejectsOtherMethods(t *testing.T) {
	store := newSessionStore(time.Minute)
	h := handleLogin(store, time.Minute)

	r := httptest.NewRequest("DELETE", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// newAuditApp returns an app with a real (temp) audit log and a handful of
// seeded rows. Store is nil — the web UI never touches it.
func newAuditApp(t *testing.T) *app.App {
	t.Helper()
	// handleIndex reads syncpkg.Load(""), which resolves its path via
	// os.UserHomeDir() — isolate HOME so tests never read (or are
	// affected by) the real developer's ~/.config/my-secrets/sync.yaml.
	t.Setenv("HOME", t.TempDir())
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ctx := context.Background()
	// A handful of representative rows covering every actor_kind and result.
	rows := []audit.Entry{
		{Action: audit.ActionGet, SecretPath: "jasp/github", Org: "jasp", ActorKind: audit.ActorAI, Result: audit.ResultOK, Reason: "allow"},
		{Action: audit.ActionGet, SecretPath: "private/bank", Org: "private", ActorKind: audit.ActorAI, Result: audit.ResultDenied, Reason: "scope"},
		{Action: audit.ActionAdd, SecretPath: "jasp/aws", Org: "jasp", ActorKind: audit.ActorHuman, Result: audit.ResultOK},
		{Action: audit.ActionList, SecretPath: "", Org: "jasp", ActorKind: audit.ActorScript, Result: audit.ResultOK},
	}
	for _, r := range rows {
		if _, err := l.Write(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return &app.App{Audit: l, Policy: policy.Default(), Override: "human"}
}

// newFakeApp wires an App to the in-memory fake store for tests that need
// entry decrypts, not just audit rows. Mirrors internal/app's appWithFake
// test helper: "human"/"fullaccess" expand the policy to grant every
// actor kind full access, working around the fact that caller.Identify
// often classifies a `go test` process as AI (CLAUDECODE=1 in the dev/CI
// environment) — the anti-bypass guard means Override alone cannot force
// it back to human, so the test grants access to whichever kind the
// classifier actually picks.
func newFakeApp(t *testing.T, override string, entries ...*store.Entry) (*app.App, *fake.Store) {
	t.Helper()
	// Mirrors newAuditApp's HOME isolation (see its comment) — any test
	// using this helper with writeTempSyncConfig must land in an
	// isolated tempdir, never the real developer's
	// ~/.config/my-secrets/sync.yaml.
	t.Setenv("HOME", t.TempDir())
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := fake.NewWithEntries(entries...)
	pol := policy.Default()
	if override == "human" || override == "fullaccess" {
		pol = &policy.Policy{Actors: map[string]policy.Rules{
			"human":       {Allow: []string{"**"}},
			"script":      {Allow: []string{"**"}},
			"ai":          {Allow: []string{"**"}},
			"claude-code": {Allow: []string{"**"}},
		}}
		override = "claude-code"
	}
	return &app.App{Store: f, Audit: l, Policy: pol, Override: override}, f
}

// sampleWebEntries sets Org explicitly on every fixture — unlike the real
// store (store.entryFromSecret derives Org from Path automatically),
// fake.Store.NewWithEntries stores a plain struct copy and does not, so
// a test relying on grouping/org-scoped behavior would silently see
// every entry bucketed under Org="" if this were left unset.
func sampleWebEntries() []*store.Entry {
	return []*store.Entry{
		{Path: "jasp/github", Org: "jasp", Username: "alice", Password: "p1", Kind: store.KindToken, Tags: []string{"ci"}},
		{Path: "jasp/aws", Org: "jasp", Username: "bob", Password: "p2", Notes: "prod", Domain: "aws.amazon.com"},
		{Path: "zuhause/router", Org: "zuhause", Username: "admin", Password: "p3"},
		{Path: "private/bank", Org: "private", Username: "me", Password: "p4"},
	}
}

// TestHandleEntries_AlwaysShowsAllEntriesGrouped covers the current
// design: /entries decrypts and shows every policy-visible entry, on one
// page, grouped by org — no click-through, no separate "browse this org"
// step. Filtering then happens entirely client-side (see entries.html's
// inline script), which is also why the server-rendered body always
// contains every entry regardless of any "q" — the data-search attribute
// is what the browser filters on, not the server response.
func TestHandleEntries_AlwaysShowsAllEntriesGrouped(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"jasp/github", "jasp/aws", "zuhause/router", "alice", "aws.amazon.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("entries page missing %q: %s", want, body)
		}
	}
	// Actual per-org headers, not just a substring match against entry
	// paths (which would pass even if grouping were completely broken,
	// since "jasp"/"zuhause" already appear inside "jasp/github" etc.).
	for _, want := range []string{"<h2>jasp", "<h2>zuhause"} {
		if !strings.Contains(body, want) {
			t.Errorf("entries page missing org group header %q: %s", want, body)
		}
	}
	// Exactly one aggregated audit row for the whole page, regardless of
	// how many entries it decrypted.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionListDetail, Limit: 5})
	if len(rows) != 1 {
		t.Errorf("want exactly 1 list_detail row for the page load, got %d", len(rows))
	}
}

// TestHandleEntries_CacheAvoidsRepeatDecrypt is a regression test for a
// real-world problem: even after extendWriteDeadline stopped /entries
// from being cut off outright on a real store, every single page load
// still paid the full decrypt cost — "click a link, wait tens of
// seconds, nothing happens" was still the actual experience. A shared
// entriesCache across requests within its TTL must serve the second
// load from memory: no second App.BrowseDetailed call, and — since no
// decrypt happened — no second list_detail audit row either.
func TestHandleEntries_CacheAvoidsRepeatDecrypt(t *testing.T) {
	a, f := newFakeApp(t, "human", sampleWebEntries()...)
	cache := newEntriesCache()

	getCallsBefore := f.GetCallCount()
	r1 := httptest.NewRequest("GET", "/entries", nil)
	w1 := httptest.NewRecorder()
	handleEntries(a, cache)(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first load: status = %d", w1.Code)
	}
	getCallsAfterFirst := f.GetCallCount()
	if getCallsAfterFirst == getCallsBefore {
		t.Fatal("first load should have decrypted at least once (cache miss)")
	}

	r2 := httptest.NewRequest("GET", "/entries?q=jasp", nil)
	w2 := httptest.NewRecorder()
	handleEntries(a, cache)(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second load: status = %d", w2.Code)
	}
	getCallsAfterSecond := f.GetCallCount()
	if getCallsAfterSecond != getCallsAfterFirst {
		t.Errorf("second load within the cache TTL re-decrypted: %d Get calls before, %d after", getCallsAfterFirst, getCallsAfterSecond)
	}

	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionListDetail, Limit: 5})
	if len(rows) != 1 {
		t.Errorf("want exactly 1 list_detail row (cache hit writes none), got %d", len(rows))
	}
}

// cacheTestApp builds a fake-store App plus a fresh cache for the
// cache-level tests below.
func cacheTestApp(t *testing.T, entries ...*store.Entry) (*app.App, *fake.Store) {
	t.Helper()
	f := fake.NewWithEntries(entries...)
	pol := &policy.Policy{Actors: map[string]policy.Rules{
		"human": {Allow: []string{"**"}}, "claude-code": {Allow: []string{"**"}},
	}}
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &app.App{Store: f, Audit: l, Policy: pol, Override: "claude-code"}, f
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func (c *entriesCache) snapshot() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.refreshing
}

// TestEntriesCache_StaleWhileRevalidate: a stale cache is served
// immediately (no wait) and refreshed in the background, so a later read
// reflects the updated store.
func TestEntriesCache_StaleWhileRevalidate(t *testing.T) {
	a, f := cacheTestApp(t, &store.Entry{Path: "jasp/a", Org: "jasp"})
	cache := newEntriesCache()

	if got, _ := cache.get(context.Background(), a); len(got) != 1 {
		t.Fatalf("initial load: want 1 entry, got %d", len(got))
	}

	// Store grows, cache goes stale.
	if err := f.Set(context.Background(), &store.Entry{Path: "jasp/b", Org: "jasp"}); err != nil {
		t.Fatal(err)
	}
	cache.at = time.Now().Add(-entriesCacheTTL - time.Second)

	// A stale read returns the OLD set immediately (no block) and fires a
	// background refresh.
	got, err := cache.get(context.Background(), a)
	if err != nil {
		t.Fatalf("stale read should not error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("stale read should serve the old (1-entry) set immediately, got %d", len(got))
	}
	// The background refresh converges to the new 2-entry set.
	waitFor(t, "background refresh to pick up the new entry", func() bool {
		n, refreshing := cache.snapshot()
		return n == 2 && !refreshing
	})
	if got, _ := cache.get(context.Background(), a); len(got) != 2 {
		t.Errorf("after refresh want 2 entries, got %d", len(got))
	}
}

// TestEntriesCache_FailedRefreshKeepsStale: a background refresh that
// errors keeps serving the last good result (never an error, never a
// truncated set), and recovery converges on the next stale read.
func TestEntriesCache_FailedRefreshKeepsStale(t *testing.T) {
	a, f := cacheTestApp(t, &store.Entry{Path: "jasp/a", Org: "jasp"})
	cache := newEntriesCache()
	if _, err := cache.get(context.Background(), a); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Make it stale and fail the refresh.
	cache.at = time.Now().Add(-entriesCacheTTL - time.Second)
	f.ListErr = errors.New("store unreachable")
	got, err := cache.get(context.Background(), a)
	if err != nil {
		t.Fatalf("stale-while-revalidate must not surface the refresh error, got: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want the stale good entry, got %d", len(got))
	}
	// The failed refresh clears its flag and leaves the good result intact.
	waitFor(t, "failed refresh to clear its flag", func() bool {
		n, refreshing := cache.snapshot()
		return n == 1 && !refreshing
	})

	// Recover: store gains an entry, next stale read converges to it.
	f.ListErr = nil
	if err := f.Set(context.Background(), &store.Entry{Path: "jasp/b", Org: "jasp"}); err != nil {
		t.Fatal(err)
	}
	cache.at = time.Now().Add(-entriesCacheTTL - time.Second)
	if _, err := cache.get(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "recovery refresh to converge", func() bool {
		n, refreshing := cache.snapshot()
		return n == 2 && !refreshing
	})
}

// TestEntriesCache_WarmPrepopulates: warm() does a synchronous decrypt so
// a subsequent get is a hit with no additional Store.Get calls.
func TestEntriesCache_WarmPrepopulates(t *testing.T) {
	a, f := cacheTestApp(t, &store.Entry{Path: "jasp/a", Org: "jasp"}, &store.Entry{Path: "jasp/b", Org: "jasp"})
	cache := newEntriesCache()

	cache.warm(a)
	after := f.GetCallCount()
	if after == 0 {
		t.Fatal("warm should have decrypted the store")
	}
	got, err := cache.get(context.Background(), a)
	if err != nil || len(got) != 2 {
		t.Fatalf("warmed get: want 2 entries no error, got %d / %v", len(got), err)
	}
	if f.GetCallCount() != after {
		t.Errorf("get after warm should be a cache hit (no new Get calls): before=%d after=%d", after, f.GetCallCount())
	}
}

// TestHandleEntries_CancelledLoadDoesNotPoisonCache is the web-level
// regression test for #73: a /entries request the browser aborts
// mid-decrypt must not leave a truncated result in the cache. The next
// (uncancelled) load must return every entry.
func TestHandleEntries_CancelledLoadDoesNotPoisonCache(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	cache := newEntriesCache()

	// First load with an already-cancelled context — BrowseDetailed's
	// cancellation guard fires, returns an error, and the cache must NOT
	// store a (truncated/empty) partial.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	r1 := httptest.NewRequest("GET", "/entries", nil).WithContext(cancelledCtx)
	w1 := httptest.NewRecorder()
	handleEntries(a, cache)(w1, r1)
	// (The browser already navigated away; the 500 goes to no one. What
	//  matters is only that nothing partial got cached.)

	// Second load, fresh context: must see the full set.
	r2 := httptest.NewRequest("GET", "/entries", nil)
	w2 := httptest.NewRecorder()
	handleEntries(a, cache)(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second load status = %d, want 200; body=%q", w2.Code, w2.Body.String())
	}
	body := w2.Body.String()
	for _, want := range []string{"jasp/github", "jasp/aws", "zuhause/router"} {
		if !strings.Contains(body, want) {
			t.Errorf("second load missing %q — cache was poisoned by the cancelled load: %s", want, body)
		}
	}
}

func TestHandleEntries_FiltersByPolicy(t *testing.T) {
	a, _ := newFakeApp(t, "claude-code", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "private/bank") {
		t.Error("AI actor should not see private/bank")
	}
}

func TestHandleEntries_PrefillsSearchBoxFromQueryParam(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries?q=alice", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	if !strings.Contains(w.Body.String(), `id="search" value="alice"`) {
		t.Errorf("expected ?q= to prefill the search box's value: %s", w.Body.String())
	}
}

// TestHandleEntries_DataSearchAttributeDrivesClientFilter checks that
// each entry card carries a data-search blob the inline JS filter
// matches against (path/username/domain/etc.) — never the password
// value; see TestHandleEntries_NeverRendersPassword for the authoritative
// assertion that no secret value appears anywhere on the page.
func TestHandleEntries_DataSearchAttributeDrivesClientFilter(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	body := w.Body.String()
	// data-search now lives on the <tr>, not co-located with the path's
	// <a href> (which is in a nested <td>), so match on the blob content
	// itself — it already includes the path — rather than the two
	// attributes appearing adjacent in the markup.
	re := regexp.MustCompile(`data-search="([^"]*)"`)
	var blob string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], "jasp/aws") {
			blob = m[1]
			break
		}
	}
	if blob == "" {
		t.Fatalf("could not find jasp/aws's data-search attribute in body: %s", body)
	}
	for _, want := range []string{"jasp/aws", "bob", "aws.amazon.com", "prod"} {
		if !strings.Contains(blob, want) {
			t.Errorf("data-search blob %q missing %q", blob, want)
		}
	}
	if strings.Contains(blob, "p2") {
		t.Error("data-search blob must never contain the password value")
	}
}

// TestHandleEntries_KeyboardNavContract guards the server-side markup the
// keyboard navigation in app.js depends on: each result is an `.entry-row`
// carrying a `data-copy-password` and a detail link, and the keyboard
// hint renders. If the markup drifts, the JS silently stops working, so
// this pins the contract even though the JS itself can't run in a Go test.
func TestHandleEntries_KeyboardNavContract(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)
	body := w.Body.String()

	// A row the JS can navigate to and act on.
	if !strings.Contains(body, `class="entry-row"`) {
		t.Fatal("no .entry-row rows — keyboard nav has nothing to select")
	}
	if !strings.Contains(body, `data-copy-password="jasp/github"`) {
		t.Error("row missing data-copy-password (Enter copy target)")
	}
	if !strings.Contains(body, `href="/entries/jasp/github"`) {
		t.Error("row missing detail link (Shift+Enter open target)")
	}
	// The keyboard hint is shown when there are entries, including the
	// Esc-resets-search affordance.
	if !strings.Contains(body, "kbd-hint") || !strings.Contains(body, "Passwort kopieren") {
		t.Error("keyboard hint not rendered on a non-empty entries page")
	}
	if !strings.Contains(body, "Suche zurücksetzen") {
		t.Error("keyboard hint missing the Esc-resets-search affordance")
	}
	// app.js (which wires the keys) is pulled in via the shared head.
	if !strings.Contains(body, `/static/app.js`) {
		t.Error("app.js not included — keyboard nav would not load")
	}
}

func TestHandleEntries_ShowsLastRead(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	ts := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	_, err := a.Audit.Write(context.Background(), audit.Entry{
		TS: ts, Action: audit.ActionGet, SecretPath: "jasp/github",
		ActorKind: audit.ActorHuman, Result: audit.ResultOK,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "2026-03-04") {
		t.Errorf("expected last-read date for jasp/github in body: %s", body)
	}
	if !strings.Contains(body, "nie") {
		t.Errorf("jasp/aws was never read and should show \"nie\": %s", body)
	}
}

func TestHandleEntryDetail_ShowsLastRead(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	ts := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	_, err := a.Audit.Write(context.Background(), audit.Entry{
		TS: ts, Action: audit.ActionGet, SecretPath: "jasp/github",
		ActorKind: audit.ActorHuman, Result: audit.ResultOK,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if !strings.Contains(w.Body.String(), "2026-03-04") {
		t.Errorf("expected last-read date in detail page: %s", w.Body.String())
	}
}

// TestHandleEntryDetail_BackAffordance pins the "escape back to the list"
// contract: the detail page renders the back link and the Esc hint, and
// pulls in app.js (whose /entries/<path> handler wires Esc → history.back).
func TestHandleEntryDetail_BackAffordance(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)
	body := w.Body.String()

	// Assert on the back-link's own text, not just href="/entries" — the
	// nav bar always carries that href, so a bare href check would stay
	// green even if the "← Alle Einträge" affordance were deleted.
	if !strings.Contains(body, "Alle Einträge") {
		t.Error("detail page missing the back-to-list link")
	}
	if !strings.Contains(body, "kbd-hint") || !strings.Contains(body, "zurück") {
		t.Error("detail page missing the Esc-back hint")
	}
	if !strings.Contains(body, `/static/app.js`) {
		t.Error("app.js not included — Esc-back would not load")
	}
}

// gitRepoForWebHistory mirrors internal/app's gitRepoForHistory helper:
// a minimal real git repo with one commit, wired up via
// PASSWORD_STORE_DIR so App.History resolves against it.
func gitRepoForWebHistory(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	full := filepath.Join(dir, "jasp", "github.gpg")
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "jasp/github.gpg")
	run("commit", "-q", "-m", "add jasp/github")
	t.Setenv("PASSWORD_STORE_DIR", dir)
}

func TestHandleEntryDetail_ShowsHistory(t *testing.T) {
	gitRepoForWebHistory(t)
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "add jasp/github") {
		t.Errorf("expected commit message in history section: %s", w.Body.String())
	}
}

func TestHandleEntryDetail_NoHistorySection_WhenGitUnavailable(t *testing.T) {
	// No repo set up, and PATH points at an empty dir so exec.LookPath
	// ("git") fails inside history.Log — the page must still render.
	t.Setenv("PATH", t.TempDir())
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when git/history is unavailable; body=%q", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "Historie (") {
		t.Error("history section should be omitted entirely when there is no history")
	}
}

func TestHandleReveal_UpdatesLastRead(t *testing.T) {
	withStubTouchID(t, func(context.Context) error { return nil })
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	// Before any reveal: "never".
	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)
	if !strings.Contains(w.Body.String(), "nie") {
		t.Fatalf("expected \"nie\" before any reveal: %s", w.Body.String())
	}

	// Reveal, then load again: should now show a real timestamp.
	r = httptest.NewRequest("POST", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w = httptest.NewRecorder()
	handleEntryDetail(a)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("reveal status = %d", w.Code)
	}

	r = httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w = httptest.NewRecorder()
	handleEntryDetail(a)(w, r)
	if strings.Contains(w.Body.String(), "Zuletzt gelesen</td><td>nie") {
		t.Error("last-read should no longer be \"nie\" after a successful reveal")
	}
}

// TestHandleEntries_BrowsingNeverCountsAsLastRead is the load-bearing
// regression test for the whole feature: merely browsing the list/detail
// pages (App.BrowseDetailed/App.Inspect, ActionListDetail) must never
// make "last read" show a timestamp — only an actual reveal (App.Get)
// may.
func TestHandleEntries_BrowsingNeverCountsAsLastRead(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	// Browse the (always-full) list and the detail page repeatedly —
	// none of this is a "read".
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/entries", nil)
		w := httptest.NewRecorder()
		handleEntries(a, newEntriesCache())(w, r)

		r2 := httptest.NewRequest("GET", "/entries/jasp/github", nil)
		r2.SetPathValue("path", "jasp/github")
		w2 := httptest.NewRecorder()
		handleEntryDetail(a)(w2, r2)
	}

	got, err := a.Audit.LastAccessByPath(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("browsing must never populate last-read, got %+v", got)
	}
}

func TestHandleEntries_NeverRendersPassword(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a, newEntriesCache())(w, r)

	for _, secret := range []string{"p1", "p2", "p3", "p4"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("entries list must never render a password value, found %q", secret)
		}
	}
}

func TestHandleEntryDetail_OK(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "alice") {
		t.Errorf("detail page missing metadata: %s", body)
	}
	if strings.Contains(body, "p1") {
		t.Error("detail page must not render the raw password")
	}
}

// TestHandleEntryDetail_MasksSecretLikeFields guards against rendering
// custom Fields values raw. Field keys are user-defined and can legally
// be named "api_secret"/"db_password" etc. — those must be masked exactly
// like Password, not treated as safe just because they live in the Fields
// map instead of the well-known Password field.
func TestHandleEntryDetail_MasksSecretLikeFields(t *testing.T) {
	e := &store.Entry{
		Path: "jasp/aws", Username: "bob", Password: "p2",
		Fields: map[string]string{
			"api_secret": "sk-super-secret-value",
			"account_id": "123456",
		},
	}
	a, _ := newFakeApp(t, "human", e)
	r := httptest.NewRequest("GET", "/entries/jasp/aws", nil)
	r.SetPathValue("path", "jasp/aws")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	body := w.Body.String()
	if strings.Contains(body, "sk-super-secret-value") {
		t.Error("secret-like field value must be masked, found raw value in body")
	}
	if !strings.Contains(body, "123456") {
		t.Error("non-secret field value (account_id) should render unmasked")
	}
}

// TestHandleEntryDetail_MasksCredentialShapedFields is a regression test
// for a security review finding: the original secret-like-key rule only
// matched "password"/"secret" substrings, so fields like api_key/token/
// private_key rendered raw with no Touch-ID gate at all — a bigger leak
// than the un-gated Password mask, since these are exactly the values a
// hijacked browser session would want.
func TestHandleEntryDetail_MasksCredentialShapedFields(t *testing.T) {
	e := &store.Entry{
		Path: "jasp/aws", Username: "bob", Password: "p2",
		Fields: map[string]string{
			"api_key":      "AKIA-raw-value",
			"access_token": "gho_raw-token-value",
			"private_key":  "-----BEGIN RSA PRIVATE KEY-----raw",
		},
	}
	a, _ := newFakeApp(t, "human", e)
	r := httptest.NewRequest("GET", "/entries/jasp/aws", nil)
	r.SetPathValue("path", "jasp/aws")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	body := w.Body.String()
	for _, raw := range []string{"AKIA-raw-value", "gho_raw-token-value", "-----BEGIN RSA PRIVATE KEY-----raw"} {
		if strings.Contains(body, raw) {
			t.Errorf("credential-shaped field value must be masked, found raw value %q", raw)
		}
	}
}

func TestHandleEntryDetail_Denied(t *testing.T) {
	a, _ := newFakeApp(t, "claude-code", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries/private/bank", nil)
	r.SetPathValue("path", "private/bank")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestHandleEntryDetail_MethodNotAllowed(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)
	r := httptest.NewRequest("DELETE", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestHandleReveal_Success(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	r := httptest.NewRequest("POST", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "p1") {
		t.Error("successful reveal should render the real password value")
	}
	// Reveal must produce a `get` audit row — parity with `mys get --reveal`.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK || rows[0].SecretPath != "jasp/github" {
		t.Fatalf("want 1 ok get row for jasp/github, got %+v", rows)
	}
}

// TestHandleReveal_IsSessionOnly is the load-bearing test for the
// session-only reveal model (#74): once the login session is valid,
// revealing must NOT invoke the OS auth prompt at all — not per reveal,
// not ever. requireTouchIDFunc is stubbed to record calls; a successful
// reveal must leave that count at zero.
func TestHandleReveal_IsSessionOnly(t *testing.T) {
	calls := 0
	withStubTouchID(t, func(context.Context) error { calls++; return nil })
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/entries/jasp/github", nil)
		r.SetPathValue("path", "jasp/github")
		w := httptest.NewRecorder()
		handleEntryDetail(a)(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("reveal %d: status = %d; body=%q", i, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "p1") {
			t.Errorf("reveal %d did not render the value", i)
		}
	}
	if calls != 0 {
		t.Errorf("reveal must not invoke the OS auth prompt (session-only), got %d calls", calls)
	}
}

// TestHandleReveal_JSONMode covers the entries table's inline "copy
// password" button: same App.Get gate as the full-page reveal, just a
// JSON {"password": "..."} response instead of rendering entry.html,
// requested via Accept: application/json.
func TestHandleReveal_JSONMode(t *testing.T) {
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	r := httptest.NewRequest("POST", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var got struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v; body=%q", err, w.Body.String())
	}
	if got.Password != "p1" {
		t.Errorf("password = %q, want p1", got.Password)
	}
	if strings.Contains(w.Body.String(), "<html") {
		t.Error("JSON mode must not render the HTML page")
	}

	// Same audit parity as the HTML-mode reveal.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("want 1 ok get row, got %+v", rows)
	}
}

func TestHandleReveal_JSONMode_Denied(t *testing.T) {
	a, _ := newFakeApp(t, "claude-code", sampleWebEntries()...)

	r := httptest.NewRequest("POST", "/entries/private/bank", nil)
	r.SetPathValue("path", "private/bank")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "p4") {
		t.Error("denied reveal must not leak the password in JSON mode")
	}
}

func TestHandleReveal_JSONMode_PropagatesAppErrorWithoutCredentialContent(
	t *testing.T,
) {
	secretSentinel := "sentinel-" + "secret-must-not-leak"
	entryPath := "jasp/" + "production"
	entryURL := "https://credentials.invalid/" + secretSentinel
	a, fakeStore := newFakeApp(t, "human", &store.Entry{
		Path: entryPath, URL: entryURL, Password: secretSentinel,
	})
	// This transport-only test injects the exact App error at Store.Get.
	// The App runtime contract separately proves that a real team-audit
	// preflight failure returns it before Store.Get.
	fakeStore.GetErr = app.ErrTeamAuditUnavailable

	r := httptest.NewRequest("POST", "/entries/jasp/production", nil)
	r.SetPathValue("path", entryPath)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%q", w.Code, w.Body.String())
	}
	if w.Body.String() != app.ErrTeamAuditUnavailable.Error()+"\n" {
		t.Fatalf("body = %q, want generic audit failure", w.Body.String())
	}
	if strings.Contains(w.Body.String(), secretSentinel) ||
		strings.Contains(w.Body.String(), entryURL) ||
		strings.Contains(w.Body.String(), entryPath) {
		t.Fatalf("reveal response leaked plaintext, URL, or path: %q", w.Body.String())
	}
	if fakeStore.GetCallCount() != 1 {
		t.Fatalf(
			"transport injection Store.Get calls = %d, want 1",
			fakeStore.GetCallCount(),
		)
	}
}

func TestHandleReveal_DeniedDoesNotRenderValue(t *testing.T) {
	a, _ := newFakeApp(t, "claude-code", sampleWebEntries()...)

	r := httptest.NewRequest("POST", "/entries/private/bank", nil)
	r.SetPathValue("path", "private/bank")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "p4") {
		t.Error("denied reveal must not render the password value")
	}
	// Denial is enforced by App.Get's policy check, and writes a denied
	// get row (not an ok one).
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("want 1 denied get row, got %+v", rows)
	}
}

func TestAuthGate_SetsNoStoreHeader(t *testing.T) {
	store := newSessionStore(time.Minute)
	id := store.Issue()
	h := authGate(store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/entries/jasp/github", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		t    time.Time
		want string
	}{
		{"zero", time.Time{}, "nie"},
		{"just now", now.Add(-10 * time.Second), "gerade eben"},
		{"one minute", now.Add(-70 * time.Second), "vor 1 Minute"},
		{"three minutes", now.Add(-3 * time.Minute), "vor 3 Minuten"},
		{"today, two hours ago", now.Add(-2 * time.Hour), "heute, " + now.Add(-2*time.Hour).Local().Format("15:04")},
		{"yesterday", now.AddDate(0, 0, -1), "gestern, " + now.AddDate(0, 0, -1).Local().Format("15:04")},
		{"a week ago", now.AddDate(0, 0, -7), now.AddDate(0, 0, -7).Local().Format("2006-01-02 15:04:05")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// "today, two hours ago" is flaky right around midnight (the
			// 2-hour-ago timestamp could fall on the previous calendar
			// day) — skip that one edge case rather than special-case it.
			if tc.name == "today, two hours ago" && now.Add(-2*time.Hour).Day() != now.Day() {
				t.Skip("would cross midnight in this run — flaky by construction, not a real bug")
			}
			if got := relativeTime(tc.t); got != tc.want {
				t.Errorf("relativeTime(%v) = %q, want %q", tc.t, got, tc.want)
			}
		})
	}
}

func TestSearchableText(t *testing.T) {
	e := &store.Entry{
		Path: "jasp/aws", Username: "bob", URL: "https://aws.amazon.com",
		Domain: "aws.amazon.com", Notes: "prod account", Kind: store.KindAPIKey,
		Tags: []string{"infra", "billing"}, Password: "super-secret-value",
	}
	blob := searchableText(e)
	for _, want := range []string{"jasp/aws", "bob", "aws.amazon.com", "prod account", "api_key", "infra", "billing"} {
		if !strings.Contains(blob, want) {
			t.Errorf("searchableText missing %q: %q", want, blob)
		}
	}
	if strings.Contains(blob, "super-secret-value") {
		t.Error("searchableText must never include the password value")
	}
	if blob != strings.ToLower(blob) {
		t.Error("searchableText must be lowercase (client-side filter lowercases the query to match)")
	}
}

func TestGroupByOrg(t *testing.T) {
	entries := []*store.Entry{
		{Path: "jasp/bbb", Org: "jasp"},
		{Path: "jasp/aaa", Org: "jasp"},
		{Path: "zuhause/router", Org: "zuhause"},
	}
	groups := groupByOrg(entries)
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d", len(groups))
	}
	if groups[0].Org != "jasp" || groups[1].Org != "zuhause" {
		t.Errorf("groups not sorted by org name: %+v", groups)
	}
	if len(groups[0].Entries) != 2 || groups[0].Entries[0].Path != "jasp/aaa" {
		t.Errorf("entries within a group not sorted by path: %+v", groups[0].Entries)
	}
}

func TestHandleIndex(t *testing.T) {
	a := newAuditApp(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(a)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// Stats render — four seeded rows and the three actor-kind counts must
	// all appear. The denied-count path is also exercised here.
	for _, substr := range []string{"Total events", "my-secrets", "jasp/github", "Audit Log"} {
		if !strings.Contains(body, substr) {
			t.Errorf("index body missing %q: %s", substr, body[:minInt(len(body), 300)])
		}
	}
}

// TestVersionShownInFooters pins the update-verification surface: the
// login page (pre-auth, reachable without Touch ID) and the start page
// both render the injected binary version in their footers, so a PWA
// user can confirm an update landed without a shell.
func TestVersionShownInFooters(t *testing.T) {
	prev := Version
	Version = "v9.9.9-test"
	t.Cleanup(func() { Version = prev })

	lw := httptest.NewRecorder()
	handleLogin(newSessionStore(time.Minute), time.Minute)(lw, httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(lw.Body.String(), "mys v9.9.9-test") {
		t.Errorf("login footer missing version: %s", lw.Body.String())
	}

	a := newAuditApp(t)
	iw := httptest.NewRecorder()
	handleIndex(a)(iw, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(iw.Body.String(), "mys v9.9.9-test") {
		t.Errorf("start page footer missing version")
	}
}

// TestHandleIndex_SearchAndRecentlyUsed covers the redesigned start page:
// a search form pointing at /entries, and a "zuletzt benutzt" list built
// from the audit log's get/ok rows (never from denied gets), each with a
// one-click copy-password button — all without decrypting anything.
func TestHandleIndex_SearchAndRecentlyUsed(t *testing.T) {
	// newAuditApp seeds a get/ok for jasp/github and a get/denied for
	// private/bank; only the former is "recently used".
	a := newAuditApp(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(a)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	// Search form → /entries with an input named q.
	if !strings.Contains(body, `action="/entries"`) || !strings.Contains(body, `name="q"`) {
		t.Errorf("start page missing a search form pointing at /entries: %s", body)
	}
	// Recently-used shows the successfully-read path with a copy button…
	if !strings.Contains(body, `data-copy-password="jasp/github"`) {
		t.Errorf("recently-used missing jasp/github copy button: %s", body)
	}
	// …but never a path that was only ever denied.
	if strings.Contains(body, `data-copy-password="private/bank"`) {
		t.Error("a denied get must not appear in recently-used")
	}
}

func TestRecentlyUsed_OrdersByMostRecentAndCapsLimit(t *testing.T) {
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	a := &app.App{Audit: l, Policy: policy.Default(), Override: "human"}
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, p := range []string{"jasp/old", "jasp/mid", "jasp/new"} {
		_, _ = l.Write(ctx, audit.Entry{
			TS: base.Add(time.Duration(i) * time.Hour), Action: audit.ActionGet,
			SecretPath: p, ActorKind: audit.ActorHuman, Result: audit.ResultOK,
		})
	}
	got := recentlyUsed(a, ctx, 2)
	if len(got) != 2 {
		t.Fatalf("want 2 (capped), got %d", len(got))
	}
	if got[0].Path != "jasp/new" || got[1].Path != "jasp/mid" {
		t.Errorf("want most-recent-first [jasp/new jasp/mid], got %+v", got)
	}
}

// writeTempSyncConfig writes a sync.yaml under the current $HOME (which
// newAuditApp/newFakeApp already isolate to a per-test tempdir) so
// syncpkg.Load("") — resolving its path via os.UserHomeDir() — picks it
// up without ever touching the real developer's sync config. Must be
// called AFTER whichever helper set HOME, not before, or it would write
// into a directory a later t.Setenv("HOME", ...) immediately discards.
func writeTempSyncConfig(t *testing.T, cfg *syncpkg.Config) {
	t.Helper()
	home := os.Getenv("HOME")
	if home == "" {
		t.Fatal("writeTempSyncConfig: HOME is not set — call after newAuditApp/newFakeApp")
	}
	path := filepath.Join(home, ".config", "my-secrets", "sync.yaml")
	if err := syncpkg.Save(path, cfg); err != nil {
		t.Fatalf("save sync config: %v", err)
	}
}

func TestHandleIndex_ShowsSyncStatus(t *testing.T) {
	a := newAuditApp(t)
	lastSync := time.Date(2026, 2, 1, 9, 0, 0, 0, time.UTC)
	writeTempSyncConfig(t, &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutSingle,
		Remotes: []syncpkg.StoreRemote{
			{Mount: syncpkg.DefaultStoreMount, URL: "git@github.com:me/my-secrets-store.git", LastSync: lastSync},
		},
	})
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	// shortTime renders in local time, so assert against the same
	// conversion rather than a hardcoded UTC date string — otherwise
	// this test is timezone-fragile (fails west of UTC-9, where
	// 2026-02-01T09:00Z's local date rolls back to 2026-01-31).
	wantDate := lastSync.Local().Format("2006-01-02")
	for _, want := range []string{"my-secrets-store.git", wantDate} {
		if !strings.Contains(body, want) {
			t.Errorf("index body missing sync status %q: %s", want, body)
		}
	}
}

func TestHandleIndex_NoSyncConfigured(t *testing.T) {
	// No sync.yaml written (newAuditApp already isolates HOME to an
	// empty tempdir) — syncpkg.Load("") returns an empty Config, not an
	// error, and the page must render a plain empty state rather than
	// fail or block on a network probe.
	a := newAuditApp(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "kein Sync konfiguriert") {
		t.Error("expected empty-state message when no sync.yaml exists")
	}
}

func TestHandleAudit(t *testing.T) {
	a := newAuditApp(t)

	cases := []struct {
		name        string
		query       string
		wantStatus  int
		wantMatches []string
	}{
		{"all", "", 200, []string{"jasp/github", "private/bank", "jasp/aws"}},
		{"actor_filter_ai", "actor=ai", 200, []string{"jasp/github", "private/bank"}},
		{"action_filter_get", "action=get", 200, []string{"jasp/github"}},
		{"org_filter_jasp", "org=jasp", 200, []string{"jasp/github", "jasp/aws"}},
		{"since_date", "since=2000-01-01", 200, []string{"jasp/github"}},
		// Invalid since is silently ignored — the handler must still 200.
		{"since_bad", "since=not-a-date", 200, []string{"jasp/github"}},
		// Limit > 1000 or <= 0 is clamped to 100.
		{"limit_clamp_high", "limit=99999", 200, []string{"jasp/github"}},
		{"limit_clamp_zero", "limit=0", 200, []string{"jasp/github"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/audit?"+tc.query, nil)
			w := httptest.NewRecorder()
			handleAudit(a)(w, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body=%q", w.Code, tc.wantStatus, w.Body.String())
				return
			}
			body := w.Body.String()
			for _, m := range tc.wantMatches {
				if !strings.Contains(body, m) {
					t.Errorf("body missing %q", m)
				}
			}
		})
	}
}

func TestActorBadge(t *testing.T) {
	cases := map[string]string{
		audit.ActorAI:     "#a78bfa",
		audit.ActorHuman:  "#4ade80",
		audit.ActorScript: "#f59e42",
		"unknown":         "#8b90a0",
	}
	for kind, expectedColor := range cases {
		got := string(actorBadge(kind))
		if !strings.Contains(got, expectedColor) {
			t.Errorf("actorBadge(%q) should contain %q: %s", kind, expectedColor, got)
		}
		if !strings.Contains(got, kind) {
			t.Errorf("actorBadge(%q) should include kind label", kind)
		}
	}
}

func TestResultBadge(t *testing.T) {
	cases := map[string]string{
		audit.ResultOK:     "#4ade80",
		audit.ResultDenied: "#f87171",
		audit.ResultError:  "#f59e42",
		"weird":            "#8b90a0",
	}
	for result, expectedColor := range cases {
		got := string(resultBadge(result))
		if !strings.Contains(got, expectedColor) {
			t.Errorf("resultBadge(%q) should contain %q: %s", result, expectedColor, got)
		}
	}
}

func TestCountHelpers(t *testing.T) {
	a := newAuditApp(t)
	ctx := context.Background()
	// Sanity: we seeded 2 AI, 1 Human, 1 Script, 1 Denied.
	if got := countActor(a, ctx, audit.ActorAI); got != 2 {
		t.Errorf("countActor ai = %d, want 2", got)
	}
	if got := countActor(a, ctx, audit.ActorHuman); got != 1 {
		t.Errorf("countActor human = %d, want 1", got)
	}
	if got := countResult(a, ctx, audit.ResultDenied); got != 1 {
		t.Errorf("countResult denied = %d, want 1", got)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestServe_StartStop starts the HTTP server on a random free port, issues
// a /healthz probe, then cancels the context to exercise the shutdown path.
func TestServe_StartStop(t *testing.T) {
	a := newAuditApp(t)
	port := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, a, port, &stdout) }()

	// Poll /healthz until the server is listening (or time out).
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		cancel()
		<-done
		t.Fatalf("server never came up: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("/healthz = %q, want ok", string(body))
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve returned error: %v", err)
	}

	// A web_open audit row must have been written on startup.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionWebOpen, Limit: 5})
	if len(rows) == 0 {
		t.Error("expected web_open audit entry")
	}
}

// TestServe_PWAAssetsAreServed confirms the manifest, service worker, and
// icons the PWA shell depends on are actually reachable through the real
// static file handler — these are embed.FS entries, not template output,
// so httptest-direct handler calls elsewhere in this file don't exercise
// the //go:embed wiring the way a real running server does.
func TestServe_PWAAssetsAreServed(t *testing.T) {
	a := newAuditApp(t)
	port := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, a, port, &stdout) }()
	t.Cleanup(func() { cancel(); <-done })

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port)); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	cases := []struct {
		path        string
		wantContain string // empty = just check 200 + non-empty body
	}{
		{"/static/manifest.webmanifest", `"start_url": "/"`},
		{"/static/sw.js", "addEventListener"},
		{"/static/icons/icon-192.png", ""},
		{"/static/icons/icon-512.png", ""},
	}
	for _, tc := range cases {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, tc.path))
		if err != nil {
			t.Errorf("%s: %v", tc.path, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tc.path, resp.StatusCode)
		}
		if len(body) == 0 {
			t.Errorf("%s: empty body", tc.path)
		}
		if tc.wantContain != "" && !strings.Contains(string(body), tc.wantContain) {
			t.Errorf("%s: body missing %q", tc.path, tc.wantContain)
		}
	}
}

// TestHandleEntries_SlowDecryptDoesNotHitWriteTimeout is a regression
// test for a real-world bug found on a real store: with enough entries
// and real decrypt latency, /entries used to take longer than the
// server's default 10s WriteTimeout. The request's context got cancelled
// mid-decrypt (surfacing as a wall of "context canceled" errors from the
// remaining Store.Get calls) and the connection was torn down before any
// response reached the browser — the page silently "loaded nothing".
// Simulates 3 entries at 4s of decrypt latency each (12s total, past the
// old 10s window, comfortably inside entriesWriteBudget) through a real
// net/http server — httptest.ResponseRecorder doesn't support write
// deadlines at all, so this can't be a table test against the handler
// directly.
func TestHandleEntries_SlowDecryptDoesNotHitWriteTimeout(t *testing.T) {
	withStubTouchID(t, func(context.Context) error { return nil })
	entries := []*store.Entry{
		{Path: "jasp/a", Org: "jasp", Username: "a"},
		{Path: "jasp/b", Org: "jasp", Username: "b"},
		{Path: "jasp/c", Org: "jasp", Username: "c"},
	}
	a, f := newFakeApp(t, "human", entries...)
	f.GetDelay = 4 * time.Second

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- serveWith(ctx, a, port, &stdout, time.Minute, time.Second) }()
	t.Cleanup(func() { cancel(); <-done })

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
		// Without this, the client follows the login POST's 303 redirect
		// straight into GET /entries, running the slow decrypt path once
		// there and again for the explicit GET below — doubling the
		// test's cost and moving the failure (without the fix) to the
		// login call instead of the intended assertion.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	loginResp, err := client.Post(base+"/login", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()

	resp, err := client.Get(base + "/entries")
	if err != nil {
		t.Fatalf("GET /entries failed, likely truncated by the server's WriteTimeout: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, body)
	}
	for _, want := range []string{"jasp/a", "jasp/b", "jasp/c"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("entries page missing %q despite slow decrypts: %s", want, body)
		}
	}
}

// TestSWJS_NeverCaches guards the security-load-bearing constraint on the
// service worker: it must never call caches.open/cache.put, or a
// revealed secret value could persist unencrypted in Cache Storage
// outside the audit log's visibility (see docs/SECURITY.md).
func TestSWJS_NeverCaches(t *testing.T) {
	b, err := assets.ReadFile("static/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, forbidden := range []string{"caches.open", "cache.put", ".put(", ".add("} {
		if strings.Contains(src, forbidden) {
			t.Errorf("sw.js must never cache anything, found forbidden call %q", forbidden)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
