package web

import (
	"bytes"
	"context"
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
// default landing page (the search-first entries browser, not the
// stats overview — matches the PWA's start_url).
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
	handleEntries(a)(w, r)

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

func TestHandleEntries_FiltersByPolicy(t *testing.T) {
	a, _ := newFakeApp(t, "claude-code", sampleWebEntries()...)
	r := httptest.NewRequest("GET", "/entries", nil)
	w := httptest.NewRecorder()
	handleEntries(a)(w, r)

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
	handleEntries(a)(w, r)

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
	handleEntries(a)(w, r)

	body := w.Body.String()
	re := regexp.MustCompile(`href="/entries/jasp/aws" data-search="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("could not find jasp/aws's data-search attribute in body: %s", body)
	}
	blob := m[1]
	for _, want := range []string{"jasp/aws", "bob", "aws.amazon.com", "prod"} {
		if !strings.Contains(blob, want) {
			t.Errorf("data-search blob %q missing %q", blob, want)
		}
	}
	if strings.Contains(blob, "p2") {
		t.Error("data-search blob must never contain the password value")
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
	handleEntries(a)(w, r)

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
		handleEntries(a)(w, r)

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
	handleEntries(a)(w, r)

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
	withStubTouchID(t, func(context.Context) error { return nil })
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
	if w.Header().Get("Cache-Control") != "" {
		// handleEntryDetail is exercised directly here (bypassing authGate,
		// same as every other handler test in this file), so no-store is
		// asserted separately in TestAuthGate_SetsNoStoreHeader — this
		// check just documents that the handler itself sets no headers
		// that would fight authGate's Cache-Control.
		t.Logf("handler set its own Cache-Control=%q (authGate also sets one)", w.Header().Get("Cache-Control"))
	}

	// Reveal must produce a `get` audit row — parity with `mys get --reveal`.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 5})
	if len(rows) != 1 || rows[0].Result != audit.ResultOK || rows[0].SecretPath != "jasp/github" {
		t.Fatalf("want 1 ok get row for jasp/github, got %+v", rows)
	}
}

func TestHandleReveal_TouchIDFailure_StaysMasked(t *testing.T) {
	withStubTouchID(t, func(context.Context) error { return errors.New("user cancelled") })
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	r := httptest.NewRequest("POST", "/entries/jasp/github", nil)
	r.SetPathValue("path", "jasp/github")
	w := httptest.NewRecorder()
	handleEntryDetail(a)(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (masked re-render, not an HTTP error); body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "p1") {
		t.Error("failed Touch ID must not reveal the password")
	}
	if !strings.Contains(body, "user cancelled") {
		t.Error("failed Touch ID should surface an error message")
	}
	// No `get` row on a failed reveal attempt — nothing was actually read.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionGet, Limit: 5})
	if len(rows) != 0 {
		t.Errorf("failed Touch ID must not write a get row, got %d", len(rows))
	}
}

func TestHandleReveal_RequiresFreshTouchIDEveryTime(t *testing.T) {
	calls := 0
	withStubTouchID(t, func(context.Context) error {
		calls++
		return nil
	})
	a, _ := newFakeApp(t, "human", sampleWebEntries()...)

	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/entries/jasp/github", nil)
		r.SetPathValue("path", "jasp/github")
		w := httptest.NewRecorder()
		handleEntryDetail(a)(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("reveal %d: status = %d", i, w.Code)
		}
	}
	if calls != 2 {
		t.Errorf("Touch ID challenge count = %d, want 2 (one per reveal, no session-cookie shortcut)", calls)
	}
}

func TestHandleReveal_DeniedNeverCallsTouchIDOrRendersValue(t *testing.T) {
	touchIDCalled := false
	withStubTouchID(t, func(context.Context) error {
		touchIDCalled = true
		return nil
	})
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
	// Policy denial happens inside App.Get before Touch ID would even
	// matter for authorization, but a denied caller should not be able to
	// trigger the Touch-ID prompt at all via a path they can't read.
	if touchIDCalled {
		t.Error("Touch ID should not fire for a policy-denied path")
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
		{"/static/manifest.webmanifest", `"start_url": "/entries"`},
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
