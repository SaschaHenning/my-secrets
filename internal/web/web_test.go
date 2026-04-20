package web

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
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
// valid session cookie is bounced to /login with a 303.
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
	if got := w.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected redirect to /login, got %q", got)
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
// /login, expect a Set-Cookie and a redirect to /.
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
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("expected redirect to /, got %q", got)
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
