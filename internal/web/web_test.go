package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
