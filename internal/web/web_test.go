package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
