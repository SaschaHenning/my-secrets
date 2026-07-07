package web

// Temporary helper for the PR's before/after UI evidence — renders the
// login and start pages to static HTML for screenshotting. Deleted
// before merge; guarded so it never runs in normal test runs.

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestDumpPagesForScreenshot(t *testing.T) {
	dir := os.Getenv("DUMP_DIR")
	if dir == "" {
		t.Skip("set DUMP_DIR to dump rendered pages")
	}
	prev := Version
	Version = os.Getenv("DUMP_VERSION")
	t.Cleanup(func() { Version = prev })

	lw := httptest.NewRecorder()
	handleLogin(newSessionStore(time.Minute), time.Minute)(lw, httptest.NewRequest("GET", "/login", nil))
	if err := os.WriteFile(dir+"/login-after/index.html", lw.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newAuditApp(t)
	iw := httptest.NewRecorder()
	handleIndex(a)(iw, httptest.NewRequest("GET", "/", nil))
	if err := os.WriteFile(dir+"/start-after/index.html", iw.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
