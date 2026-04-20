package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
)

// fakeApp wires a fake store and an isolated audit log into a full-access
// policy so runLs can exercise the filter paths without hitting gopass.
func fakeApp(t *testing.T, entries ...*store.Entry) *app.App {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	pol := &policy.Policy{Actors: map[string]policy.Rules{
		"human":       {Allow: []string{"**"}},
		"script":      {Allow: []string{"**"}},
		"ai":          {Allow: []string{"**"}},
		"claude-code": {Allow: []string{"**"}},
	}}
	f := fake.NewWithEntries(entries...)
	// Disable auto-sync side effects for these tests.
	prev := app.NoSyncFlag
	app.NoSyncFlag = true
	t.Cleanup(func() { app.NoSyncFlag = prev })
	return &app.App{Store: f, Audit: l, Policy: pol, Override: "human"}
}

func TestRunLs_StaleFilter(t *testing.T) {
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	stale := &store.Entry{
		Path:        "jasp/stale",
		Password:    "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-120 * 24 * time.Hour), // 30 days overdue
	}
	fresh := &store.Entry{
		Path:        "jasp/fresh",
		Password:    "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-10 * 24 * time.Hour),
	}
	noPolicy := &store.Entry{
		Path:     "zuhause/router",
		Password: "p",
		// No RotateAfter — must never show up in --stale.
	}
	a := fakeApp(t, stale, fresh, noPolicy)

	var buf bytes.Buffer
	if err := runLs(context.Background(), a, &buf, lsOptions{
		StaleOnly: true,
		Now:       now,
	}); err != nil {
		t.Fatalf("runLs: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "jasp/stale") {
		t.Errorf("stale entry missing from --stale output:\n%s", out)
	}
	if strings.Contains(out, "jasp/fresh") {
		t.Errorf("fresh entry leaked into --stale output:\n%s", out)
	}
	if strings.Contains(out, "zuhause/router") {
		t.Errorf("no-policy entry leaked into --stale output:\n%s", out)
	}
	// Enriched format includes age + rotate_after.
	if !strings.Contains(out, "rotate_after=90d") {
		t.Errorf("--stale output missing rotate_after= suffix:\n%s", out)
	}
	if !strings.Contains(out, "30d old") {
		t.Errorf("--stale output missing '30d old' age:\n%s", out)
	}
}

func TestRunLs_RotatingInFilter(t *testing.T) {
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	soon := &store.Entry{
		Path:        "jasp/soon",
		Password:    "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-85 * 24 * time.Hour), // due in 5 days
	}
	later := &store.Entry{
		Path:        "jasp/later",
		Password:    "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-10 * 24 * time.Hour), // due in 80 days
	}
	a := fakeApp(t, soon, later)

	var buf bytes.Buffer
	if err := runLs(context.Background(), a, &buf, lsOptions{
		RotatingIn: 7 * 24 * time.Hour,
		Now:        now,
	}); err != nil {
		t.Fatalf("runLs: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "jasp/soon") {
		t.Errorf("due-soon entry missing:\n%s", out)
	}
	if strings.Contains(out, "jasp/later") {
		t.Errorf("far-future entry leaked into --rotating-in 7d output:\n%s", out)
	}
}

func TestRunLs_StaleAndRotatingInCombined(t *testing.T) {
	// Combining both filters is AND: an entry must be stale and due
	// within the window. A stale entry is always "due within" any
	// positive window (DueWithin treats past-due as in-window), so the
	// combined filter collapses to --stale; but we still must not
	// emit entries that are fresh + merely soon.
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	stale := &store.Entry{
		Path: "jasp/stale", Password: "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-100 * 24 * time.Hour),
	}
	soonButNotStale := &store.Entry{
		Path: "jasp/soon", Password: "p",
		RotateAfter: "90d",
		RotatedAt:   now.Add(-85 * 24 * time.Hour),
	}
	a := fakeApp(t, stale, soonButNotStale)

	var buf bytes.Buffer
	if err := runLs(context.Background(), a, &buf, lsOptions{
		StaleOnly:  true,
		RotatingIn: 30 * 24 * time.Hour,
		Now:        now,
	}); err != nil {
		t.Fatalf("runLs: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "jasp/stale") {
		t.Errorf("stale+in-window entry missing:\n%s", out)
	}
	if strings.Contains(out, "jasp/soon") {
		t.Errorf("not-yet-stale entry leaked:\n%s", out)
	}
}

func TestRunLs_NoFiltersListsAll(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/a", Password: "p"},
		&store.Entry{Path: "zuhause/b", Password: "p"},
	)
	var buf bytes.Buffer
	if err := runLs(context.Background(), a, &buf, lsOptions{
		Now: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("runLs: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"jasp/a", "zuhause/b"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}
