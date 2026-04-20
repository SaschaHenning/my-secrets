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

func TestMatchesFields_ExactAND(t *testing.T) {
	entry := map[string]string{
		"account_id": "12345",
		"region":     "eu-central-1",
		"tenant":     "acme",
	}
	cases := []struct {
		name    string
		filters map[string]string
		want    bool
	}{
		{"single match", map[string]string{"region": "eu-central-1"}, true},
		{"case-insensitive value", map[string]string{"region": "EU-Central-1"}, true},
		{"multi AND match", map[string]string{"region": "eu-central-1", "tenant": "acme"}, true},
		{"one mismatch fails all", map[string]string{"region": "eu-central-1", "tenant": "other"}, false},
		{"missing key fails", map[string]string{"nope": "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFields(entry, tc.filters)
			if got != tc.want {
				t.Errorf("matchesFields = %v, want %v", got, tc.want)
			}
		})
	}
}

// Review finding I3: --field region= must be a presence check that
// matches any non-empty value, not a literal empty-string comparison.
func TestMatchesFields_EmptyValueIsPresenceCheck(t *testing.T) {
	withRegion := map[string]string{"region": "eu-central-1"}
	emptyRegion := map[string]string{"region": ""}
	noRegion := map[string]string{"other": "x"}

	filters := map[string]string{"region": ""}

	if !matchesFields(withRegion, filters) {
		t.Error("empty filter value should match any non-empty value")
	}
	if matchesFields(emptyRegion, filters) {
		t.Error("empty filter value must not match an entry whose field is also empty")
	}
	if matchesFields(noRegion, filters) {
		t.Error("empty filter value must not match an entry missing the key entirely")
	}
}

func TestHasTag(t *testing.T) {
	tags := []string{"infra", "ci"}
	if !hasTag(tags, "infra") {
		t.Error("expected hit for infra")
	}
	if hasTag(tags, "INFRA") {
		t.Error("tag match must be case-sensitive to match existing behaviour")
	}
	if hasTag(nil, "x") {
		t.Error("nil tag list must not match")
	}
}

// Integration-ish: exercise the matching helpers against an Entry-like
// seed that mirrors what cmd_ls would filter over.
func TestDomainSubdomainMatchViaMatchDomain(t *testing.T) {
	tier, _, ok := store.MatchDomain("amazon.com", "aws.amazon.com")
	if !ok || tier != store.TierSubdomain {
		t.Errorf("amazon.com vs aws.amazon.com: tier=%q ok=%v, want subdomain/true", tier, ok)
	}
	_, _, ok = store.MatchDomain("amazon.com", "jasp.eu")
	if ok {
		t.Error("amazon.com vs jasp.eu must not match")
	}
}
