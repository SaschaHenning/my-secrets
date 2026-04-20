package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

// stubProvider is a test-only RotationEntriesProvider that returns a
// fixed entry slice (or a fixed error).
type stubProvider struct {
	entries []*store.Entry
	err     error
}

func (s stubProvider) Entries(_ context.Context) ([]*store.Entry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}

// withRotationProvider swaps the provider for the duration of the test
// and restores it via Cleanup.
func withRotationProvider(t *testing.T, entries []*store.Entry, err error, now time.Time) {
	t.Helper()
	prevP := SetRotationProvider(stubProvider{entries: entries, err: err})
	prevN := SetRotationNow(func() time.Time { return now })
	t.Cleanup(func() {
		SetRotationProvider(prevP)
		SetRotationNow(prevN)
	})
}

func TestCheckRotationOverdue_PassOnEmptyStore(t *testing.T) {
	withRotationProvider(t, nil, nil, time.Now().UTC())
	c := CheckRotationOverdue(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckRotationOverdue_WarnOnTwoStale(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	entries := []*store.Entry{
		// Two stale entries.
		{Path: "jasp/a", RotateAfter: "90d", RotatedAt: now.Add(-100 * 24 * time.Hour)},
		{Path: "jasp/b", RotateAfter: "30d", RotatedAt: now.Add(-40 * 24 * time.Hour)},
		// One fresh entry.
		{Path: "jasp/c", RotateAfter: "90d", RotatedAt: now.Add(-10 * 24 * time.Hour)},
		// One with no policy (ignored).
		{Path: "zuhause/router"},
	}
	withRotationProvider(t, entries, nil, now)

	c := CheckRotationOverdue(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN, got %s (%s)", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, "2 stale") {
		t.Errorf("expected '2 stale' in message, got %q", c.Message)
	}
	if c.Remedy == "" {
		t.Error("WARN should carry a remedy hint")
	}
}

func TestCheckRotationOverdue_WarnOnPolicyWithoutHistory(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	entries := []*store.Entry{
		{Path: "jasp/a", RotateAfter: "90d"}, // policy, no rotated_at
	}
	withRotationProvider(t, entries, nil, now)

	c := CheckRotationOverdue(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN, got %s (%s)", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, "no rotation history") {
		t.Errorf("expected 'no rotation history' in message, got %q", c.Message)
	}
}

func TestCheckRotationOverdue_StaleDominatesPolicyOnly(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	entries := []*store.Entry{
		{Path: "jasp/a", RotateAfter: "90d", RotatedAt: now.Add(-100 * 24 * time.Hour)},
		{Path: "jasp/b", RotateAfter: "90d"}, // policy-only
	}
	withRotationProvider(t, entries, nil, now)

	c := CheckRotationOverdue(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN, got %s", c.Status)
	}
	if !strings.Contains(c.Message, "1 stale") {
		t.Errorf("expected '1 stale' in message, got %q", c.Message)
	}
	if !strings.Contains(c.Message, "1 more have a policy but no rotation history") {
		t.Errorf("expected trailing '(1 more …)' note, got %q", c.Message)
	}
}

func TestCheckRotationOverdue_WarnOnProviderError(t *testing.T) {
	withRotationProvider(t, nil, errors.New("gpg locked"), time.Now().UTC())
	c := CheckRotationOverdue(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN on provider error, got %s (%s)", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, "gpg") {
		t.Errorf("message should mention gpg, got %q", c.Message)
	}
}
