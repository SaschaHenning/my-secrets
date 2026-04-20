package rotation

import (
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		// Happy paths — cover every supported unit.
		{"30 days", "30d", 30 * 24 * time.Hour, false},
		{"2 weeks", "2w", 2 * 7 * 24 * time.Hour, false},
		{"3 months", "3m", 3 * 30 * 24 * time.Hour, false},
		{"1 year", "1y", 365 * 24 * time.Hour, false},
		// Rejections requested by the issue.
		{"nonsense suffix", "abc", 0, true},
		{"no unit suffix", "30", 0, true},
		{"negative duration", "-5d", 0, true},
		// Additional defence-in-depth rejections.
		{"empty string", "", 0, true},
		{"zero", "0d", 0, true},
		{"unknown unit", "7h", 0, true},
		{"float prefix", "2.5d", 0, true},
		{"plus sign", "+5d", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDuration(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsStale(t *testing.T) {
	now := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		entry          *store.Entry
		wantStale      bool
		wantPolicyOnly bool // expected PolicyWithoutHistory(e)
	}{
		{
			name:      "nil entry is not stale",
			entry:     nil,
			wantStale: false,
		},
		{
			name:      "no policy is not stale",
			entry:     &store.Entry{Path: "jasp/x", RotatedAt: now.Add(-365 * 24 * time.Hour)},
			wantStale: false,
		},
		{
			name: "91 days old with 90d policy is stale",
			entry: &store.Entry{
				Path:        "jasp/a",
				RotateAfter: "90d",
				RotatedAt:   now.Add(-91 * 24 * time.Hour),
			},
			wantStale: true,
		},
		{
			name: "89 days old with 90d policy is not stale",
			entry: &store.Entry{
				Path:        "jasp/b",
				RotateAfter: "90d",
				RotatedAt:   now.Add(-89 * 24 * time.Hour),
			},
			wantStale: false,
		},
		{
			name: "policy without history is not stale but flagged",
			entry: &store.Entry{
				Path:        "jasp/c",
				RotateAfter: "90d",
				// RotatedAt left zero.
			},
			wantStale:      false,
			wantPolicyOnly: true,
		},
		{
			name: "unparseable policy is not stale",
			entry: &store.Entry{
				Path:        "jasp/d",
				RotateAfter: "foobar",
				RotatedAt:   now.Add(-1000 * 24 * time.Hour),
			},
			wantStale: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stale, overdue := IsStale(tc.entry, now)
			if stale != tc.wantStale {
				t.Errorf("IsStale = %v, want %v", stale, tc.wantStale)
			}
			if !stale && overdue != 0 {
				t.Errorf("IsStale=false but overdue=%v; want 0", overdue)
			}
			if stale && overdue <= 0 {
				t.Errorf("IsStale=true but overdue=%v; want positive", overdue)
			}
			if got := PolicyWithoutHistory(tc.entry); got != tc.wantPolicyOnly {
				t.Errorf("PolicyWithoutHistory = %v, want %v", got, tc.wantPolicyOnly)
			}
		})
	}
}

func TestIsStaleOverdueDuration(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	e := &store.Entry{
		RotateAfter: "90d",
		RotatedAt:   now.Add(-95 * 24 * time.Hour),
	}
	stale, overdue := IsStale(e, now)
	if !stale {
		t.Fatalf("expected stale")
	}
	// horizon at -5d means overdue ~= 5d
	want := 5 * 24 * time.Hour
	if overdue != want {
		t.Errorf("overdue = %v, want %v", overdue, want)
	}
}

func TestDueWithin(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	// 85d old with 90d policy → due in 5d, inside a 7d window.
	e := &store.Entry{
		RotateAfter: "90d",
		RotatedAt:   now.Add(-85 * 24 * time.Hour),
	}
	soon, dueIn := DueWithin(e, now, 7*24*time.Hour)
	if !soon {
		t.Fatalf("expected dueSoon=true")
	}
	// dueIn should be ~5 days (positive — not yet overdue).
	if dueIn < 4*24*time.Hour || dueIn > 6*24*time.Hour {
		t.Errorf("dueIn = %v, want approximately 5d", dueIn)
	}

	// A 30d-old entry with 90d policy → 60 days remaining → outside a
	// 7d window.
	e2 := &store.Entry{
		RotateAfter: "90d",
		RotatedAt:   now.Add(-30 * 24 * time.Hour),
	}
	soon2, dueIn2 := DueWithin(e2, now, 7*24*time.Hour)
	if soon2 {
		t.Errorf("expected dueSoon=false for e2, got true (dueIn=%v)", dueIn2)
	}
}

func TestDueWithinPastDueIsStillSoon(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	// 100d old with 90d policy → 10d past due — a 7d window should
	// still catch it because "due within 7d" semantically includes
	// "already overdue".
	e := &store.Entry{
		RotateAfter: "90d",
		RotatedAt:   now.Add(-100 * 24 * time.Hour),
	}
	soon, dueIn := DueWithin(e, now, 7*24*time.Hour)
	if !soon {
		t.Fatalf("expected dueSoon=true for already-overdue entry")
	}
	if dueIn > 0 {
		t.Errorf("dueIn should be negative (past due), got %v", dueIn)
	}
}

func TestDueWithinNoPolicyOrHistory(t *testing.T) {
	now := time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		e    *store.Entry
	}{
		{"nil", nil},
		{"no policy", &store.Entry{RotatedAt: now.Add(-1000 * 24 * time.Hour)}},
		{"policy but no history", &store.Entry{RotateAfter: "90d"}},
		{"unparseable policy", &store.Entry{RotateAfter: "zzz", RotatedAt: now}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			soon, _ := DueWithin(tc.e, now, 7*24*time.Hour)
			if soon {
				t.Errorf("expected dueSoon=false")
			}
		})
	}
}
