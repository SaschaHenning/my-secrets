// Package rotation implements the rotation-reminder logic for my-secrets.
//
// The package is intentionally free of I/O: callers feed it a *store.Entry
// plus a "now" timestamp and receive a pure verdict. This keeps the
// behaviour trivially testable and independent of the gopass backend.
//
// Duration format accepted by ParseDuration:
//
//	Nd  — N days    (N*24h)
//	Nw  — N weeks   (N*7*24h)
//	Nm  — N months  (N*30*24h, a coarse calendar-month approximation)
//	Ny  — N years   (N*365*24h, ignores leap years)
//
// Month = 30 days and year = 365 days is intentional: rotation reminders
// are nudges, not compliance math, and a fuzzy approximation is good
// enough and far easier to reason about than time.AddDate.
package rotation

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

const (
	day   = 24 * time.Hour
	week  = 7 * day
	month = 30 * day
	year  = 365 * day
)

// ParseDuration parses a rotation-policy string such as "90d", "2w", "3m"
// or "1y" into a time.Duration. The numeric prefix must be a positive
// integer; empty strings, negative values, missing suffixes and unknown
// suffixes are rejected.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("rotation: empty duration")
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("rotation: %q too short — expected like 90d/2w/3m/1y", s)
	}
	unit := s[len(s)-1]
	numPart := s[:len(s)-1]
	// Reject explicit sign characters — we only accept positive durations.
	if strings.ContainsAny(numPart, "+-") {
		return 0, fmt.Errorf("rotation: %q must be a positive integer with a unit suffix", s)
	}
	n, err := strconv.Atoi(numPart)
	if err != nil {
		// Hide the internal strconv error from the user — they typed a
		// duration, they should see a duration-shaped error.
		return 0, fmt.Errorf("rotation: %q is not a valid duration — expected Nd / Nw / Nm / Ny (e.g. 30d, 2w, 3m, 1y)", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("rotation: %q must be positive", s)
	}
	var mult time.Duration
	switch unit {
	case 'd':
		mult = day
	case 'w':
		mult = week
	case 'm':
		mult = month
	case 'y':
		mult = year
	default:
		return 0, fmt.Errorf("rotation: unknown unit %q in %q (want d/w/m/y)", string(unit), s)
	}
	return time.Duration(n) * mult, nil
}

// IsStale reports whether the entry is past its rotation horizon and, if
// so, by how much. Returns (false, 0) in any of these cases:
//
//   - e is nil
//   - e.RotateAfter is empty (rotation not configured — opt-in)
//   - e.RotateAfter fails to parse (treated as no policy; callers can
//     independently inspect the string and surface a validation error)
//   - e.RotatedAt is the zero value (no rotation history yet — see
//     PolicyWithoutHistory for that orthogonal condition)
//
// When stale, overdue is now - (rotated_at + rotate_after).
func IsStale(e *store.Entry, now time.Time) (stale bool, overdue time.Duration) {
	if e == nil || e.RotateAfter == "" {
		return false, 0
	}
	d, err := ParseDuration(e.RotateAfter)
	if err != nil {
		return false, 0
	}
	if e.RotatedAt.IsZero() {
		return false, 0
	}
	due := e.RotatedAt.Add(d)
	if now.After(due) {
		return true, now.Sub(due)
	}
	return false, 0
}

// PolicyWithoutHistory reports whether the entry has a rotation policy
// configured but no rotation-history timestamp yet. This is a gentler
// warning state than "stale": the user asked for reminders, but the tool
// has no basis to decide whether the secret is actually old.
func PolicyWithoutHistory(e *store.Entry) bool {
	if e == nil {
		return false
	}
	return e.RotateAfter != "" && e.RotatedAt.IsZero()
}

// DueWithin reports whether the entry will fall due within the given
// window from now. Returns (false, 0) when no policy is set, the policy
// is unparseable, or there is no rotation history. When the entry is
// already past due the call still returns true with a negative dueIn
// (i.e. the time since the due date).
//
// Callers who want to distinguish "past due" from "due soon" should use
// IsStale + DueWithin together:
//
//	stale, _ := rotation.IsStale(e, now)
//	soon, dueIn := rotation.DueWithin(e, now, 7*24*time.Hour)
//	switch {
//	case stale: ...
//	case soon:  ...
//	}
func DueWithin(e *store.Entry, now time.Time, window time.Duration) (dueSoon bool, dueIn time.Duration) {
	if e == nil || e.RotateAfter == "" {
		return false, 0
	}
	d, err := ParseDuration(e.RotateAfter)
	if err != nil {
		return false, 0
	}
	if e.RotatedAt.IsZero() {
		return false, 0
	}
	due := e.RotatedAt.Add(d)
	remaining := due.Sub(now)
	// Past due counts as "due within" — a window cannot exclude an entry
	// that is already overdue.
	if remaining <= window {
		return true, remaining
	}
	return false, remaining
}
