// Rotation-overdue check — counts entries whose rotate_after horizon has
// elapsed since the last rotated_at timestamp and surfaces the count as
// a WARN. The check never prints individual paths: doctor output stays
// compact, and a high count in a large store would otherwise dominate
// the report.
//
// The check needs to decrypt every entry to read its rotate_after and
// rotated_at headers. On machines where gpg is locked or the store has
// not been initialised, decryption fails — we report a WARN with the
// message "store cannot be enumerated without gpg" rather than a FAIL,
// so the rest of `mys doctor` keeps running.

package doctor

import (
	"context"
	"fmt"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/rotation"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// RotationEntriesProvider is the narrow interface the rotation-overdue
// check needs. It returns every entry in the store (already decrypted,
// with RotateAfter / RotatedAt populated) or an error explaining why
// enumeration is not currently possible.
//
// The default implementation opens the real gopass store; tests inject
// a stub so they never touch gpg.
type RotationEntriesProvider interface {
	Entries(ctx context.Context) ([]*store.Entry, error)
}

// rotationProvider is the package-level hook CheckRotationOverdue calls
// into. Tests overwrite it via SetRotationProvider(); production code
// leaves it at the default implementation.
var rotationProvider RotationEntriesProvider = defaultRotationProvider{}

// rotationNow is the "now" source for the rotation-overdue check. Tests
// override it to pin time for deterministic assertions; production code
// uses time.Now().
var rotationNow = func() time.Time { return time.Now().UTC() }

// SetRotationProvider swaps in a different entry source. Passing nil
// restores the default. Returns the previous provider so the caller can
// restore it in a cleanup hook.
func SetRotationProvider(p RotationEntriesProvider) RotationEntriesProvider {
	prev := rotationProvider
	if p == nil {
		rotationProvider = defaultRotationProvider{}
	} else {
		rotationProvider = p
	}
	return prev
}

// SetRotationNow overrides the "now" function used by the rotation
// check. Passing nil restores the default (time.Now().UTC()). Returns
// the previous function so the caller can restore it in cleanup.
func SetRotationNow(fn func() time.Time) func() time.Time {
	prev := rotationNow
	if fn == nil {
		rotationNow = func() time.Time { return time.Now().UTC() }
	} else {
		rotationNow = fn
	}
	return prev
}

// defaultRotationProvider opens the real gopass store and decrypts every
// entry. Any gpg error (locked keyring, missing store, agent unreachable)
// is surfaced verbatim; the check wraps it into a WARN with a
// gpg-independent explanation so other checks keep running.
type defaultRotationProvider struct{}

func (defaultRotationProvider) Entries(ctx context.Context) ([]*store.Entry, error) {
	st, err := store.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close(ctx) }()
	paths, err := st.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list store: %w", err)
	}
	out := make([]*store.Entry, 0, len(paths))
	for _, p := range paths {
		e, gerr := st.Get(ctx, p)
		if gerr != nil {
			// Abort enumeration on the first decrypt failure: a partial
			// count would be misleading. The caller converts this into
			// a WARN.
			return nil, fmt.Errorf("decrypt %s: %w", p, gerr)
		}
		out = append(out, e)
	}
	return out, nil
}

// CheckRotationOverdue — check #11: count entries past their rotation
// horizon and flag a WARN when any exist. Never returns FAIL: missing
// rotations are a nudge, not a blocker.
func CheckRotationOverdue(ctx context.Context) Check {
	c := Check{ID: "rotation-overdue", Label: "rotation reminders"}
	entries, err := rotationProvider.Entries(ctx)
	if err != nil {
		c.Status = StatusWarn
		c.Message = "store cannot be enumerated without gpg"
		c.Remedy = "unlock the gpg keyring or run `gpg --list-secret-keys`"
		return c
	}
	now := rotationNow()
	stale := 0
	policyOnly := 0
	for _, e := range entries {
		if s, _ := rotation.IsStale(e, now); s {
			stale++
			continue
		}
		if rotation.PolicyWithoutHistory(e) {
			policyOnly++
		}
	}
	switch {
	case stale == 0 && policyOnly == 0:
		c.Status = StatusPass
		c.Message = fmt.Sprintf("no stale entries (%d entrie(s) checked)", len(entries))
	case stale == 0 && policyOnly > 0:
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("%d entrie(s) have a rotation policy but no rotation history", policyOnly)
		c.Remedy = "run `mys rotate <path>` to stamp a rotation timestamp"
	default:
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("%d stale entrie(s) past their rotate_after horizon", stale)
		if policyOnly > 0 {
			c.Message += fmt.Sprintf(" (%d more have a policy but no rotation history)", policyOnly)
		}
		c.Remedy = "run `mys ls --stale` to list them, then `mys rotate <path>` each"
	}
	return c
}
