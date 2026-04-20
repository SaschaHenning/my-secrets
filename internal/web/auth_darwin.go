//go:build darwin

package web

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// requireTouchIDFunc is the indirection the HTTP handlers use. Tests can
// replace it with a no-op stub so CI never has to hit the real
// Authorization Services dialog.
var requireTouchIDFunc = defaultRequireTouchID

// defaultRequireTouchID triggers the macOS Authorization Services prompt,
// which — on systems with Touch ID configured and the appropriate
// mechanism policy (/etc/pam.d/sudo & friends, or the default admin
// right on modern macOS) — surfaces as a Touch ID sheet. The user can
// also fall back to entering their account password.
//
// Implementation: we acquire a short-lived authorization for the
// "system.privilege.admin" right via /usr/bin/security authorize -u.
// That is the same right that `sudo`, Keychain Access and similar UI
// tools request, and on recent macOS releases its policy is
// "authenticate-admin-nonshared" — which LocalAuthentication fulfils via
// Touch ID when available.
//
// Rationale / alternatives considered:
//   - `security execute-with-privileges` also triggers Authorization
//     Services but requires an actual helper binary and keeps the auth
//     scoped to that child process; overkill for a login gate.
//   - `osascript -e 'do shell script "true" with administrator
//     privileges'` works too and honours Touch ID, but it routes through
//     AppleEvents and the Script Editor entitlement path, which is
//     noisier in the security log and less direct.
//
// The `security authorize -u` path is the smallest, most auditable
// invocation that reliably triggers the Touch ID sheet.
func defaultRequireTouchID(ctx context.Context) error {
	// Guard with an explicit 30s timeout so a user who dismisses the
	// sheet (or never sees it) does not block the HTTP handler.
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(callCtx, "/usr/bin/security",
		"authorize",
		"-u", // allow user interaction (Touch ID / password sheet)
		"system.privilege.admin",
	)
	// We never read output; `security authorize` writes "YES (0)" on
	// success and a non-zero exit otherwise.
	if err := cmd.Run(); err != nil {
		if callCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("touch-id prompt timed out")
		}
		return fmt.Errorf("touch-id authorization failed: %w", err)
	}
	return nil
}

// requireTouchID is the package-level entry point.
func requireTouchID(ctx context.Context) error {
	return requireTouchIDFunc(ctx)
}
