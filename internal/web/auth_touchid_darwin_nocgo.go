//go:build darwin && !cgo

package web

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// defaultRequireTouchID (no-cgo fallback) acquires a short-lived
// authorization for the system.privilege.admin right via
// `/usr/bin/security authorize -u`. IMPORTANT: on a default macOS this
// right's rule is class=user with no biometric mechanism, so it presents
// the account-PASSWORD dialog, not a Touch ID sheet — real Touch ID needs
// the LocalAuthentication framework, which requires cgo (see the cgo
// sibling). This path exists only so a CGO_ENABLED=0 darwin build still
// compiles and can authenticate at all.
func defaultRequireTouchID(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(callCtx, "/usr/bin/security",
		"authorize", "-u", "system.privilege.admin")
	if err := cmd.Run(); err != nil {
		if callCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("authorization prompt timed out")
		}
		return fmt.Errorf("authorization failed: %w", err)
	}
	return nil
}
