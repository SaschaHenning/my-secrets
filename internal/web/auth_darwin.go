//go:build darwin

package web

import "context"

// requireTouchIDFunc is the indirection the HTTP login handler uses. Tests
// replace it with a no-op stub so CI never has to hit a real biometric /
// authorization dialog.
//
// The platform implementation of defaultRequireTouchID is provided by one
// of two build-tagged siblings:
//
//   - auth_touchid_darwin_cgo.go   (darwin && cgo): real Touch ID via the
//     LocalAuthentication framework (LAContext, deviceOwnerAuthentication —
//     Touch ID with automatic password fallback). This is what a normal
//     `make build`/`go build` on macOS produces, since cgo is on by default.
//   - auth_touchid_darwin_nocgo.go (darwin && !cgo): the older
//     `security authorize` path, kept so a CGO_ENABLED=0 darwin build (or a
//     cross-build) still compiles. It shows the account-password dialog, not
//     a biometric sheet.
var requireTouchIDFunc = defaultRequireTouchID

// requireTouchID is the package-level entry point used by the login
// handler. (Reveal is session-only and does not call this — see
// handleReveal.)
func requireTouchID(ctx context.Context) error {
	return requireTouchIDFunc(ctx)
}
