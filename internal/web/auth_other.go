//go:build !darwin

package web

import "context"

// requireTouchIDFunc mirrors the darwin variant so tests can still swap
// in a stub regardless of the build platform.
var requireTouchIDFunc = defaultRequireTouchID

// defaultRequireTouchID is a no-op on non-darwin platforms. The web UI
// on Linux/Windows is intended for local development only — it still
// binds to 127.0.0.1 via the existing loopback middleware, but there is
// no Secure Enclave to gate it with. This is documented behaviour.
func defaultRequireTouchID(_ context.Context) error { return nil }

// requireTouchID is the package-level entry point.
func requireTouchID(ctx context.Context) error {
	return requireTouchIDFunc(ctx)
}
