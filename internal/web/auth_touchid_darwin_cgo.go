//go:build darwin && cgo

package web

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#include <stdlib.h>
int mys_touchid_authenticate(const char *reason);
*/
import "C"

import (
	"context"
	"errors"
	"time"
	"unsafe"
)

// defaultRequireTouchID presents a real Touch ID sheet via macOS
// LocalAuthentication (LAContext, deviceOwnerAuthentication — biometrics
// with automatic password fallback), implemented in
// auth_touchid_darwin.m.
//
// The C call blocks on the OS sheet until the user responds, so it runs on
// a dedicated goroutine that is raced against ctx (the login handler caps
// this via the write budget). Cancelling ctx lets the handler return; the
// sheet itself is owned by the OS and is dismissed by the user.
//
// Caveat: LocalAuthentication requires the binary to be code-signed to
// present biometrics. The Go toolchain applies an ad-hoc signature, which
// is usually sufficient for deviceOwnerAuthentication, but on some
// setups/policies it can still fall back to the password sheet — that is a
// graceful degradation, not a failure.
func defaultRequireTouchID(ctx context.Context) error {
	// Cap the wait so a login handler never blocks indefinitely on a sheet
	// the user walked away from. LAContext auto-cancels its own sheet after
	// a while (signalling the semaphore, so the goroutine below unwinds),
	// but this bounds the handler regardless.
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	reason := C.CString("die my-secrets Weboberfläche zu entsperren")

	// Free `reason` INSIDE the goroutine, only after the C call fully
	// returns — never via a defer in this function. If ctx.Done() wins the
	// select below, this function returns while the C call may still be
	// running; freeing `reason` here (defer) would then be a use-after-free
	// the instant mys_touchid_authenticate reads it (stringWithUTF8String).
	// resultCh is buffered (1) so this send never blocks even when the
	// select already returned via ctx.Done() and nobody receives.
	resultCh := make(chan C.int, 1)
	go func() {
		code := C.mys_touchid_authenticate(reason)
		C.free(unsafe.Pointer(reason))
		resultCh <- code
	}()

	select {
	case code := <-resultCh:
		switch code {
		case 1:
			return nil
		case -1:
			return errors.New("device authentication unavailable (no Touch ID enrolled and no password set)")
		default:
			return errors.New("authentication cancelled or failed")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}
