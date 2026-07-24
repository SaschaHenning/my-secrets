package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
)

// AcquireMountLock serializes local administrative mutations of a gopass
// mount across mys processes. The returned release function is idempotent.
func AcquireMountLock(ctx context.Context, mount string) (func() error, error) {
	_, release, err := AcquireMountLockContext(ctx, mount)
	return release, err
}

// AcquireMountLockContext is AcquireMountLock plus the explicit lease context
// required by nested config writes in the same administrative operation.
func AcquireMountLockContext(
	ctx context.Context,
	mount string,
) (context.Context, func() error, error) {
	label := mountLabel(mount)
	if strings.ContainsAny(label, `/\`+"\x00\r\n") {
		return nil, nil, fmt.Errorf("invalid mount lock name %q", label)
	}
	return acquireAnchorLockContext(
		ctx,
		fmt.Sprintf("mount %q", label),
	)
}

func acquireConfigLock(
	ctx context.Context,
	_ string,
) (func() error, error) {
	return acquireAnchorLock(ctx, "sync config")
}

func acquireAnchorLock(
	ctx context.Context,
	label string,
) (func() error, error) {
	_, release, err := acquireAnchorLockContext(ctx, label)
	return release, err
}

func acquireAnchorLockContext(
	ctx context.Context,
	label string,
) (context.Context, func() error, error) {
	lockedContext, release, err := lockanchor.AcquireContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("acquire %s lock: %w", label, err)
	}
	return lockedContext, release, nil
}
