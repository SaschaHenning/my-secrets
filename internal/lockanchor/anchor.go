// Package lockanchor provides one process-wide administrative lock shared by
// every compliant mys process.
package lockanchor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type leaseContextKey struct{}

type leaseState struct {
	mu     sync.Mutex
	active bool
	nested int
	ready  *sync.Cond
}

type metadata struct {
	anchorUID        int
	parentUID        int
	effectiveUID     int
	anchorMode       os.FileMode
	parentMode       os.FileMode
	parentWritable   bool
	parentWriteKnown bool
}

const (
	linuxNFSSuperMagic  = uint64(0x6969)
	linuxCIFSSuperMagic = uint64(0xff534d42)
	linuxSMB2SuperMagic = uint64(0xfe534d42)
)

// Acquire takes an exclusive cross-process lock on a stable operating-system
// home-directory inode. A nil context is treated as context.Background.
// The returned release function is idempotent.
func Acquire(ctx context.Context) (func() error, error) {
	_, release, err := AcquireContext(ctx)
	return release, err
}

// AcquireContext is Acquire plus an explicit capability context. Passing the
// returned context to a nested Acquire call reuses this one active lease. A
// caller without that exact context still waits for the kernel lock.
func AcquireContext(
	ctx context.Context,
) (context.Context, func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, waitError(err)
	}
	if inherited := leaseFromContext(ctx); inherited != nil {
		if nestedRelease, acquired := inherited.acquireNested(); acquired {
			return ctx, nestedRelease, nil
		}
	}

	anchor, canonicalPath, err := openAnchor()
	if err != nil {
		return nil, nil, fmt.Errorf("open stable lock anchor: %w", err)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		acquired, lockErr := tryLock(anchor)
		if lockErr != nil {
			return nil, nil, errors.Join(
				fmt.Errorf("acquire stable lock anchor: %w", lockErr),
				anchor.Close(),
			)
		}
		if acquired {
			if err := validateLockedAnchor(anchor, canonicalPath); err != nil {
				return nil, nil, errors.Join(
					fmt.Errorf("validate stable lock anchor: %w", err),
					closeLockedAnchor(anchor),
				)
			}
			lease := newLeaseState()
			lockedContext := context.WithValue(
				ctx,
				leaseContextKey{},
				lease,
			)
			return lockedContext, releaseOnce(anchor, lease), nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, errors.Join(
				waitError(ctx.Err()),
				anchor.Close(),
			)
		case <-ticker.C:
		}
	}
}

func leaseFromContext(ctx context.Context) *leaseState {
	if ctx == nil {
		return nil
	}
	lease, _ := ctx.Value(leaseContextKey{}).(*leaseState)
	return lease
}

func newLeaseState() *leaseState {
	lease := &leaseState{active: true}
	lease.ready = sync.NewCond(&lease.mu)
	return lease
}

func (lease *leaseState) acquireNested() (func() error, bool) {
	if lease == nil {
		return nil, false
	}
	lease.mu.Lock()
	if !lease.active {
		lease.mu.Unlock()
		return nil, false
	}
	lease.nested++
	lease.mu.Unlock()

	var once sync.Once
	return func() error {
		once.Do(func() {
			lease.mu.Lock()
			lease.nested--
			if lease.nested == 0 {
				lease.ready.Broadcast()
			}
			lease.mu.Unlock()
		})
		return nil
	}, true
}

func (lease *leaseState) deactivateAndWait() {
	lease.mu.Lock()
	lease.active = false
	for lease.nested > 0 {
		lease.ready.Wait()
	}
	lease.mu.Unlock()
}

func validateMetadata(value metadata) error {
	if !value.anchorMode.IsDir() {
		return errors.New("stable lock anchor must be a directory")
	}
	if value.anchorUID != value.effectiveUID {
		return fmt.Errorf(
			"stable lock anchor owner %d does not match effective user %d",
			value.anchorUID,
			value.effectiveUID,
		)
	}
	if permissions := value.anchorMode.Perm(); permissions&0o022 != 0 {
		return fmt.Errorf(
			"stable lock anchor permissions %#o are insecure",
			permissions,
		)
	}
	if !value.parentMode.IsDir() {
		return errors.New("stable lock anchor parent must be a directory")
	}
	if permissions := value.parentMode.Perm(); permissions&0o022 != 0 {
		return fmt.Errorf(
			"stable lock anchor parent permissions %#o are insecure",
			permissions,
		)
	}
	if value.effectiveUID != 0 && value.parentUID == value.effectiveUID {
		return errors.New(
			"stable lock anchor parent is owned by the effective user",
		)
	}
	if !value.parentWriteKnown {
		return errors.New("stable lock anchor parent writability is unknown")
	}
	if value.effectiveUID != 0 && value.parentWritable {
		return errors.New(
			"stable lock anchor parent is writable by the effective user",
		)
	}
	return nil
}

func rejectKnownLinuxNetworkFilesystem(filesystemType uint64) error {
	switch filesystemType {
	case linuxNFSSuperMagic:
		return errors.New("NFS home directories cannot be lock anchors")
	case linuxCIFSSuperMagic, linuxSMB2SuperMagic:
		return errors.New("CIFS/SMB home directories cannot be lock anchors")
	default:
		return nil
	}
}

func waitError(err error) error {
	return fmt.Errorf("wait for stable lock anchor: %w", err)
}

func releaseOnce(anchor *os.File, lease *leaseState) func() error {
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			lease.deactivateAndWait()
			releaseErr = closeLockedAnchor(anchor)
		})
		return releaseErr
	}
}

func closeLockedAnchor(anchor *os.File) error {
	return errors.Join(unlock(anchor), anchor.Close())
}
