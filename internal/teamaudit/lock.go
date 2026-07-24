package teamaudit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func acquireAuditLock(
	ctx context.Context,
	stateDir string,
) (func() error, error) {
	return acquireAuditFileLock(
		ctx,
		filepath.Join(stateDir, "operation.lock"),
		"team audit operation",
	)
}

func acquireAuditFileLock(
	ctx context.Context,
	path string,
	label string,
) (func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("create %s lock directory: %w", label, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s lock: %w", label, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure %s lock: %w", label, err)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		acquired, lockErr := tryAuditFileLock(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire %s lock: %w", label, lockErr)
		}
		if acquired {
			var (
				once       sync.Once
				releaseErr error
			)
			return func() error {
				once.Do(func() {
					if err := unlockAuditFile(file); err != nil {
						releaseErr = err
					}
					if err := file.Close(); releaseErr == nil {
						releaseErr = err
					}
				})
				return releaseErr
			}, nil
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, fmt.Errorf("wait for %s lock: %w", label, ctx.Err())
		case <-ticker.C:
		}
	}
}
