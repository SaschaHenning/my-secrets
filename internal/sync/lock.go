package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AcquireMountLock serializes local administrative mutations of a gopass
// mount across mys processes. The returned release function is idempotent.
func AcquireMountLock(ctx context.Context, mount string) (func() error, error) {
	label := mountLabel(mount)
	if strings.ContainsAny(label, `/\`+"\x00\r\n") {
		return nil, fmt.Errorf("invalid mount lock name %q", label)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("resolve config directory for mount lock: %w", err)
	}
	lockDir := filepath.Join(configDir, "my-secrets", "locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("create mount lock directory: %w", err)
	}
	return acquireFileLock(
		ctx,
		filepath.Join(lockDir, label+".lock"),
		fmt.Sprintf("mount %q", label),
	)
}

func acquireConfigLock(
	ctx context.Context,
	configPath string,
) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return nil, fmt.Errorf("create sync config lock directory: %w", err)
	}
	return acquireFileLock(ctx, configPath+".lock", "sync config")
}

func acquireFileLock(
	ctx context.Context,
	lockPath string,
	label string,
) (func() error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s lock: %w", label, err)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		acquired, lockErr := tryLockFile(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("acquire %s lock: %w", label, lockErr)
		}
		if acquired {
			var once sync.Once
			var releaseErr error
			return func() error {
				once.Do(func() {
					if err := unlockFile(file); err != nil {
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
