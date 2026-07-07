package bw

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AcquireLock takes an exclusive, non-blocking flock on path (creating
// parent dir and file as needed) and returns a release func. Two
// concurrent bw-push runs would plan against the same remote snapshot
// and both create folders/items — the lock turns the second run into an
// immediate, explicit error instead.
func AcquireLock(path string) (func(), error) {
	if path == "" {
		cfgPath, err := DefaultConfigPath()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(filepath.Dir(cfgPath), "bw-push.lock")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another bw-push is already running (lock %s held)", path)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
