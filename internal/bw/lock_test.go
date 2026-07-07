package bw

import (
	"path/filepath"
	"testing"
)

func TestAcquireLock_SecondAcquireFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.lock")
	release, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("second acquire must fail while the lock is held")
	}
	release()
	release2, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	release2()
}
