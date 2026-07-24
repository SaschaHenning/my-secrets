package sync

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireMountLockSerializesAndReleases(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	release, err := AcquireMountLock(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = AcquireMountLock(ctx, "jasp")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock error = %v, want deadline exceeded", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}

	releaseAgain, err := AcquireMountLock(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := releaseAgain(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestConfigLockSerializesLastSyncMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.yaml")
	release, err := acquireConfigLock(context.Background(), path)
	if err != nil {
		t.Fatalf("first config lock: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = MarkSharedSyncedAndSave(
		ctx, path, "jasp-shared", time.Now(),
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("merge error = %v, want deadline exceeded", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release config lock: %v", err)
	}
}
