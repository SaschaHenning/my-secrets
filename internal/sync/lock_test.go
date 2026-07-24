package sync

import (
	"context"
	"errors"
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
