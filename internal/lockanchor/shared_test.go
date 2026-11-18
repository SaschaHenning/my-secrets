package lockanchor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func isolateHolders(t *testing.T) *bytes.Buffer {
	t.Helper()
	dir := t.TempDir()
	notice := &bytes.Buffer{}
	previousDir, previousOutput, previousDelay := holderDir, noticeOutput, waitNoticeDelay
	holderDir = func() string { return dir }
	noticeOutput = notice
	waitNoticeDelay = 20 * time.Millisecond
	t.Cleanup(func() {
		holderDir, noticeOutput, waitNoticeDelay = previousDir, previousOutput, previousDelay
	})
	return notice
}

func TestSharedLeasesCoexistAndExcludeExclusive(t *testing.T) {
	isolateHolders(t)
	first, err := AcquireShared(context.Background())
	if err != nil {
		t.Fatalf("first shared lease: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := AcquireShared(ctx)
	if err != nil {
		_ = first()
		t.Fatalf("second shared lease blocked behind the first: %v", err)
	}

	exclusiveCtx, cancelExclusive := context.WithTimeout(
		context.Background(), 100*time.Millisecond,
	)
	defer cancelExclusive()
	if release, err := Acquire(exclusiveCtx); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			_ = release()
		}
		t.Fatalf("exclusive lease beside shared holders: err = %v", err)
	}
	if err := errors.Join(first(), second()); err != nil {
		t.Fatalf("release shared leases: %v", err)
	}

	exclusive, err := Acquire(context.Background())
	if err != nil {
		t.Fatalf("exclusive after shared release: %v", err)
	}
	sharedCtx, cancelShared := context.WithTimeout(
		context.Background(), 100*time.Millisecond,
	)
	defer cancelShared()
	if release, err := AcquireShared(sharedCtx); !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			_ = release()
		}
		t.Fatalf("shared lease beside exclusive holder: err = %v", err)
	}
	if err := exclusive(); err != nil {
		t.Fatalf("release exclusive: %v", err)
	}
}

func TestNestedLeaseModes(t *testing.T) {
	isolateHolders(t)
	sharedCtx, release, err := AcquireSharedContext(context.Background())
	if err != nil {
		t.Fatalf("shared lease: %v", err)
	}
	if nested, err := Acquire(sharedCtx); !errors.Is(err, ErrSharedLeaseUpgrade) {
		if nested != nil {
			_ = nested()
		}
		_ = release()
		t.Fatalf("exclusive under shared lease: err = %v", err)
	}
	nestedShared, err := AcquireShared(sharedCtx)
	if err != nil {
		_ = release()
		t.Fatalf("shared under shared lease: %v", err)
	}
	if err := errors.Join(nestedShared(), release()); err != nil {
		t.Fatalf("release: %v", err)
	}

	exclusiveCtx, releaseExclusive, err := AcquireContext(context.Background())
	if err != nil {
		t.Fatalf("exclusive lease: %v", err)
	}
	nested, err := AcquireShared(exclusiveCtx)
	if err != nil {
		_ = releaseExclusive()
		t.Fatalf("shared under exclusive lease: %v", err)
	}
	if err := errors.Join(nested(), releaseExclusive()); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func TestWaitNamesHolderAndTimesOut(t *testing.T) {
	notice := isolateHolders(t)
	t.Setenv(WaitTimeoutEnv, "300ms")
	release, err := Acquire(context.Background())
	if err != nil {
		t.Fatalf("holder lease: %v", err)
	}
	defer func() { _ = release() }()

	started := time.Now()
	waiter, err := AcquireShared(context.Background())
	elapsed := time.Since(started)
	if waiter != nil {
		_ = waiter()
		t.Fatal("waiter acquired a held lock")
	}
	if !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("wait error = %v, want ErrWaitTimeout", err)
	}
	if elapsed < 300*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("wait took %s, want about 300ms", elapsed)
	}
	pid := strconv.Itoa(os.Getpid())
	if !strings.Contains(err.Error(), "held by PID "+pid) {
		t.Fatalf("timeout error does not name holder %s: %v", pid, err)
	}
	if !strings.Contains(notice.String(), "gehalten von PID "+pid) {
		t.Fatalf("wait notice = %q, want holder PID %s", notice.String(), pid)
	}
}

func TestReleaseRemovesHolderRecord(t *testing.T) {
	isolateHolders(t)
	release, err := Acquire(context.Background())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if got := holders(); len(got) != 1 || got[0] != os.Getpid() {
		_ = release()
		t.Fatalf("holders while held = %v", got)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := holders(); len(got) != 0 {
		t.Fatalf("holders after release = %v", got)
	}
}

func TestWaitTimeoutEnvFallsBackOnInvalidValue(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"":      defaultWaitTimeout,
		"bogus": defaultWaitTimeout,
		"-1s":   defaultWaitTimeout,
		"45s":   45 * time.Second,
	} {
		t.Setenv(WaitTimeoutEnv, value)
		if got := waitTimeout(); got != want {
			t.Errorf("waitTimeout(%q) = %s, want %s", value, got, want)
		}
	}
}
