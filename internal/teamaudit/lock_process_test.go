package teamaudit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAuditLockCoordinatesAcrossProcesses(t *testing.T) {
	if !supportsProcessFileLock(runtime.GOOS) {
		t.Skip("process file locking is unavailable on this platform")
	}

	root := t.TempDir()
	lockPath := filepath.Join(root, "operation.lock")
	readyPath := filepath.Join(root, "child.ready")
	exitPath := filepath.Join(root, "child.exit")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestAuditLockProcessHelper$",
	)
	command.Env = append(
		os.Environ(),
		"MYS_TEAM_AUDIT_LOCK_HELPER=1",
		"MYS_TEAM_AUDIT_LOCK_PATH="+lockPath,
		"MYS_TEAM_AUDIT_LOCK_READY="+readyPath,
		"MYS_TEAM_AUDIT_LOCK_EXIT="+exitPath,
	)
	output := new(strings.Builder)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start lock helper: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})
	waitForTestPath(t, readyPath, 5*time.Second)

	waitStarted := time.Now()
	timeoutContext, cancelTimeout := context.WithTimeout(
		context.Background(),
		150*time.Millisecond,
	)
	_, err := acquireAuditFileLock(
		timeoutContext,
		lockPath,
		"cross-process test",
	)
	cancelTimeout()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait timeout error = %v", err)
	}
	if elapsed := time.Since(waitStarted); elapsed < 100*time.Millisecond {
		t.Fatalf("lock wait returned too early after %s", elapsed)
	}

	acquired := make(chan error, 1)
	go func() {
		waitContext, cancelWait := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancelWait()
		release, acquireErr := acquireAuditFileLock(
			waitContext,
			lockPath,
			"cross-process test",
		)
		if acquireErr == nil {
			acquireErr = release()
		}
		acquired <- acquireErr
	}()
	select {
	case err := <-acquired:
		t.Fatalf("lock acquired before child exit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(exitPath, []byte("exit\n"), 0o600); err != nil {
		t.Fatalf("signal lock helper: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("wait for lock helper: %v: %s", err, output.String())
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("acquire lock after child exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock was not released after child process ended")
	}
}

func TestAuditLockProcessHelper(t *testing.T) {
	if os.Getenv("MYS_TEAM_AUDIT_LOCK_HELPER") != "1" {
		return
	}
	lockPath := os.Getenv("MYS_TEAM_AUDIT_LOCK_PATH")
	readyPath := os.Getenv("MYS_TEAM_AUDIT_LOCK_READY")
	exitPath := os.Getenv("MYS_TEAM_AUDIT_LOCK_EXIT")
	release, err := acquireAuditFileLock(
		context.Background(),
		lockPath,
		"helper process",
	)
	if err != nil {
		t.Fatalf("helper acquire: %v", err)
	}
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("helper ready: %v", err)
	}
	waitForTestPath(t, exitPath, 5*time.Second)
	runtime.KeepAlive(release)
}

func waitForTestPath(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("wait for %s: %v", filepath.Base(path), err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", filepath.Base(path))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func supportsProcessFileLock(goos string) bool {
	switch goos {
	case "aix", "darwin", "dragonfly", "freebsd", "linux",
		"netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}
