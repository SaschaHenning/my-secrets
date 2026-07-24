package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	sharedPolicyHelperModeEnv    = "MYS_TEST_SHARED_POLICY_MODE"
	sharedPolicyHelperMountEnv   = "MYS_TEST_SHARED_POLICY_MOUNT"
	sharedPolicyHelperAttemptEnv = "MYS_TEST_SHARED_POLICY_ATTEMPT"
	sharedPolicyHelperReadyEnv   = "MYS_TEST_SHARED_POLICY_READY"
	sharedPolicyHelperReleaseEnv = "MYS_TEST_SHARED_POLICY_RELEASE"
)

func TestSharedPathRejectsUnsafeMounts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tests := []string{
		"",
		".",
		"..",
		"../team",
		"team/other",
		"/tmp/team",
		`team\other`,
		" team",
		"team ",
		"tëam",
		"team\nother",
		"root",
	}
	for _, mount := range tests {
		t.Run(mount, func(t *testing.T) {
			if _, err := SharedPath(mount); err == nil {
				t.Fatalf("SharedPath(%q) unexpectedly succeeded", mount)
			}
		})
	}
}

func TestSharedPathUsesMountSpecificConfigFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := SharedPath("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(
		home,
		".config",
		"my-secrets",
		"shared-policies",
		"jasp-shared.yaml",
	)
	if got != want {
		t.Fatalf("SharedPath = %q, want %q", got, want)
	}
}

func TestLoadSharedMissingFailsClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if _, _, _, err := LoadShared("jasp-shared"); err == nil {
		t.Fatal("missing shared policy must fail closed")
	}
}

func TestBeginSharedDefaultIgnoresUntrustedLegacyLockFiles(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "symbolic link",
			setup: func(t *testing.T, lockPath string) {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, lockPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "insecure permissions",
			setup: func(t *testing.T, lockPath string) {
				if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(lockPath, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			policyPath, err := SharedPath("jasp-shared")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
				t.Fatal(err)
			}
			test.setup(t, policyPath+".lock")

			transaction, err := BeginSharedDefault("jasp-shared")
			if err != nil {
				t.Fatalf("legacy lock path affected stable anchor: %v", err)
			}
			if err := transaction.Commit(); err != nil {
				t.Fatalf("commit shared policy: %v", err)
			}
		})
	}
}

func TestAcquireSharedPolicyLockNilContextAndIdempotentRelease(t *testing.T) {
	release, err := acquireSharedPolicyLock(nil, "jasp-shared")
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("repeat release lock: %v", err)
	}
}

func TestEnsureSharedDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writtenPath, err := EnsureSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(writtenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("shared policy mode = %#o, want 0600", got)
	}
	raw, err := os.ReadFile(writtenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "version: 1\n") {
		t.Fatalf("shared policy lacks version 1:\n%s", raw)
	}

	pol, loadedPath, hash, err := LoadShared("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != writtenPath {
		t.Fatalf("loaded path = %q, want %q", loadedPath, writtenPath)
	}
	sum := sha256.Sum256(raw)
	if want := hex.EncodeToString(sum[:]); hash != want {
		t.Fatalf("hash = %q, want %q", hash, want)
	}
	for _, actor := range []struct {
		kind  string
		label string
	}{
		{kind: "human"},
		{kind: "script"},
		{kind: "ai"},
		{kind: "ai", label: "claude-code"},
	} {
		if decision := pol.Evaluate(actor.kind, actor.label, "jasp-shared/secret"); !decision.Allowed {
			t.Fatalf("%s/%s should be allowed inside mount: %v",
				actor.kind, actor.label, decision)
		}
		if decision := pol.Evaluate(actor.kind, actor.label, "other/secret"); decision.Allowed {
			t.Fatalf("%s/%s should be denied outside mount: %v",
				actor.kind, actor.label, decision)
		}
	}

	secondPath, err := EnsureSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(secondRaw) != string(raw) {
		t.Fatal("second ensure changed the existing policy")
	}
}

func TestBeginSharedDefaultAcceptsSymlinkedEnvironmentPaths(t *testing.T) {
	tests := []struct {
		name string
		home func(*testing.T) string
	}{
		{
			name: "home",
			home: func(t *testing.T) string {
				t.Helper()
				target := t.TempDir()
				link := filepath.Join(t.TempDir(), "home")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
		},
		{
			name: "config directory",
			home: func(t *testing.T) string {
				t.Helper()
				home := t.TempDir()
				if err := os.Symlink(
					t.TempDir(),
					filepath.Join(home, ".config"),
				); err != nil {
					t.Fatal(err)
				}
				return home
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", test.home(t))
			transaction, err := BeginSharedDefault("jasp-shared")
			if err != nil {
				t.Fatalf("begin with symlinked %s: %v", test.name, err)
			}
			if err := transaction.Commit(); err != nil {
				t.Fatalf("commit with symlinked %s: %v", test.name, err)
			}
			if _, _, _, err := LoadShared("jasp-shared"); err != nil {
				t.Fatalf("load with symlinked %s: %v", test.name, err)
			}
		})
	}
}

func TestEnsureSharedDefaultConcurrent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := EnsureSharedDefault("jasp-shared")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent ensure: %v", err)
		}
	}
	if _, _, _, err := LoadShared("jasp-shared"); err != nil {
		t.Fatalf("concurrent ensure left invalid policy: %v", err)
	}
}

func TestSharedDefaultTransactionRollbackRetainsCreatedPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	policyPath := transaction.Path()
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("created policy: %v", err)
	}

	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, _, _, err := LoadShared("jasp-shared"); err != nil {
		t.Fatalf("policy after rollback must remain valid: %v", err)
	}
	if _, err := os.Stat(policyPath); err != nil {
		t.Fatalf("retained policy after rollback: %v", err)
	}
}

func TestBeginSharedDefaultRejectsUnsafeMount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, err := BeginSharedDefault("../team"); err == nil {
		t.Fatal("unsafe mount unexpectedly accepted")
	}
}

func TestSharedDefaultTransactionRollbackNeverRestoresDeletedPolicy(
	t *testing.T,
) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(transaction.Path()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback deleted policy: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("repeat rollback: %v", err)
	}
	if _, err := os.Lstat(transaction.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback restored deleted policy: %v", err)
	}
}

func TestSharedDefaultTransactionCommitKeepsCreatedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback after commit: %v", err)
	}
	if _, _, _, err := LoadShared("jasp-shared"); err != nil {
		t.Fatalf("committed policy: %v", err)
	}
}

func TestSharedDefaultTransactionNeverChangesExistingPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	policyPath, err := EnsureSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	beforeData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatalf("rollback existing policy: %v", err)
	}
	afterData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterData, beforeData) {
		t.Fatal("existing policy bytes changed")
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("existing policy inode changed")
	}
}

func TestBeginSharedDefaultRejectsInvalidExistingPolicyWithoutChanging(
	t *testing.T,
) {
	t.Setenv("HOME", t.TempDir())
	invalid := []byte("version: 2\nactors: {}\n")
	policyPath := writeSharedPolicy(
		t,
		"jasp-shared",
		string(invalid),
		0o600,
	)
	beforeInfo, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BeginSharedDefault("jasp-shared"); err == nil {
		t.Fatal("invalid existing policy unexpectedly accepted")
	}
	afterData, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterData, invalid) {
		t.Fatal("invalid existing policy bytes changed")
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("invalid existing policy inode changed")
	}
}

func TestSharedDefaultTransactionCommitRejectsReplacementWithoutDeletingIt(
	t *testing.T,
) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("version: 1\nactors:\n  human:\n    allow:\n      - jasp-shared/**\n")
	replacementPath := filepath.Join(filepath.Dir(transaction.Path()), "replacement.yaml")
	if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, transaction.Path()); err != nil {
		t.Fatal(err)
	}

	err = transaction.Commit()
	if err == nil || !strings.Contains(err.Error(), "inode") {
		t.Fatalf("commit error = %v, want inode mismatch", err)
	}
	if repeated := transaction.Commit(); repeated == nil ||
		repeated.Error() != err.Error() {
		t.Fatalf("repeated commit error = %v, want %v", repeated, err)
	}
	got, readErr := os.ReadFile(transaction.Path())
	if readErr != nil {
		t.Fatalf("read replacement: %v", readErr)
	}
	if !bytes.Equal(got, replacement) {
		t.Fatalf("replacement changed: got %q, want %q", got, replacement)
	}
}

func TestSharedDefaultTransactionVerifyAndCommitRejectContentChange(
	t *testing.T,
) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("version: 1\nactors: {}\n")
	if err := os.WriteFile(transaction.Path(), replacement, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := transaction.Verify(); err == nil ||
		!strings.Contains(err.Error(), "contents") {
		t.Fatalf("verify error = %v, want contents mismatch", err)
	}
	err = transaction.Commit()
	if err == nil || !strings.Contains(err.Error(), "contents") {
		t.Fatalf("commit error = %v, want contents mismatch", err)
	}
	got, readErr := os.ReadFile(transaction.Path())
	if readErr != nil {
		t.Fatalf("read changed policy: %v", readErr)
	}
	if !bytes.Equal(got, replacement) {
		t.Fatalf("changed policy was not preserved: got %q", got)
	}
}

func TestSharedDefaultTransactionCommitRejectsDeletion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	transaction, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(transaction.Path()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		t.Fatalf("commit deleted policy error = %v, want not-exist", err)
	}
	if _, err := os.Lstat(transaction.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("commit restored deleted policy: %v", err)
	}
}

func TestReadBoundSharedPolicyRejectsPathReplacement(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	policyPath := writeSharedPolicy(
		t,
		"jasp-shared",
		"version: 1\nactors:\n  human:\n    allow: [\"jasp-shared/**\"]\n",
		0o600,
	)
	opened, err := os.Open(policyPath)
	if err != nil {
		t.Fatalf("open original policy: %v", err)
	}
	defer opened.Close()

	replacementPath := filepath.Join(filepath.Dir(policyPath), "replacement.yaml")
	if err := os.WriteFile(
		replacementPath,
		[]byte("version: 1\nactors: {}\n"),
		0o600,
	); err != nil {
		t.Fatalf("write replacement policy: %v", err)
	}
	if err := os.Rename(replacementPath, policyPath); err != nil {
		t.Fatalf("replace policy path: %v", err)
	}

	if _, err := readBoundSharedPolicyFile(
		policyPath,
		opened,
		nil,
	); err == nil || !strings.Contains(err.Error(), "opened file") {
		t.Fatalf("bound read error = %v, want opened-file mismatch", err)
	}
}

func TestReadSharedPolicySnapshotRejectsSymlinkBeforeFollowing(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.Symlink(
		filepath.Join(t.TempDir(), "missing-target.yaml"),
		policyPath,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := readSharedPolicySnapshot(
		policyPath,
		nil,
	); err == nil || !strings.Contains(err.Error(), "symbolic-link") {
		t.Fatalf("snapshot symlink error = %v, want symbolic-link rejection", err)
	}
}

func TestReadBoundSharedPolicyValidatesDescriptorAndPath(t *testing.T) {
	validBody := []byte("version: 1\nactors: {}\n")

	t.Run("empty path", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "policy")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := readBoundSharedPolicyFile("", file, nil); err == nil ||
			!strings.Contains(err.Error(), "path is empty") {
			t.Fatalf("empty-path error = %v", err)
		}
	})

	t.Run("nil descriptor", func(t *testing.T) {
		if _, err := readBoundSharedPolicyFile(
			"/config/policy.yaml",
			nil,
			nil,
		); err == nil || !strings.Contains(err.Error(), "file is nil") {
			t.Fatalf("nil-descriptor error = %v", err)
		}
	})

	t.Run("non regular descriptor", func(t *testing.T) {
		directory, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		if _, err := readBoundSharedPolicyFile(
			directory.Name(),
			directory,
			nil,
		); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("directory-descriptor error = %v", err)
		}
	})

	t.Run("insecure descriptor mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(path, validBody, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundSharedPolicyFile(path, file, nil); err == nil ||
			!strings.Contains(err.Error(), "permissions") {
			t.Fatalf("insecure-mode error = %v", err)
		}
	})

	t.Run("oversized descriptor", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(
			path,
			bytes.Repeat([]byte{'#'}, policyFileSizeLimit+1),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := readBoundSharedPolicyFile(path, file, nil); err == nil ||
			!strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversize error = %v", err)
		}
	})

	t.Run("unexpected descriptor inode", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "policy.yaml")
		otherPath := filepath.Join(directory, "other.yaml")
		if err := os.WriteFile(path, validBody, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(otherPath, validBody, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		otherInfo, err := os.Stat(otherPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundSharedPolicyFile(
			path,
			file,
			otherInfo,
		); err == nil || !strings.Contains(err.Error(), "inode") {
			t.Fatalf("unexpected-inode error = %v", err)
		}
	})

	t.Run("symbolic link path", func(t *testing.T) {
		directory := t.TempDir()
		targetPath := filepath.Join(directory, "target.yaml")
		linkPath := filepath.Join(directory, "policy.yaml")
		if err := os.WriteFile(targetPath, validBody, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(targetPath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundSharedPolicyFile(
			linkPath,
			file,
			nil,
		); err == nil || !strings.Contains(err.Error(), "symbolic-link") {
			t.Fatalf("symbolic-link error = %v", err)
		}
	})
}

func TestSharedPolicyTransactionHelperProcess(t *testing.T) {
	mode := os.Getenv(sharedPolicyHelperModeEnv)
	if mode == "" {
		return
	}
	mount := requireSharedPolicyHelperEnv(t, sharedPolicyHelperMountEnv)
	if mode == "timeout" {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			250*time.Millisecond,
		)
		defer cancel()
		writeSharedPolicyHelperSignal(
			t,
			requireSharedPolicyHelperEnv(t, sharedPolicyHelperAttemptEnv),
		)
		transaction, err := BeginSharedDefaultContext(ctx, mount)
		if transaction != nil {
			_ = transaction.Rollback()
			t.Fatal("shared policy waiter acquired while holder was active")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf(
				"shared policy waiter error = %v, want deadline exceeded",
				err,
			)
		}
		return
	}
	writeSharedPolicyHelperSignal(
		t,
		requireSharedPolicyHelperEnv(t, sharedPolicyHelperAttemptEnv),
	)
	transaction, err := BeginSharedDefaultContext(
		context.Background(),
		mount,
	)
	if err != nil {
		t.Fatalf("begin shared policy: %v", err)
	}
	writeSharedPolicyHelperSignal(
		t,
		requireSharedPolicyHelperEnv(t, sharedPolicyHelperReadyEnv),
	)
	waitForSharedPolicyHelperSignal(
		t,
		requireSharedPolicyHelperEnv(t, sharedPolicyHelperReleaseEnv),
	)
	switch mode {
	case "commit":
		if err := transaction.Commit(); err != nil {
			t.Fatalf("commit shared policy: %v", err)
		}
	case "abort":
		if err := transaction.Rollback(); err != nil {
			t.Fatalf("abort shared policy: %v", err)
		}
	default:
		t.Fatalf(
			"unknown shared policy helper mode %q",
			mode,
		)
	}
}

func TestSharedDefaultTransactionsSerializeAcrossProcesses(t *testing.T) {
	home := t.TempDir()
	firstAttempt := filepath.Join(home, "first-attempt")
	firstReady := filepath.Join(home, "first-ready")
	firstRelease := filepath.Join(home, "first-release")
	first := startSharedPolicyHelper(
		t,
		home,
		"abort",
		firstAttempt,
		firstReady,
		firstRelease,
	)
	waitForSharedPolicyHelperSignal(t, firstReady)

	secondAttempt := filepath.Join(home, "second-attempt")
	secondReady := filepath.Join(home, "second-ready")
	secondRelease := filepath.Join(home, "second-release")
	second := startSharedPolicyHelper(
		t,
		home,
		"timeout",
		secondAttempt,
		secondReady,
		secondRelease,
	)
	waitForSharedPolicyHelperSignal(t, secondAttempt)
	waitSharedPolicyHelper(t, second)

	writeSharedPolicyHelperSignal(t, firstRelease)
	waitSharedPolicyHelper(t, first)

	t.Setenv("HOME", home)
	postRelease, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatalf("begin shared policy after release: %v", err)
	}
	if err := postRelease.Commit(); err != nil {
		t.Fatalf("commit shared policy after release: %v", err)
	}
	if _, _, _, err := LoadShared("jasp-shared"); err != nil {
		t.Fatalf("serialized abort/adopt/commit left invalid policy: %v", err)
	}
}

func TestSharedDefaultTransactionsRemainSerializedAfterPathReplacement(
	t *testing.T,
) {
	tests := []struct {
		name    string
		replace func(*testing.T, string)
	}{
		{
			name: "lock file",
			replace: func(t *testing.T, policyPath string) {
				t.Helper()
				lockPath := policyPath + ".lock"
				displacedPath := lockPath + ".displaced"
				if _, err := os.Lstat(lockPath); errors.Is(
					err,
					os.ErrNotExist,
				) {
					if err := os.WriteFile(
						lockPath,
						[]byte("legacy"),
						0o600,
					); err != nil {
						t.Fatalf("create legacy lock path: %v", err)
					}
				} else if err != nil {
					t.Fatalf("inspect active lock path: %v", err)
				}
				if err := os.Rename(lockPath, displacedPath); err != nil {
					t.Fatalf("displace active lock path: %v", err)
				}
				if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
					t.Fatalf("replace active lock path: %v", err)
				}
			},
		},
		{
			name: "policy directory",
			replace: func(t *testing.T, policyPath string) {
				t.Helper()
				policyDirectory := filepath.Dir(policyPath)
				displacedDirectory := policyDirectory + ".displaced"
				if err := os.Rename(
					policyDirectory,
					displacedDirectory,
				); err != nil {
					t.Fatalf("displace policy directory: %v", err)
				}
				if err := os.Mkdir(policyDirectory, 0o700); err != nil {
					t.Fatalf("replace policy directory: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			firstAttempt := filepath.Join(home, "first-attempt")
			firstReady := filepath.Join(home, "first-ready")
			firstRelease := filepath.Join(home, "first-release")
			first := startSharedPolicyHelper(
				t,
				home,
				"abort",
				firstAttempt,
				firstReady,
				firstRelease,
			)
			waitForSharedPolicyHelperSignal(t, firstReady)

			t.Setenv("HOME", home)
			policyPath, err := SharedPath("jasp-shared")
			if err != nil {
				t.Fatal(err)
			}
			test.replace(t, policyPath)

			secondAttempt := filepath.Join(home, "second-attempt")
			secondReady := filepath.Join(home, "second-ready")
			secondRelease := filepath.Join(home, "second-release")
			second := startSharedPolicyHelper(
				t,
				home,
				"timeout",
				secondAttempt,
				secondReady,
				secondRelease,
			)
			waitForSharedPolicyHelperSignal(t, secondAttempt)
			waitSharedPolicyHelper(t, second)

			writeSharedPolicyHelperSignal(t, firstRelease)
			waitSharedPolicyHelper(t, first)

			postRelease, err := BeginSharedDefault("jasp-shared")
			if err != nil {
				t.Fatalf(
					"begin shared policy after %s replacement release: %v",
					test.name,
					err,
				)
			}
			if err := postRelease.Rollback(); err != nil {
				t.Fatalf(
					"rollback shared policy after %s replacement release: %v",
					test.name,
					err,
				)
			}
		})
	}
}

func TestBeginSharedDefaultContextCancelsLockWaitAndRecovers(
	t *testing.T,
) {
	t.Setenv("HOME", t.TempDir())
	first, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := BeginSharedDefaultContext(ctx, "jasp-shared"); err == nil ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second transaction error = %v, want deadline exceeded", err)
	}
	if err := first.Rollback(); err != nil {
		t.Fatalf("abort first transaction: %v", err)
	}

	second, err := BeginSharedDefault("jasp-shared")
	if err != nil {
		t.Fatalf("begin after canceled waiter: %v", err)
	}
	if err := second.Commit(); err != nil {
		t.Fatalf("commit after canceled waiter: %v", err)
	}
}

func TestSharedDefaultTransactionsSerializeDifferentMounts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, err := BeginSharedDefault("first-team")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := BeginSharedDefaultContext(
		ctx,
		"second-team",
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("different-mount transaction error = %v", err)
	}
	if err := first.Rollback(); err != nil {
		t.Fatalf("release first mount: %v", err)
	}

	second, err := BeginSharedDefault("second-team")
	if err != nil {
		t.Fatalf("begin second mount after release: %v", err)
	}
	if err := second.Rollback(); err != nil {
		t.Fatalf("release second mount: %v", err)
	}
}

type sharedPolicyHelperProcess struct {
	command *exec.Cmd
	output  *bytes.Buffer
}

func startSharedPolicyHelper(
	t *testing.T,
	home string,
	mode string,
	attemptPath string,
	readyPath string,
	releasePath string,
) sharedPolicyHelperProcess {
	t.Helper()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestSharedPolicyTransactionHelperProcess$",
	)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	command.Env = append(
		filterSharedPolicyHelperEnv(os.Environ()),
		"HOME="+home,
		sharedPolicyHelperModeEnv+"="+mode,
		sharedPolicyHelperMountEnv+"=jasp-shared",
		sharedPolicyHelperAttemptEnv+"="+attemptPath,
		sharedPolicyHelperReadyEnv+"="+readyPath,
		sharedPolicyHelperReleaseEnv+"="+releasePath,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start shared policy helper: %v", err)
	}
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return sharedPolicyHelperProcess{command: command, output: output}
}

func filterSharedPolicyHelperEnv(environment []string) []string {
	blocked := []string{
		"HOME=",
		sharedPolicyHelperModeEnv + "=",
		sharedPolicyHelperMountEnv + "=",
		sharedPolicyHelperAttemptEnv + "=",
		sharedPolicyHelperReadyEnv + "=",
		sharedPolicyHelperReleaseEnv + "=",
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		keep := true
		for _, prefix := range blocked {
			if strings.HasPrefix(entry, prefix) {
				keep = false
				break
			}
		}
		if keep {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func waitSharedPolicyHelper(
	t *testing.T,
	helper sharedPolicyHelperProcess,
) {
	t.Helper()
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("shared policy helper: %v\n%s", err, helper.output.String())
	}
}

func requireSharedPolicyHelperEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("required shared policy helper environment %s is empty", name)
	}
	return value
}

func writeSharedPolicyHelperSignal(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatalf("write shared policy helper signal: %v", err)
	}
}

func waitForSharedPolicyHelperSignal(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect shared policy helper signal: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for shared policy helper signal %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEvaluateCombinedRequiresBothPolicies(t *testing.T) {
	tests := []struct {
		name       string
		global     *Policy
		shared     *Policy
		wantAllow  bool
		wantPrefix string
	}{
		{
			name: "both allow",
			global: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"jasp-shared/**"}},
			}},
			shared: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"jasp-shared/**"}},
			}},
			wantAllow:  true,
			wantPrefix: "global:",
		},
		{
			name: "global deny",
			global: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"other/**"}},
			}},
			shared: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"jasp-shared/**"}},
			}},
			wantPrefix: "global:",
		},
		{
			name: "mount deny",
			global: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"jasp-shared/**"}},
			}},
			shared: &Policy{Actors: map[string]Rules{
				"ai": {
					Allow: []string{"jasp-shared/**"},
					Deny:  []string{"jasp-shared/private/**"},
				},
			}},
			wantPrefix: "shared:",
		},
		{
			name: "nil mount policy",
			global: &Policy{Actors: map[string]Rules{
				"ai": {Allow: []string{"jasp-shared/**"}},
			}},
			wantPrefix: "shared:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretPath := "jasp-shared/secret"
			if tt.name == "mount deny" {
				secretPath = "jasp-shared/private/secret"
			}
			got := EvaluateCombined(tt.global, tt.shared, "ai", "", secretPath)
			if got.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v, want %v (%v)", got.Allowed, tt.wantAllow, got)
			}
			if !strings.HasPrefix(got.MatchedRule, tt.wantPrefix) {
				t.Fatalf("MatchedRule = %q, want prefix %q", got.MatchedRule, tt.wantPrefix)
			}
		})
	}
}

func TestLoadSharedRejectsInvalidYAML(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing version",
			body: "actors: {}\n",
		},
		{
			name: "unsupported version",
			body: "version: 2\nactors: {}\n",
		},
		{
			name: "null version",
			body: "version: null\nactors: {}\n",
		},
		{
			name: "string version",
			body: "version: \"1\"\nactors: {}\n",
		},
		{
			name: "unknown root field",
			body: "version: 1\nactors: {}\nunexpected: true\n",
		},
		{
			name: "unknown rule field",
			body: "version: 1\nactors:\n  ai:\n    unexpected: true\n",
		},
		{
			name: "duplicate root key",
			body: "version: 1\nversion: 1\nactors: {}\n",
		},
		{
			name: "duplicate nested key",
			body: "version: 1\nactors:\n  ai:\n    allow: [\"jasp-shared/**\"]\n" +
				"    allow: [\"other/**\"]\n",
		},
		{
			name: "multiple documents",
			body: "version: 1\nactors: {}\n---\nversion: 1\nactors: {}\n",
		},
		{
			name: "null actors",
			body: "version: 1\nactors: null\n",
		},
		{
			name: "null rules",
			body: "version: 1\nactors:\n  ai: null\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			writeSharedPolicy(t, "jasp-shared", tt.body, 0o600)
			if _, _, _, err := LoadShared("jasp-shared"); err == nil {
				t.Fatal("expected invalid shared policy to be rejected")
			}
		})
	}
}

func TestLoadSharedRejectsUnsafeFiles(t *testing.T) {
	t.Run("symbolic link", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		p, err := SharedPath("jasp-shared")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target.yaml")
		if err := os.WriteFile(
			target,
			[]byte("version: 1\nactors: {}\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := LoadShared("jasp-shared"); err == nil {
			t.Fatal("expected symbolic-link policy to be rejected")
		}
	})

	t.Run("non regular", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		p, err := SharedPath("jasp-shared")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := LoadShared("jasp-shared"); err == nil {
			t.Fatal("expected directory policy to be rejected")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		writeSharedPolicy(
			t,
			"jasp-shared",
			strings.Repeat("#", policyFileSizeLimit+1),
			0o600,
		)
		if _, _, _, err := LoadShared("jasp-shared"); err == nil {
			t.Fatal("expected oversized policy to be rejected")
		}
	})

	t.Run("group readable", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		p := writeSharedPolicy(
			t,
			"jasp-shared",
			"version: 1\nactors: {}\n",
			0o600,
		)
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := LoadShared("jasp-shared"); err == nil {
			t.Fatal("expected insecure permissions to be rejected")
		}
	})
}

func TestLoadSharedHashChangesWithCheckedContent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p := writeSharedPolicy(
		t,
		"jasp-shared",
		"version: 1\nactors:\n  ai:\n    allow: [\"jasp-shared/one/**\"]\n",
		0o600,
	)
	_, _, firstHash, err := LoadShared("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	secondBody := []byte(
		"version: 1\nactors:\n  ai:\n    allow: [\"jasp-shared/two/**\"]\n",
	)
	if err := os.WriteFile(p, secondBody, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, secondHash, err := LoadShared("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if firstHash == secondHash {
		t.Fatal("hash did not change with checked policy content")
	}
	sum := sha256.Sum256(secondBody)
	if want := hex.EncodeToString(sum[:]); secondHash != want {
		t.Fatalf("second hash = %q, want %q", secondHash, want)
	}
}

func TestLoadSharedValidatesActorsAndGlobs(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unicode actor",
			body: "version: 1\nactors:\n  über-agent:\n" +
				"    allow: [\"jasp-shared/**\"]\n",
		},
		{
			name: "control actor",
			body: "version: 1\nactors:\n  \"ai\\tbot\":\n" +
				"    allow: [\"jasp-shared/**\"]\n",
		},
		{
			name: "control glob",
			body: "version: 1\nactors:\n  ai:\n" +
				"    allow: [\"jasp-shared/ok\\n/**\"]\n",
		},
		{
			name: "invalid glob",
			body: "version: 1\nactors:\n  ai:\n" +
				"    allow: [\"jasp-shared/[broken\"]\n",
		},
		{
			name: "unsupported composite globstar",
			body: "version: 1\nactors:\n  ai:\n" +
				"    allow: [\"jasp-shared/*/**\"]\n",
		},
		{
			name: "traversing glob",
			body: "version: 1\nactors:\n  ai:\n" +
				"    allow: [\"../jasp-shared/**\"]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			writeSharedPolicy(t, "jasp-shared", tt.body, 0o600)
			if _, _, _, err := LoadShared("jasp-shared"); err == nil {
				t.Fatal("expected invalid shared policy to be rejected")
			}
		})
	}
}

func TestLoadSharedAllowsPrintableUnicodeGlob(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeSharedPolicy(
		t,
		"jasp-shared",
		"version: 1\nactors:\n  human:\n"+
			"    allow: [\"jasp-shared/über/**\"]\n",
		0o600,
	)
	pol, _, _, err := LoadShared("jasp-shared")
	if err != nil {
		t.Fatal(err)
	}
	if decision := pol.Evaluate(
		"human",
		"",
		"jasp-shared/über/passwort",
	); !decision.Allowed {
		t.Fatalf("printable Unicode glob should be supported: %v", decision)
	}
}

func writeSharedPolicy(
	t *testing.T,
	mount string,
	body string,
	mode os.FileMode,
) string {
	t.Helper()
	p, err := SharedPath(mount)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}
