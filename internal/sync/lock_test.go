package sync

import (
	"bytes"
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

const (
	syncLockHelperModeEnv        = "MYS_TEST_SYNC_LOCK_MODE"
	syncLockHelperPathEnv        = "MYS_TEST_SYNC_LOCK_PATH"
	syncLockHelperMountEnv       = "MYS_TEST_SYNC_LOCK_MOUNT"
	syncLockHelperRemoteEnv      = "MYS_TEST_SYNC_LOCK_REMOTE"
	syncLockHelperFingerprintEnv = "MYS_TEST_SYNC_LOCK_FINGERPRINT"
	syncLockHelperReadyEnv       = "MYS_TEST_SYNC_LOCK_READY"
	syncLockHelperReleaseEnv     = "MYS_TEST_SYNC_LOCK_RELEASE"
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

func TestAcquireMountLockContextRejectsUnsafeLabels(t *testing.T) {
	for _, mount := range []string{
		"../jasp",
		"jasp/team",
		`jasp\team`,
		"jasp\nteam",
		"jasp\x00team",
	} {
		t.Run(mount, func(t *testing.T) {
			lockedContext, release, err := AcquireMountLockContext(
				context.Background(),
				mount,
			)
			if lockedContext != nil || release != nil || err == nil {
				if release != nil {
					_ = release()
				}
				t.Fatalf(
					"unsafe mount lock result: context=%t release=%t error=%v",
					lockedContext != nil,
					release != nil,
					err,
				)
			}
		})
	}
}

func TestMountLeaseContextAllowsNestedConfigLockOnly(t *testing.T) {
	lockedContext, release, err := AcquireMountLockContext(
		context.Background(),
		"jasp",
	)
	if err != nil {
		t.Fatalf("acquire mount lease context: %v", err)
	}

	nestedRelease, err := acquireConfigLock(
		lockedContext,
		filepath.Join(t.TempDir(), "sync.yaml"),
	)
	if err != nil {
		_ = release()
		t.Fatalf("nested config lock: %v", err)
	}
	if err := nestedRelease(); err != nil {
		_ = release()
		t.Fatalf("release nested config lock: %v", err)
	}

	foreignResult := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			50*time.Millisecond,
		)
		defer cancel()
		foreignRelease, err := acquireConfigLock(ctx, "unused")
		if foreignRelease != nil {
			_ = foreignRelease()
			foreignResult <- errors.New(
				"foreign config writer bypassed mount lock",
			)
			return
		}
		foreignResult <- err
	}()
	if err := <-foreignResult; !errors.Is(err, context.DeadlineExceeded) {
		_ = release()
		t.Fatalf("foreign config writer error = %v", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release mount lease context: %v", err)
	}
}

func TestConfigLockHelperProcess(t *testing.T) {
	mode := os.Getenv(syncLockHelperModeEnv)
	if mode == "" {
		return
	}
	switch mode {
	case "locked-update":
		runLockedUpdateHelper(
			t,
			requireSyncLockHelperEnv(t, syncLockHelperPathEnv),
		)
	case "update":
		signalSyncLockHelper(t)
		_, err := UpdateSharedTeamAuditAndSave(
			context.Background(),
			requireSyncLockHelperEnv(t, syncLockHelperPathEnv),
			requireSyncLockHelperEnv(t, syncLockHelperMountEnv),
			syncLockHelperAudit(t),
		)
		if err != nil {
			t.Fatalf("update shared audit: %v", err)
		}
	case "hold":
		release, err := acquireConfigLock(
			context.Background(),
			requireSyncLockHelperEnv(t, syncLockHelperPathEnv),
		)
		if err != nil {
			t.Fatalf("hold config lock: %v", err)
		}
		signalSyncLockHelper(t)
		waitForSyncLockHelperFile(
			t,
			requireSyncLockHelperEnv(t, syncLockHelperReleaseEnv),
		)
		// Deliberately leave the lock open. Process exit must release the
		// kernel lock even when application cleanup did not run.
		runtime.KeepAlive(release)
	case "timeout":
		ctx, cancel := context.WithTimeout(
			context.Background(),
			250*time.Millisecond,
		)
		defer cancel()
		signalSyncLockHelper(t)
		_, err := UpdateSharedTeamAuditAndSave(
			ctx,
			requireSyncLockHelperEnv(t, syncLockHelperPathEnv),
			requireSyncLockHelperEnv(t, syncLockHelperMountEnv),
			syncLockHelperAudit(t),
		)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock wait error = %v, want deadline exceeded", err)
		}
	case "hold-mount":
		release, err := AcquireMountLock(
			context.Background(),
			requireSyncLockHelperEnv(t, syncLockHelperMountEnv),
		)
		if err != nil {
			t.Fatalf("hold mount lock: %v", err)
		}
		signalSyncLockHelper(t)
		waitForSyncLockHelperFile(
			t,
			requireSyncLockHelperEnv(t, syncLockHelperReleaseEnv),
		)
		runtime.KeepAlive(release)
	case "timeout-mount":
		signalSyncLockHelper(t)
		ctx, cancel := context.WithTimeout(
			context.Background(),
			100*time.Millisecond,
		)
		defer cancel()
		release, err := AcquireMountLock(
			ctx,
			requireSyncLockHelperEnv(t, syncLockHelperMountEnv),
		)
		if release != nil {
			_ = release()
			t.Fatal("canceled mount lock returned release function")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf(
				"mount lock wait error = %v, want deadline exceeded",
				err,
			)
		}
	default:
		t.Fatalf("unknown sync lock helper mode %q", mode)
	}
}

func TestConfigLockSerializesCrossProcessMountUpdates(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sync.yaml")
	saveTwoSharedMountConfig(t, path)

	holderReady := filepath.Join(tempDir, "holder-ready")
	holderRelease := filepath.Join(tempDir, "holder-release")
	holder, holderOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:        "locked-update",
		syncLockHelperPathEnv:        path,
		syncLockHelperMountEnv:       "alpha",
		syncLockHelperRemoteEnv:      "/remotes/alpha-audit.git",
		syncLockHelperFingerprintEnv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		syncLockHelperReadyEnv:       holderReady,
		syncLockHelperReleaseEnv:     holderRelease,
		"HOME":                       tempDir,
		"XDG_CONFIG_HOME":            tempDir,
	})
	t.Cleanup(func() {
		_ = os.WriteFile(holderRelease, []byte("release"), 0o600)
		if holder.Process != nil && holder.ProcessState == nil {
			_ = holder.Process.Kill()
		}
	})
	waitForSyncLockHelperFile(t, holderReady)

	waiterReady := filepath.Join(tempDir, "waiter-ready")
	waiter, waiterOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:        "timeout",
		syncLockHelperPathEnv:        path,
		syncLockHelperMountEnv:       "beta",
		syncLockHelperRemoteEnv:      "/remotes/beta-audit.git",
		syncLockHelperFingerprintEnv: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		syncLockHelperReadyEnv:       waiterReady,
		"HOME":                       tempDir,
		"XDG_CONFIG_HOME":            tempDir,
	})
	t.Cleanup(func() {
		if waiter.Process != nil && waiter.ProcessState == nil {
			_ = waiter.Process.Kill()
		}
	})
	waitForSyncLockHelperFile(t, waiterReady)
	if err := waiter.Wait(); err != nil {
		t.Fatalf(
			"blocked update helper: %v\n%s",
			err,
			waiterOutput.String(),
		)
	}

	if err := os.WriteFile(holderRelease, []byte("release"), 0o600); err != nil {
		t.Fatalf("release locked update helper: %v", err)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("locked update helper: %v\n%s", err, holderOutput.String())
	}
	if _, err := UpdateSharedTeamAuditAndSave(
		context.Background(),
		path,
		"beta",
		TeamAuditConfig{
			URL:                "/remotes/beta-audit.git",
			SigningFingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		},
	); err != nil {
		t.Fatalf("update after holder release: %v", err)
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("load merged config: %v", err)
	}
	assertSyncLockAuditRemote(t, config, "alpha", "/remotes/alpha-audit.git")
	assertSyncLockAuditRemote(t, config, "beta", "/remotes/beta-audit.git")
}

func TestConfigLockContextCancellationAndReleaseAfterChildExit(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sync.yaml")
	saveTwoSharedMountConfig(t, path)

	holderReady := filepath.Join(tempDir, "holder-ready")
	holderRelease := filepath.Join(tempDir, "holder-release")
	holder, holderOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:    "hold",
		syncLockHelperPathEnv:    path,
		syncLockHelperReadyEnv:   holderReady,
		syncLockHelperReleaseEnv: holderRelease,
		"HOME":                   tempDir,
		"XDG_CONFIG_HOME":        tempDir,
	})
	t.Cleanup(func() {
		_ = os.WriteFile(holderRelease, []byte("release"), 0o600)
		if holder.Process != nil && holder.ProcessState == nil {
			_ = holder.Process.Kill()
		}
	})
	waitForSyncLockHelperFile(t, holderReady)

	waiterReady := filepath.Join(tempDir, "waiter-ready")
	waiter, waiterOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:        "timeout",
		syncLockHelperPathEnv:        path,
		syncLockHelperMountEnv:       "beta",
		syncLockHelperRemoteEnv:      "/remotes/beta-audit.git",
		syncLockHelperFingerprintEnv: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		syncLockHelperReadyEnv:       waiterReady,
		"HOME":                       tempDir,
		"XDG_CONFIG_HOME":            tempDir,
	})
	t.Cleanup(func() {
		if waiter.Process != nil && waiter.ProcessState == nil {
			_ = waiter.Process.Kill()
		}
	})
	waitForSyncLockHelperFile(t, waiterReady)
	if err := waiter.Wait(); err != nil {
		t.Fatalf("timeout helper: %v\n%s", err, waiterOutput.String())
	}

	config, err := Load(path)
	if err != nil {
		t.Fatalf("load config after canceled waiter: %v", err)
	}
	if remote, ok := config.Remote("beta"); !ok || remote.TeamAudit != nil {
		t.Fatalf("canceled waiter mutated config: %+v", remote)
	}

	if err := os.WriteFile(holderRelease, []byte("release"), 0o600); err != nil {
		t.Fatalf("end holder helper: %v", err)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("holder helper: %v\n%s", err, holderOutput.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := UpdateSharedTeamAuditAndSave(
		ctx,
		path,
		"beta",
		TeamAuditConfig{
			URL:                "/remotes/beta-audit.git",
			SigningFingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		},
	); err != nil {
		t.Fatalf("update after holder process exit: %v", err)
	}
}

func TestConfigLockRemainsSerializedAfterPathReplacement(t *testing.T) {
	tests := []struct {
		name    string
		replace func(*testing.T, string)
	}{
		{
			name: "legacy lock file",
			replace: func(t *testing.T, configPath string) {
				t.Helper()
				replaceSyncLockTestFile(t, configPath+".lock")
			},
		},
		{
			name: "config directory",
			replace: func(t *testing.T, configPath string) {
				t.Helper()
				directory := filepath.Dir(configPath)
				if err := os.Rename(
					directory,
					directory+".displaced",
				); err != nil {
					t.Fatalf("displace config directory: %v", err)
				}
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatalf("replace config directory: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			configDirectory := filepath.Join(tempDir, "config")
			if err := os.Mkdir(configDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(configDirectory, "sync.yaml")
			if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			holderReady := filepath.Join(tempDir, "holder-ready")
			holderRelease := filepath.Join(tempDir, "holder-release")
			holder, holderOutput := startSyncLockHelper(t, map[string]string{
				syncLockHelperModeEnv:    "hold",
				syncLockHelperPathEnv:    path,
				syncLockHelperReadyEnv:   holderReady,
				syncLockHelperReleaseEnv: holderRelease,
				"HOME":                   tempDir,
				"XDG_CONFIG_HOME":        tempDir,
			})
			t.Cleanup(func() {
				_ = os.WriteFile(holderRelease, []byte("release"), 0o600)
				if holder.Process != nil && holder.ProcessState == nil {
					_ = holder.Process.Kill()
				}
			})
			waitForSyncLockHelperFile(t, holderReady)
			test.replace(t, path)

			waiterReady := filepath.Join(tempDir, "waiter-ready")
			waiter, waiterOutput := startSyncLockHelper(
				t,
				map[string]string{
					syncLockHelperModeEnv:        "timeout",
					syncLockHelperPathEnv:        path,
					syncLockHelperMountEnv:       "beta",
					syncLockHelperRemoteEnv:      "/remotes/beta-audit.git",
					syncLockHelperFingerprintEnv: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
					syncLockHelperReadyEnv:       waiterReady,
					"HOME":                       tempDir,
					"XDG_CONFIG_HOME":            tempDir,
				},
			)
			waitForSyncLockHelperFile(t, waiterReady)
			if err := waiter.Wait(); err != nil {
				t.Fatalf(
					"canceled waiter bypassed replaced config path: %v\n%s",
					err,
					waiterOutput.String(),
				)
			}

			if err := os.WriteFile(
				holderRelease,
				[]byte("release"),
				0o600,
			); err != nil {
				t.Fatalf("release config holder: %v", err)
			}
			if err := holder.Wait(); err != nil {
				t.Fatalf("config holder: %v\n%s", err, holderOutput.String())
			}
			release, err := acquireConfigLock(context.Background(), path)
			if err != nil {
				t.Fatalf("reacquire config lock: %v", err)
			}
			if err := release(); err != nil {
				t.Fatalf("release reacquired config lock: %v", err)
			}
		})
	}
}

func TestMountLockRemainsSerializedAfterLegacyPathReplacement(t *testing.T) {
	tempDir := t.TempDir()
	lockDirectory := filepath.Join(tempDir, "my-secrets", "locks")
	if err := os.MkdirAll(lockDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(lockDirectory, "jasp.lock")
	if err := os.WriteFile(lockPath, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}

	holderReady := filepath.Join(tempDir, "holder-ready")
	holderRelease := filepath.Join(tempDir, "holder-release")
	holder, holderOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:    "hold-mount",
		syncLockHelperMountEnv:   "jasp",
		syncLockHelperReadyEnv:   holderReady,
		syncLockHelperReleaseEnv: holderRelease,
		"HOME":                   tempDir,
		"XDG_CONFIG_HOME":        tempDir,
	})
	t.Cleanup(func() {
		_ = os.WriteFile(holderRelease, []byte("release"), 0o600)
		if holder.Process != nil && holder.ProcessState == nil {
			_ = holder.Process.Kill()
		}
	})
	waitForSyncLockHelperFile(t, holderReady)
	replaceSyncLockTestFile(t, lockPath)

	waiterReady := filepath.Join(tempDir, "waiter-ready")
	waiter, waiterOutput := startSyncLockHelper(t, map[string]string{
		syncLockHelperModeEnv:  "timeout-mount",
		syncLockHelperMountEnv: "jasp",
		syncLockHelperReadyEnv: waiterReady,
		"HOME":                 tempDir,
		"XDG_CONFIG_HOME":      tempDir,
	})
	waitForSyncLockHelperFile(t, waiterReady)
	if err := waiter.Wait(); err != nil {
		t.Fatalf(
			"canceled waiter bypassed replaced mount lock path: %v\n%s",
			err,
			waiterOutput.String(),
		)
	}

	if err := os.WriteFile(holderRelease, []byte("release"), 0o600); err != nil {
		t.Fatalf("release mount holder: %v", err)
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("mount holder: %v\n%s", err, holderOutput.String())
	}
	release, err := AcquireMountLock(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("reacquire mount lock: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release reacquired mount lock: %v", err)
	}
}

func replaceSyncLockTestFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, []byte("legacy"), 0o600); err != nil {
			t.Fatalf("create legacy lock path: %v", err)
		}
	} else if err != nil {
		t.Fatalf("inspect legacy lock path: %v", err)
	}
	if err := os.Rename(path, path+".displaced"); err != nil {
		t.Fatalf("displace legacy lock path: %v", err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("replace legacy lock path: %v", err)
	}
}

func runLockedUpdateHelper(t *testing.T, path string) {
	release, err := acquireConfigLock(context.Background(), path)
	if err != nil {
		t.Fatalf("acquire config lock: %v", err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Errorf("release config lock: %v", err)
		}
	}()
	config, err := Load(path)
	if err != nil {
		t.Fatalf("load config under lock: %v", err)
	}
	audit, err := normalizeTeamAuditConfig(syncLockHelperAudit(t))
	if err != nil {
		t.Fatalf("normalize audit config: %v", err)
	}
	if err := setSharedTeamAudit(
		config,
		requireSyncLockHelperEnv(t, syncLockHelperMountEnv),
		audit,
	); err != nil {
		t.Fatalf("update shared audit under lock: %v", err)
	}
	signalSyncLockHelper(t)
	waitForSyncLockHelperFile(
		t,
		requireSyncLockHelperEnv(t, syncLockHelperReleaseEnv),
	)
	if err := saveConfigNextRevisionLocked(path, config); err != nil {
		t.Fatalf("save config under lock: %v", err)
	}
}

func syncLockHelperAudit(t *testing.T) TeamAuditConfig {
	t.Helper()
	return TeamAuditConfig{
		URL: requireSyncLockHelperEnv(t, syncLockHelperRemoteEnv),
		SigningFingerprint: requireSyncLockHelperEnv(
			t,
			syncLockHelperFingerprintEnv,
		),
	}
}

func signalSyncLockHelper(t *testing.T) {
	t.Helper()
	path := requireSyncLockHelperEnv(t, syncLockHelperReadyEnv)
	if err := os.WriteFile(path, []byte("ready"), 0o600); err != nil {
		t.Fatalf("signal helper readiness: %v", err)
	}
}

func requireSyncLockHelperEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("required helper environment %s is empty", name)
	}
	return value
}

func waitForSyncLockHelperFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect helper signal %s: %v", path, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for helper signal %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startSyncLockHelper(
	t *testing.T,
	environment map[string]string,
) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestConfigLockHelperProcess$",
	)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, overridden := environment[name]; !overridden {
			command.Env = append(command.Env, entry)
		}
	}
	for name, value := range environment {
		command.Env = append(command.Env, name+"="+value)
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start config lock helper: %v", err)
	}
	return command, &output
}

func saveTwoSharedMountConfig(t *testing.T, path string) {
	t.Helper()
	if err := Save(path, &Config{
		Version: 1,
		Layout:  LayoutPerOrg,
		Remotes: []StoreRemote{
			{
				Mount:  "alpha",
				URL:    "/remotes/alpha-store.git",
				Shared: true,
			},
			{
				Mount:  "beta",
				URL:    "/remotes/beta-store.git",
				Shared: true,
			},
		},
	}); err != nil {
		t.Fatalf("save shared mount config: %v", err)
	}
}

func assertSyncLockAuditRemote(
	t *testing.T,
	config *Config,
	mount string,
	wantURL string,
) {
	t.Helper()
	remote, ok := config.Remote(mount)
	if !ok || remote.TeamAudit == nil || remote.TeamAudit.URL != wantURL {
		t.Fatalf("%s audit remote = %+v, want %q", mount, remote, wantURL)
	}
}
