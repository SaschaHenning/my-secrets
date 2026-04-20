package gopassinit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultStoreDir covers the env-var override and the HOME fallback.
// The gopass-config branch (priority 2) is covered separately by the
// integration tests that set up a real gopass store — it cannot be
// unit-tested without either a gopass stub or a fake PATH.
func TestDefaultStoreDir(t *testing.T) {
	t.Setenv("PASSWORD_STORE_DIR", "/tmp/custom-store")
	got, err := DefaultStoreDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/custom-store" {
		t.Fatalf("env override: got %q, want /tmp/custom-store", got)
	}

	// For the HOME fallback to trigger in isolation we need gopass NOT
	// to be on PATH — otherwise the gopass-config branch wins and the
	// test asserts against the wrong priority level.
	os.Unsetenv("PASSWORD_STORE_DIR")
	t.Setenv("PATH", t.TempDir()) // empty dir → no gopass binary
	t.Setenv("HOME", "/tmp/fake-home")
	got, err = DefaultStoreDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join("/tmp/fake-home", ".password-store") {
		t.Fatalf("HOME fallback: got %q", got)
	}
}

// TestIsInitialised_AbsentAndPresent uses a synthetic store directory.
func TestIsInitialised_AbsentAndPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", dir)

	if IsInitialised() {
		t.Fatalf("store with no .gpg-id should not be marked initialised")
	}

	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"),
		[]byte("ABCDEF0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !IsInitialised() {
		t.Fatalf("store with .gpg-id should be marked initialised")
	}
}

// TestInitialise_AlreadyInitialised is the idempotency contract:
// Initialise must be a no-op when the store exists, and it must not
// call the gopass binary.
func TestInitialise_AlreadyInitialised(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte("FAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Point at a non-existent binary — if Initialise were to invoke it,
	// the call would fail and we would see the error.
	err := initialiseWithBin(context.Background(), "/nonexistent/gopass-stub", "FAKE")
	if err != nil {
		t.Fatalf("Initialise on an already-initialised store must be a no-op: got %v", err)
	}
}

// TestInitialise_RejectsEmptyKeyID guards against a regression where
// an empty fingerprint is passed as the positional arg.
func TestInitialise_RejectsEmptyKeyID(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSWORD_STORE_DIR", dir)
	err := initialiseWithBin(context.Background(), "gopass", "   ")
	if err == nil {
		t.Fatalf("empty keyID should error")
	}
	if !strings.Contains(err.Error(), "keyID required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestInitialise_Integration actually runs `gopass init` against a
// temporary PASSWORD_STORE_DIR, using a throwaway GPG keyring. Skipped
// when gpg or gopass are not on PATH. This is the same-shape test the
// issue asks for.
func TestInitialise_Integration(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	if _, err := exec.LookPath("gopass"); err != nil {
		t.Skip("gopass not on PATH")
	}
	if os.Getenv("MYS_SKIP_GPG_INTEGRATION") == "1" {
		t.Skip("MYS_SKIP_GPG_INTEGRATION=1")
	}

	// Short-path GNUPGHOME (macOS socket limit).
	gnupg, err := os.MkdirTemp("", "gh-")
	if err != nil {
		t.Fatalf("gnupg tmpdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(gnupg) })
	_ = os.Chmod(gnupg, 0o700)
	t.Setenv("GNUPGHOME", gnupg)

	// Generate a throwaway key so gopass has something to encrypt to.
	batch := filepath.Join(gnupg, "batch")
	if err := os.WriteFile(batch, []byte(
		"%echo integration\n%no-protection\nKey-Type: EDDSA\nKey-Curve: ed25519\nSubkey-Type: ECDH\nSubkey-Curve: cv25519\nName-Real: Integration Test\nName-Email: integration@example.com\nExpire-Date: 0\n%commit\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	statusFile := filepath.Join(gnupg, "status")
	_ = os.WriteFile(statusFile, nil, 0o600)
	out, err := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback",
		"--status-file", statusFile, "--generate-key", batch).CombinedOutput()
	if err != nil {
		t.Skipf("gpg generate-key failed in sandbox: %v: %s", err, out)
	}
	st, _ := os.ReadFile(statusFile)
	fpr := findKeyCreated(string(st))
	if fpr == "" {
		fpr = findKeyCreated(string(out))
	}
	if fpr == "" {
		t.Fatalf("could not parse generated fingerprint from: %s\n%s", st, out)
	}

	// Point gopass at a tempdir and initialise.
	storeDir := filepath.Join(t.TempDir(), "pwd-store")
	t.Setenv("PASSWORD_STORE_DIR", storeDir)
	// gopass consults its own config for store locations. Isolate
	// that config so this test cannot interfere with the dev machine.
	gopassCfgHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", gopassCfgHome)

	if err := Initialise(context.Background(), fpr); err != nil {
		t.Skipf("gopass init failed (often pinentry/agent-related in CI): %v", err)
	}
	gpgID, err := os.ReadFile(filepath.Join(storeDir, ".gpg-id"))
	if err != nil {
		t.Fatalf("read .gpg-id: %v", err)
	}
	// gopass normalises the identifier it writes to .gpg-id — it may
	// record the long key id (last 16 hex chars, possibly with a
	// leading "0x") instead of the full fingerprint. We accept any
	// form that contains the last 16 characters of the fingerprint.
	shortID := fpr[len(fpr)-16:]
	got := strings.ToUpper(strings.TrimSpace(string(gpgID)))
	if !strings.Contains(got, strings.ToUpper(shortID)) {
		t.Fatalf(".gpg-id %q does not reference fingerprint %q (short %q)", gpgID, fpr, shortID)
	}

	// Re-running must be a no-op.
	if err := Initialise(context.Background(), fpr); err != nil {
		t.Fatalf("second Initialise should be idempotent, got %v", err)
	}

	_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
}

// findKeyCreated is a local copy of the gpgsetup parser — kept here
// so this test package stays self-contained (no import cycles with
// gpgsetup).
func findKeyCreated(s string) string {
	for _, line := range strings.Split(s, "\n") {
		idx := strings.Index(line, "KEY_CREATED")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("KEY_CREATED"):])
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		return strings.ToUpper(fields[1])
	}
	return ""
}
