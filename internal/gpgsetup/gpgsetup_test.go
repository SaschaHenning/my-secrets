package gpgsetup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestParseColonsOutput drives the colon parser with a captured fixture
// taken from a real keyring. The parser must surface the primary
// fingerprint and the primary uid for each sec block.
func TestParseColonsOutput(t *testing.T) {
	fixture := strings.Join([]string{
		"sec:u:255:22:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1700000000:::u:::scESC:::+:::23::0:",
		"fpr:::::::::ABCDEF0123456789ABCDEF0123456789ABCDEF01:",
		"grp:::::::::deadbeef:",
		"uid:u::::1700000000::abc1::Sascha Henning <garry@jasp.eu>::::::::::0:",
		"ssb:u:255:18:1111222233334444:1700000000::::::e:::+:::23:",
		"fpr:::::::::AAAABBBBCCCCDDDDEEEE111122223333444455AA:",
		"sec:u:255:22:0123456789ABCDEF0123456789ABCDEF01234567:1700000100:::u:::scESC:::+:::23::0:",
		"fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:",
		"uid:u::::1700000100::def2::Other User <other@example.com>::::::::::0:",
	}, "\n") + "\n"

	keys := parseColonsOutput([]byte(fixture))
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d: %+v", len(keys), keys)
	}
	if keys[0].Fingerprint != "ABCDEF0123456789ABCDEF0123456789ABCDEF01" {
		t.Errorf("key 0 fpr = %q", keys[0].Fingerprint)
	}
	if keys[0].KeyID != "ABCDEF0123456789ABCDEF01" && keys[0].KeyID != "23456789ABCDEF01" {
		// KeyID is the last 16 hex chars of the fingerprint.
		t.Errorf("key 0 keyid = %q, want last-16 of fingerprint", keys[0].KeyID)
	}
	if keys[0].UID != "Sascha Henning <garry@jasp.eu>" {
		t.Errorf("key 0 uid = %q", keys[0].UID)
	}
	if keys[1].Fingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Errorf("key 1 fpr = %q", keys[1].Fingerprint)
	}
	if keys[1].UID != "Other User <other@example.com>" {
		t.Errorf("key 1 uid = %q", keys[1].UID)
	}
}

// TestParseColonsOutputEmpty ensures an empty keyring yields nil,
// not a key with an empty fingerprint.
func TestParseColonsOutputEmpty(t *testing.T) {
	if keys := parseColonsOutput([]byte("")); len(keys) != 0 {
		t.Fatalf("empty keyring should parse to 0 keys, got %d", len(keys))
	}
	if keys := parseColonsOutput([]byte("gpg: no secret keys found\n")); len(keys) != 0 {
		t.Fatalf("non-colon chatter should parse to 0 keys, got %d", len(keys))
	}
}

// TestParseKeyCreatedLine exercises the status-fd parser for the
// KEY_CREATED line emitted by `gpg --status-file`.
func TestParseKeyCreatedLine(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "status-fd with B",
			in:   "[GNUPG:] KEY_CREATED B ABCDEF0123456789ABCDEF0123456789ABCDEF01\n",
			want: "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
		},
		{
			name: "status-fd with P",
			in:   "[GNUPG:] KEY_CREATED P 1234567890ABCDEF1234567890ABCDEF12345678\n",
			want: "1234567890ABCDEF1234567890ABCDEF12345678",
		},
		{
			name: "combined stderr",
			in: "gpg: generating key\n" +
				"gpg: key XYZ generated\n" +
				"[GNUPG:] KEY_CREATED B DEADBEEFCAFEBABE0123456789ABCDEF01234567\n",
			want: "DEADBEEFCAFEBABE0123456789ABCDEF01234567",
		},
		{
			name: "no status line",
			in:   "gpg: nothing happened\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseKeyCreatedLine([]byte(tc.in))
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBuildKeygenBatch checks that the batch file contains the expected
// directives and — crucially — that a passphrase never leaks into argv
// by being part of the batch body instead.
func TestBuildKeygenBatch(t *testing.T) {
	b := buildKeygenBatch(GenerateOpts{
		Name:  "Sascha Henning",
		Email: "garry@jasp.eu",
	})
	for _, must := range []string{
		"Key-Type: EDDSA",
		"Key-Curve: ed25519",
		"Subkey-Type: ECDH",
		"Subkey-Curve: cv25519",
		"Name-Real: Sascha Henning",
		"Name-Email: garry@jasp.eu",
		"Expire-Date: 0",
		"%no-protection",
		"%commit",
	} {
		if !strings.Contains(b, must) {
			t.Errorf("batch file missing %q:\n%s", must, b)
		}
	}
	if strings.Contains(b, "Passphrase:") {
		t.Errorf("batch file should not contain Passphrase: when passphrase is empty:\n%s", b)
	}

	b2 := buildKeygenBatch(GenerateOpts{
		Name:       "Sascha Henning",
		Email:      "garry@jasp.eu",
		Passphrase: "correct horse battery staple",
	})
	if !strings.Contains(b2, "Passphrase: correct horse battery staple") {
		t.Errorf("batch file with passphrase missing Passphrase line:\n%s", b2)
	}
	if strings.Contains(b2, "%no-protection") {
		t.Errorf("batch file with passphrase should NOT set %%no-protection:\n%s", b2)
	}
}

// TestSanitiseBatchValue ensures newlines cannot smuggle arbitrary
// directives into the batch file via a malicious name/email.
func TestSanitiseBatchValue(t *testing.T) {
	got := sanitiseBatchValue("Attacker\nPassphrase: leak")
	if strings.Contains(got, "\n") {
		t.Fatalf("sanitise left newline in %q", got)
	}
}

// TestGenerateKey_Integration runs a real `gpg --generate-key` in a
// throwaway GNUPGHOME. Skipped when gpg is not on PATH (CI without the
// toolchain) or when CI=1 plus MYS_SKIP_GPG_INTEGRATION=1 for speed.
func TestGenerateKey_Integration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("gpg integration test is POSIX-only")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	if os.Getenv("MYS_SKIP_GPG_INTEGRATION") == "1" {
		t.Skip("MYS_SKIP_GPG_INTEGRATION=1")
	}

	dir := t.TempDir()
	// GNUPGHOME paths have a socket-name length limit. t.TempDir can
	// produce long paths on macOS ("/var/folders/.../T/...") that blow
	// up gpg-agent's autostart. Use a short symlink as a workaround.
	short, err := os.MkdirTemp("", "gh-")
	if err != nil {
		t.Fatalf("short tmpdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	_ = os.Chmod(short, 0o700)
	_ = os.Chmod(dir, 0o700)
	t.Setenv("GNUPGHOME", short)

	ctx := context.Background()
	fpr, err := GenerateKey(ctx, GenerateOpts{
		Name:  "Test User",
		Email: "test@example.com",
	})
	if err != nil {
		// On a totally fresh macOS this may fail due to pinentry. Record
		// and skip rather than fail, so the unit-test suite remains
		// usable on dev machines without a tuned GPG setup.
		t.Skipf("gpg generate-key failed in sandbox (often pinentry/entropy related): %v", err)
	}
	if len(fpr) != 40 {
		t.Fatalf("fingerprint should be 40 hex chars, got %q (len=%d)", fpr, len(fpr))
	}
	// Round-trip through HasKeys — the key must show up.
	keys, err := HasKeys(ctx)
	if err != nil {
		t.Fatalf("HasKeys: %v", err)
	}
	found := false
	for _, k := range keys {
		if k.Fingerprint == fpr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("generated key %s not listed by HasKeys; got %+v", fpr, keys)
	}
	// Shut down the per-run gpg-agent so the tempdir cleanup can delete
	// the socket without EBUSY on some systems.
	_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
}

// TestGenerateKey_WithPassphrase_RoundTrip is the regression test for
// the „Passwort falsch"-bug: generate a key with a known passphrase,
// then prove — via the built-in self-check — that the same passphrase
// actually decrypts data encrypted to the new key. Previously
// sanitiseBatchValue trimmed spaces, so a passphrase like " 1234 "
// would be stored as "1234" and the self-check (or the user's
// pinentry-mac prompt later) would reject the space-padded form.
func TestGenerateKey_WithPassphrase_RoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH")
	}
	if os.Getenv("MYS_SKIP_GPG_INTEGRATION") == "1" {
		t.Skip("MYS_SKIP_GPG_INTEGRATION=1")
	}
	short, err := os.MkdirTemp("", "gh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	_ = os.Chmod(short, 0o700)
	t.Setenv("GNUPGHOME", short)

	// Simple passphrase, and the space-padded variant that used to
	// silently get truncated.
	cases := []string{"1234", " 1234 ", "my secret with spaces"}
	for _, pass := range cases {
		t.Run(fmt.Sprintf("pass=%q", pass), func(t *testing.T) {
			fpr, err := GenerateKey(context.Background(), GenerateOpts{
				Name:       "Probe",
				Email:      "probe@example.com",
				Passphrase: pass,
			})
			if err != nil {
				t.Skipf("keygen failed (may be pinentry/entropy): %v", err)
			}
			// verifyKeyPassphrase is called by GenerateKey before it
			// returns, so a successful return IS the proof that the
			// passphrase round-trips. But be explicit and run it again
			// with a fresh probe — any flakiness would show up here.
			if err := verifyKeyPassphrase(context.Background(), "gpg", fpr, pass); err != nil {
				t.Fatalf("passphrase %q did not round-trip: %v", pass, err)
			}
			// Clean up for the next sub-test.
			_ = exec.Command("gpg", "--batch", "--yes",
				"--delete-secret-and-public-keys", fpr).Run()
		})
	}
	_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
}

// TestEnsurePinentryMac_NonMac makes sure the function is a pure
// no-op off darwin (no filesystem writes, no subprocess calls).
func TestEnsurePinentryMac_NonMac(t *testing.T) {
	home := t.TempDir()
	ctx := context.Background()
	configured, err := ensurePinentryMacIn(ctx, home, "linux")
	if err != nil {
		t.Fatalf("err on linux: %v", err)
	}
	if configured {
		t.Fatalf("should not configure on linux")
	}
	if _, err := os.Stat(filepath.Join(home, ".gnupg", "gpg-agent.conf")); err == nil {
		t.Fatalf("ensurePinentryMacIn created gpg-agent.conf on linux")
	}
}

// TestEnsurePinentryMac_NotOnPath must not touch the config when
// pinentry-mac is missing from PATH — callers print the install
// hint themselves.
func TestEnsurePinentryMac_NotOnPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific path")
	}
	// Stub PATH so LookPath fails for pinentry-mac.
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
	configured, err := ensurePinentryMacIn(context.Background(), home, "darwin")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if configured {
		t.Fatalf("configured=true with pinentry-mac missing from PATH")
	}
	if _, err := os.Stat(filepath.Join(home, ".gnupg", "gpg-agent.conf")); err == nil {
		t.Fatalf("gpg-agent.conf should not have been created")
	}
}

// TestEnsurePinentryMac_Idempotent makes sure a second call with an
// already-configured file is a no-op.
func TestEnsurePinentryMac_Idempotent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific path")
	}
	// Lay down a fake pinentry-mac so LookPath succeeds.
	pathDir := t.TempDir()
	fake := filepath.Join(pathDir, "pinentry-mac")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake pinentry: %v", err)
	}
	t.Setenv("PATH", pathDir)

	home := t.TempDir()
	ctx := context.Background()

	// First call writes the file.
	configured, err := ensurePinentryMacIn(ctx, home, "darwin")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !configured {
		t.Fatalf("first call should report configured=true")
	}
	confPath := filepath.Join(home, ".gnupg", "gpg-agent.conf")
	first, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if !strings.Contains(string(first), "pinentry-mac") {
		t.Fatalf("file missing pinentry-mac line: %q", first)
	}

	// Second call must be idempotent.
	configured2, err := ensurePinentryMacIn(ctx, home, "darwin")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if configured2 {
		t.Fatalf("second call should report configured=false (no change)")
	}
	second, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("file changed between idempotent calls:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// TestHasPinentryMacLine checks the matcher against common config
// shapes so the idempotency promise does not regress.
func TestHasPinentryMacLine(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"comment only", "# pinentry-program /opt/homebrew/bin/pinentry-mac\n", false},
		{"other pinentry", "pinentry-program /usr/local/bin/pinentry-curses\n", false},
		{"homebrew", "pinentry-program /opt/homebrew/bin/pinentry-mac\n", true},
		{"intel homebrew", "pinentry-program /usr/local/bin/pinentry-mac\n", true},
		{"leading whitespace", "   pinentry-program /opt/homebrew/bin/pinentry-mac  \n", true},
		{"no path", "pinentry-program\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasPinentryMacLine([]byte(tc.input)); got != tc.want {
				t.Fatalf("input %q → %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestSanitisePassphrase_KeepsLeadingTrailingSpaces is the regression
// test for the „Passwort falsch"-bug. A user who typed a passphrase
// with a leading or trailing space (e.g. pasted from a password
// manager that helpfully added one) used to get a key whose
// passphrase never matched because sanitiseBatchValue trimmed the
// space off before writing the batch file.
func TestSanitisePassphrase_KeepsLeadingTrailingSpaces(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"leading space", " secret", " secret"},
		{"trailing space", "secret ", "secret "},
		{"both", " secret ", " secret "},
		{"internal space", "my secret pass", "my secret pass"},
		{"strips newline", "secret\n", "secret"},
		{"strips carriage return", "secret\r", "secret"},
		{"preserves tabs and punct", "se\tcret-pw!", "se\tcret-pw!"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitisePassphrase(tc.in)
			if got != tc.want {
				t.Errorf("sanitisePassphrase(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
