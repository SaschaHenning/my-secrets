package keybackup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// setupThrowawayGPG generates a throwaway passphrase-less RSA key in an
// isolated GNUPGHOME under t.TempDir(). It skips the test if gpg is absent.
// Returns the fingerprint of the test key.
func setupThrowawayGPG(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not on PATH — skipping integration test")
	}

	gnupg := filepath.Join(t.TempDir(), "gnupg")
	if err := os.MkdirAll(gnupg, 0o700); err != nil {
		t.Fatalf("mkdir GNUPGHOME: %v", err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	// Ensure any running gpg-agent in this test does not leak between cases.
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--kill", "gpg-agent").Run()
	})

	batch := `%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: my-secrets backup test
Name-Email: backup-test@mys.local
Expire-Date: 1y
%commit
`
	batchPath := filepath.Join(gnupg, "keygen.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatalf("write batch: %v", err)
	}

	cmd := exec.Command("gpg", "--batch", "--quiet", "--generate-key", batchPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("could not generate test GPG key (env issue): %v\n%s", err, out)
	}

	// Resolve the fingerprint of the freshly generated key.
	fpr, err := ResolveFingerprint(context.Background())
	if err != nil {
		t.Fatalf("resolve fingerprint: %v", err)
	}
	if fpr == "" {
		t.Fatal("empty fingerprint after key generation")
	}
	return fpr
}

// TestPaperExportIntegration_Base16 asserts the default format is a
// printable ASCII paperkey document (hex + comments with per-line
// CRC). Skipped when paperkey or gpg is missing.
func TestPaperExportIntegration_Base16(t *testing.T) {
	if _, err := exec.LookPath("paperkey"); err != nil {
		t.Skip("paperkey not on PATH — skipping (install with `brew install paperkey`)")
	}
	fpr := setupThrowawayGPG(t)

	var out bytes.Buffer
	if err := PaperExport(context.Background(), &out, fpr, PaperBase16); err != nil {
		t.Fatalf("PaperExport base16: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("paperkey output is empty")
	}
	// Base16 paperkey output is printable text with a "# Secret Key
	// Data" header or comment lines introduced by '#'. We assert the
	// output is 7-bit-clean ASCII to catch accidental regressions back
	// to the binary 'raw' format.
	for i, b := range out.Bytes() {
		if b > 0x7e && b != '\n' && b != '\r' && b != '\t' {
			t.Fatalf("non-ASCII byte 0x%02x at offset %d — base16 output should be printable", b, i)
		}
	}
	if !bytes.ContainsAny(out.Bytes(), "0123456789abcdefABCDEF") {
		t.Errorf("paperkey output contains no hex: %q", out.String())
	}
}

// TestPaperExportIntegration_Raw verifies that PaperRaw still produces
// non-empty output (the compact binary format). We don't assert on
// byte-level contents because the raw format is intentionally
// opaque — we only guarantee it routes through paperkey successfully.
func TestPaperExportIntegration_Raw(t *testing.T) {
	if _, err := exec.LookPath("paperkey"); err != nil {
		t.Skip("paperkey not on PATH — skipping (install with `brew install paperkey`)")
	}
	fpr := setupThrowawayGPG(t)

	var out bytes.Buffer
	if err := PaperExport(context.Background(), &out, fpr, PaperRaw); err != nil {
		t.Fatalf("PaperExport raw: %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("paperkey raw output is empty")
	}
}

// TestArmoredExportIntegration runs the plain (non-symmetric) armored
// export and asserts we receive a recognisable ASCII-armor block.
func TestArmoredExportIntegration(t *testing.T) {
	fpr := setupThrowawayGPG(t)

	var out bytes.Buffer
	if err := ArmoredExport(context.Background(), &out, fpr, false, ""); err != nil {
		t.Fatalf("ArmoredExport: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		t.Errorf("missing ASCII-armor header in output:\n%s", s)
	}
	if !strings.Contains(s, "-----END PGP PRIVATE KEY BLOCK-----") {
		t.Errorf("missing ASCII-armor footer in output:\n%s", s)
	}
}

// TestArmoredSymmetricIntegration wraps the armored export in
// gpg --symmetric with a piped passphrase and asserts the output is a
// PGP MESSAGE (which is what gpg --symmetric --armor emits).
func TestArmoredSymmetricIntegration(t *testing.T) {
	fpr := setupThrowawayGPG(t)

	var out bytes.Buffer
	if err := ArmoredExport(context.Background(), &out, fpr, true, "super-strong-passphrase-xyz"); err != nil {
		t.Fatalf("ArmoredExport symmetric: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "-----BEGIN PGP MESSAGE-----") {
		t.Errorf("missing PGP MESSAGE header in symmetric output:\n%s", s)
	}
	if !strings.Contains(s, "-----END PGP MESSAGE-----") {
		t.Errorf("missing PGP MESSAGE footer in symmetric output:\n%s", s)
	}
}

// TestArmoredSymmetricEmptyPassphrase is a pure unit-level check that the
// guard rails kick in without spawning subprocesses.
func TestArmoredSymmetricEmptyPassphrase(t *testing.T) {
	var out bytes.Buffer
	err := ArmoredExport(context.Background(), &out, "", true, "")
	if err == nil {
		t.Fatal("expected error for symmetric+empty passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error should mention passphrase, got: %v", err)
	}
}
