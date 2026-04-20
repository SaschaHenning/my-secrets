// Package gpgsetup handles the detection, generation and configuration
// of the GPG key my-secrets uses to encrypt the gopass store.
//
// It is split from the rest of the project because it shells out to the
// `gpg` and `gpgconf` binaries directly — the Go-native OpenPGP
// libraries do not manage the user's keyring, and `mys init` must end
// up with a key that `gpg --list-secret-keys` agrees exists.
//
// The package exposes three high-level entry points used by `mys init`:
//
//   - HasKeys: enumerate existing secret keys via `--with-colons`.
//   - GenerateKey: batch-generate an Ed25519 key and return the new
//     fingerprint (parsed from the [GNUPG:] KEY_CREATED status line).
//   - EnsurePinentryMac: append a `pinentry-program` line to
//     ~/.gnupg/gpg-agent.conf if pinentry-mac is on PATH; idempotent.
package gpgsetup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// KeyInfo describes a single secret key as enumerated by
// `gpg --list-secret-keys --with-colons`.
type KeyInfo struct {
	// Fingerprint is the 40-character hex fingerprint (upper-case).
	Fingerprint string
	// KeyID is the last 16 characters of Fingerprint. Kept as a
	// convenience for callers that want the short form.
	KeyID string
	// UID is the primary user id string, e.g. "Sascha Henning <garry@jasp.eu>".
	// Empty if the key has no user ids attached.
	UID string
	// Algorithm is the colon-format algo code (e.g. "22" for EdDSA).
	Algorithm string
}

// HasKeys returns the list of usable secret keys in the current keyring.
// Returns an empty slice (and nil error) when gpg reports no secret keys.
//
// A non-nil error is returned when gpg itself is missing or errors out —
// an empty keyring is not an error condition.
func HasKeys(ctx context.Context) ([]KeyInfo, error) {
	return hasKeysWithGPG(ctx, "gpg")
}

// hasKeysWithGPG is the injected-gpg-binary variant used by tests.
func hasKeysWithGPG(ctx context.Context, gpgBin string) ([]KeyInfo, error) {
	if _, err := exec.LookPath(gpgBin); err != nil {
		return nil, fmt.Errorf("gpg binary not found on PATH")
	}
	cmd := exec.CommandContext(ctx, gpgBin, "--list-secret-keys", "--with-colons")
	out, err := cmd.Output()
	if err != nil {
		// gpg exits non-zero on an empty keyring on some platforms,
		// non-zero on real errors on others. Be forgiving: if stdout
		// is empty and stderr is either empty or „no secret keys",
		// return an empty slice.
		if exitErr, ok := err.(*exec.ExitError); ok {
			if looksLikeEmptyKeyring(exitErr.Stderr) && len(out) == 0 {
				return nil, nil
			}
			return nil, fmt.Errorf("gpg --list-secret-keys: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("gpg --list-secret-keys: %w", err)
	}
	return parseColonsOutput(out), nil
}

func looksLikeEmptyKeyring(stderr []byte) bool {
	s := strings.ToLower(string(stderr))
	if strings.TrimSpace(s) == "" {
		return true
	}
	return strings.Contains(s, "no secret keys") || strings.Contains(s, "keyring") && strings.Contains(s, "not found")
}

// parseColonsOutput parses the machine-readable colon output of
// `gpg --list-secret-keys --with-colons`. The format is documented in
// gnupg's DETAILS file. We care about three record types:
//
//	sec  — secret key primary record
//	fpr  — fingerprint (follows its parent sec line)
//	uid  — primary user id
//
// Sub-keys (ssb/fpr pairs underneath a sec) are ignored; my-secrets
// identifies keys by the primary fingerprint.
func parseColonsOutput(out []byte) []KeyInfo {
	var keys []KeyInfo
	var current *KeyInfo
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	// gpg can emit very long uid lines; bump the buffer.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inSec := false
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "sec":
			// Start a new key. Flush the previous one if it has a
			// fingerprint.
			if current != nil && current.Fingerprint != "" {
				keys = append(keys, *current)
			}
			ki := KeyInfo{}
			if len(fields) > 3 {
				ki.Algorithm = fields[3]
			}
			current = &ki
			inSec = true
		case "fpr":
			if inSec && current != nil && current.Fingerprint == "" && len(fields) > 9 {
				current.Fingerprint = strings.ToUpper(strings.TrimSpace(fields[9]))
				if len(current.Fingerprint) >= 16 {
					current.KeyID = current.Fingerprint[len(current.Fingerprint)-16:]
				}
			}
		case "uid":
			if inSec && current != nil && current.UID == "" && len(fields) > 9 {
				current.UID = strings.TrimSpace(fields[9])
			}
		case "ssb":
			// Leaving the primary sec block — ignore subkey fprs.
			inSec = false
		}
	}
	if current != nil && current.Fingerprint != "" {
		keys = append(keys, *current)
	}
	return keys
}

// GenerateOpts configures a batch key generation.
type GenerateOpts struct {
	// Name is the real name that ends up in the UID. Required.
	Name string
	// Email is the email address that ends up in the UID. Required.
	Email string
	// Passphrase protects the private key. Empty means „no passphrase"
	// (recommended when pinentry-mac is taking over auth).
	Passphrase string
}

// GenerateKey generates a new Ed25519 / Curve25519 key pair in the
// user's keyring using `gpg --batch --generate-key`. It returns the
// primary-key fingerprint.
//
// The fingerprint is parsed from the `[GNUPG:] KEY_CREATED B <fpr>`
// line on the status file descriptor — reliable even if the keyring
// already contains other keys, which is why we do NOT re-enumerate
// afterwards.
func GenerateKey(ctx context.Context, opts GenerateOpts) (string, error) {
	return generateKeyWithGPG(ctx, "gpg", opts)
}

// generateKeyWithGPG is the injected-binary variant used by tests.
func generateKeyWithGPG(ctx context.Context, gpgBin string, opts GenerateOpts) (string, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return "", errors.New("gpg keygen: Name is required")
	}
	if strings.TrimSpace(opts.Email) == "" {
		return "", errors.New("gpg keygen: Email is required")
	}
	if _, err := exec.LookPath(gpgBin); err != nil {
		return "", fmt.Errorf("gpg binary not found on PATH")
	}

	// Write the batch file to a private tempdir. 0600 on the file,
	// 0700 on the dir. The passphrase goes into the file (never argv)
	// and is wiped on success AND on failure.
	dir, err := os.MkdirTemp("", "mys-keygen-")
	if err != nil {
		return "", fmt.Errorf("tempdir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("tempdir chmod: %w", err)
	}
	defer os.RemoveAll(dir)

	batchPath := filepath.Join(dir, "keygen.batch")
	statusPath := filepath.Join(dir, "status.fd")

	// When we are about to supply a passphrase via the batch file, gpg
	// needs `allow-loopback-pinentry` in ~/.gnupg/gpg-agent.conf — on a
	// fresh system this is not set, so `--pinentry-mode loopback` fails
	// with an „Inappropriate ioctl for device" / „No pinentry" error.
	// Idempotent: skipped when the line is already there.
	if opts.Passphrase != "" {
		if err := ensureAllowLoopbackPinentryIn(ctx, ""); err != nil {
			return "", fmt.Errorf("enable loopback pinentry: %w", err)
		}
	}

	batch := buildKeygenBatch(opts)
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		return "", fmt.Errorf("write batch file: %w", err)
	}

	// Pre-create the status file so --status-file can open it. gpg
	// will overwrite the contents.
	if err := os.WriteFile(statusPath, nil, 0o600); err != nil {
		return "", fmt.Errorf("create status file: %w", err)
	}

	args := []string{
		"--batch",
		"--pinentry-mode", "loopback",
		"--status-file", statusPath,
		"--generate-key", batchPath,
	}
	cmd := exec.CommandContext(ctx, gpgBin, args...)
	// Do NOT pipe a tty; we want a fully non-interactive run.
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gpg --generate-key: %w: %s", err, strings.TrimSpace(string(out)))
	}

	statusBytes, rerr := os.ReadFile(statusPath)
	if rerr != nil {
		return "", fmt.Errorf("read gpg status file: %w", rerr)
	}
	fpr := parseKeyCreatedLine(statusBytes)
	if fpr == "" {
		// Fallback: some gpg builds write KEY_CREATED to stderr only.
		fpr = parseKeyCreatedLine(out)
	}
	if fpr == "" {
		return "", fmt.Errorf("could not find KEY_CREATED fingerprint in gpg output (stdout: %q)", strings.TrimSpace(string(out)))
	}
	return fpr, nil
}

// buildKeygenBatch assembles the batch control file. See `man gpg` →
// „Unattended key generation".
func buildKeygenBatch(opts GenerateOpts) string {
	var b strings.Builder
	b.WriteString("%echo Generating my-secrets Ed25519 key\n")
	if opts.Passphrase == "" {
		b.WriteString("%no-protection\n")
	}
	b.WriteString("Key-Type: EDDSA\n")
	b.WriteString("Key-Curve: ed25519\n")
	b.WriteString("Key-Usage: sign,cert\n")
	b.WriteString("Subkey-Type: ECDH\n")
	b.WriteString("Subkey-Curve: cv25519\n")
	b.WriteString("Subkey-Usage: encrypt\n")
	b.WriteString("Name-Real: ")
	b.WriteString(sanitiseBatchValue(opts.Name))
	b.WriteString("\n")
	b.WriteString("Name-Email: ")
	b.WriteString(sanitiseBatchValue(opts.Email))
	b.WriteString("\n")
	b.WriteString("Expire-Date: 0\n")
	if opts.Passphrase != "" {
		b.WriteString("Passphrase: ")
		b.WriteString(sanitiseBatchValue(opts.Passphrase))
		b.WriteString("\n")
	}
	b.WriteString("%commit\n")
	return b.String()
}

// sanitiseBatchValue strips carriage returns and newlines from values
// that would otherwise break the batch file grammar. We do NOT attempt
// to escape further — the batch format has no quoting, and the values
// my-secrets uses (a person's name, an email, a passphrase) never
// legitimately contain newlines.
func sanitiseBatchValue(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// parseKeyCreatedLine scans a blob of gpg status output and returns the
// fingerprint reported by the first `[GNUPG:] KEY_CREATED <type> <fpr>`
// line, or an empty string if none is present. <type> is one of
// P (primary), S (subkey), B (both). We accept any type but prefer B.
func parseKeyCreatedLine(b []byte) string {
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var primary, any string
	for sc.Scan() {
		line := sc.Text()
		idx := strings.Index(line, "KEY_CREATED")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("KEY_CREATED"):])
		// rest looks like "B ABCD1234..." or "P ABCD1234...".
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0]
		fpr := strings.ToUpper(fields[1])
		if any == "" {
			any = fpr
		}
		if kind == "B" || kind == "P" {
			primary = fpr
		}
	}
	if primary != "" {
		return primary
	}
	return any
}

// EnsurePinentryMac is a macOS-only helper that wires
// pinentry-mac into the user's gpg-agent configuration.
//
// Behaviour:
//   - On non-macOS: no-op, returns (false, nil).
//   - If `pinentry-mac` is not on PATH: prints nothing and returns
//     (false, nil) — the `mys init` step surfaces the install hint.
//   - If the user's ~/.gnupg/gpg-agent.conf already contains a
//     `pinentry-program` line pointing at a `pinentry-mac` binary,
//     the function is a no-op and returns (false, nil).
//   - Otherwise the function appends `pinentry-program <path>` to
//     gpg-agent.conf (creating the file if necessary with 0600) and
//     runs `gpgconf --kill gpg-agent` so the next GPG call picks up
//     the change. Returns (true, nil) on success.
//
// Any error from the filesystem or from gpgconf is returned so the
// init step can decide whether to treat it as fatal; today the init
// step treats this as a warning, not a hard failure.
func EnsurePinentryMac(ctx context.Context) (configured bool, err error) {
	return ensurePinentryMacIn(ctx, "", runtime.GOOS)
}

// ensurePinentryMacIn is the testable core. homeOverride, when
// non-empty, replaces os.UserHomeDir(). goos lets tests simulate non-mac.
func ensurePinentryMacIn(ctx context.Context, homeOverride, goos string) (bool, error) {
	if goos != "darwin" {
		return false, nil
	}
	path, err := exec.LookPath("pinentry-mac")
	if err != nil {
		// Caller prints the install hint.
		return false, nil
	}
	home := homeOverride
	if home == "" {
		h, herr := os.UserHomeDir()
		if herr != nil {
			return false, fmt.Errorf("home dir: %w", herr)
		}
		home = h
	}
	gnupgDir := filepath.Join(home, ".gnupg")
	if err := os.MkdirAll(gnupgDir, 0o700); err != nil {
		return false, fmt.Errorf("create ~/.gnupg: %w", err)
	}
	confPath := filepath.Join(gnupgDir, "gpg-agent.conf")
	existing, rerr := os.ReadFile(confPath)
	if rerr != nil && !os.IsNotExist(rerr) {
		return false, fmt.Errorf("read gpg-agent.conf: %w", rerr)
	}
	if hasPinentryMacLine(existing) {
		return false, nil
	}
	// Append — creating with 0600 if missing.
	var out strings.Builder
	if len(existing) > 0 {
		out.Write(existing)
		if !strings.HasSuffix(string(existing), "\n") {
			out.WriteString("\n")
		}
	}
	out.WriteString("pinentry-program ")
	out.WriteString(path)
	out.WriteString("\n")
	if err := os.WriteFile(confPath, []byte(out.String()), 0o600); err != nil {
		return false, fmt.Errorf("write gpg-agent.conf: %w", err)
	}
	// Reload gpg-agent so the next GPG call uses the new pinentry.
	// A missing gpgconf is a warning, not a fatal error.
	if _, err := exec.LookPath("gpgconf"); err == nil {
		_ = exec.CommandContext(ctx, "gpgconf", "--kill", "gpg-agent").Run()
	}
	return true, nil
}

// ensureAllowLoopbackPinentryIn guarantees that the user's
// ~/.gnupg/gpg-agent.conf contains `allow-loopback-pinentry`. Required
// whenever we invoke `gpg --pinentry-mode loopback` with a passphrase
// — otherwise the agent refuses to accept the loopback pinentry and
// fails key generation. Idempotent: no-op if the line is already there.
// homeOverride is used by tests; empty means os.UserHomeDir().
func ensureAllowLoopbackPinentryIn(ctx context.Context, homeOverride string) error {
	home := homeOverride
	if home == "" {
		h, herr := os.UserHomeDir()
		if herr != nil {
			return fmt.Errorf("home dir: %w", herr)
		}
		home = h
	}
	gnupgDir := filepath.Join(home, ".gnupg")
	if err := os.MkdirAll(gnupgDir, 0o700); err != nil {
		return fmt.Errorf("create ~/.gnupg: %w", err)
	}
	confPath := filepath.Join(gnupgDir, "gpg-agent.conf")
	existing, rerr := os.ReadFile(confPath)
	if rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("read gpg-agent.conf: %w", rerr)
	}
	if hasAllowLoopbackLine(existing) {
		return nil
	}
	var out strings.Builder
	if len(existing) > 0 {
		out.Write(existing)
		if !strings.HasSuffix(string(existing), "\n") {
			out.WriteString("\n")
		}
	}
	out.WriteString("allow-loopback-pinentry\n")
	if err := os.WriteFile(confPath, []byte(out.String()), 0o600); err != nil {
		return fmt.Errorf("write gpg-agent.conf: %w", err)
	}
	if _, err := exec.LookPath("gpgconf"); err == nil {
		_ = exec.CommandContext(ctx, "gpgconf", "--kill", "gpg-agent").Run()
	}
	return nil
}

// hasAllowLoopbackLine reports whether the config blob already declares
// `allow-loopback-pinentry` on a non-comment line.
func hasAllowLoopbackLine(conf []byte) bool {
	sc := bufio.NewScanner(strings.NewReader(string(conf)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "allow-loopback-pinentry" {
			return true
		}
	}
	return false
}

// hasPinentryMacLine reports whether the config blob already
// contains a non-comment `pinentry-program` line whose value ends in
// `pinentry-mac` (the suffix catches both /opt/homebrew/bin/… and
// /usr/local/bin/… installs).
func hasPinentryMacLine(conf []byte) bool {
	sc := bufio.NewScanner(strings.NewReader(string(conf)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "pinentry-program") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		bin := filepath.Base(parts[1])
		if bin == "pinentry-mac" {
			return true
		}
	}
	return false
}
