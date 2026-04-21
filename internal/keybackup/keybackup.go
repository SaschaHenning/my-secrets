// Package keybackup produces personal backups of the GPG secret key that
// encrypts the gopass store. Losing the key means losing every secret — so
// this package wraps two independent backup techniques:
//
//  1. paperkey — a compact, printable encoding of the secret key suitable
//     for paper printouts (via the external `paperkey` tool).
//  2. ASCII-armored secret key export, optionally wrapped in
//     `gpg --symmetric` so the output is safe to carry on a USB stick
//     without access to the GPG agent that wrote it.
//
// Every successful backup is recorded in a local JSON ledger
// (~/.local/share/my-secrets/backups.json) with metadata only — never key
// material. The caller is expected to also write an audit-log row via the
// App layer.
package keybackup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Method identifies the backup technique that produced a record.
type Method string

const (
	MethodPaper            Method = "paper"
	MethodArmored          Method = "armored"
	MethodArmoredSymmetric Method = "armored-symmetric"
)

// BackupRecord is one row of the backup ledger. It must NEVER contain key
// material — only metadata describing that a backup happened.
type BackupRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	Method      Method    `json:"method"`
	Fingerprint string    `json:"fingerprint"`
	OutputPath  string    `json:"output_path,omitempty"` // empty when streamed to stdout
}

// DefaultStatusPath returns the JSON ledger location:
// ~/.local/share/my-secrets/backups.json.
func DefaultStatusPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "my-secrets", "backups.json"), nil
}

// AppendRecord adds rec to the ledger at DefaultStatusPath.
func AppendRecord(rec BackupRecord) error {
	p, err := DefaultStatusPath()
	if err != nil {
		return err
	}
	return AppendRecordAt(p, rec)
}

// AppendRecordAt adds rec to the ledger at the given path, creating the
// parent directory and the file if necessary.
func AppendRecordAt(path string, rec BackupRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir backup ledger: %w", err)
	}
	records, err := listAt(path)
	if err != nil {
		return err
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	records = append(records, rec)
	buf, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup ledger: %w", err)
	}
	// Atomic replace via temp file + rename.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".backups-*.json")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write backup ledger: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename backup ledger: %w", err)
	}
	return nil
}

// List returns all ledger records in order of insertion (oldest first).
// An absent ledger file is treated as an empty list.
func List() ([]BackupRecord, error) {
	p, err := DefaultStatusPath()
	if err != nil {
		return nil, err
	}
	return listAt(p)
}

// ListAt is List with an explicit path.
func ListAt(path string) ([]BackupRecord, error) {
	return listAt(path)
}

func listAt(path string) ([]BackupRecord, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup ledger: %w", err)
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, nil
	}
	var records []BackupRecord
	if err := json.Unmarshal(buf, &records); err != nil {
		return nil, fmt.Errorf("parse backup ledger: %w", err)
	}
	return records, nil
}

// RequireBinaries checks that every named binary is available on PATH and
// returns a combined, user-friendly error if any is missing. Each missing
// binary's error includes an install hint.
func RequireBinaries(bins ...string) error {
	var missing []string
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			hint := installHint(b)
			if hint != "" {
				missing = append(missing, fmt.Sprintf("%s not on PATH (%s)", b, hint))
			} else {
				missing = append(missing, fmt.Sprintf("%s not on PATH", b))
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return errors.New(strings.Join(missing, "; "))
}

func installHint(bin string) string {
	switch bin {
	case "paperkey":
		return "install with `brew install paperkey`"
	case "gpg":
		return "install with `brew install gnupg`"
	}
	return ""
}

// ResolveFingerprint runs `gpg --list-secret-keys --with-colons` and returns
// the first secret-key fingerprint found. Used when the caller did not pass
// an explicit key ID.
func ResolveFingerprint(ctx context.Context) (string, error) {
	if err := RequireBinaries("gpg"); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "gpg", "--list-secret-keys", "--with-colons")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gpg list: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "fpr:") {
			cols := strings.Split(line, ":")
			if len(cols) >= 10 && cols[9] != "" {
				return cols[9], nil
			}
		}
	}
	return "", errors.New("no GPG secret key fingerprint found — run `gpg --list-secret-keys` to check")
}

// PaperFormat selects the paperkey output encoding. Base16 is the
// default because a "paper key" backup is expected to be printable and
// hand-copiable; Raw is a compact binary blob suitable for QR-encoding
// or downstream tooling that expects the original paperkey format.
type PaperFormat int

const (
	// PaperBase16 is printable hex (paperkey's own default). Each line
	// carries a CRC-24 so hand-copy errors are detectable.
	PaperBase16 PaperFormat = iota
	// PaperRaw is the compact binary encoding. Only useful as input to
	// something that re-encodes it (QR, base64, …).
	PaperRaw
)

// PaperExport streams the paperkey-encoded secret key identified by
// keyID to w using the chosen format. keyID may be a fingerprint, long
// key ID, or email; an empty string lets gpg pick its default secret
// key. The caller is responsible for flushing / closing w.
func PaperExport(ctx context.Context, w io.Writer, keyID string, format PaperFormat) error {
	if err := RequireBinaries("gpg", "paperkey"); err != nil {
		return err
	}
	args := []string{"--export-secret-keys"}
	if keyID != "" {
		args = append(args, keyID)
	}
	exportCmd := exec.CommandContext(ctx, "gpg", args...)
	// Base16 is paperkey's own default; we pass `--output-type base16`
	// explicitly anyway so the behaviour survives future paperkey
	// releases that might change their default.
	paperArgs := []string{"--output-type", "base16"}
	if format == PaperRaw {
		paperArgs = []string{"--output-type", "raw"}
	}
	paperCmd := exec.CommandContext(ctx, "paperkey", paperArgs...)

	pipe, err := exportCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("gpg stdout pipe: %w", err)
	}
	paperCmd.Stdin = pipe
	paperCmd.Stdout = w
	var paperErr bytes.Buffer
	paperCmd.Stderr = &paperErr
	var gpgErr bytes.Buffer
	exportCmd.Stderr = &gpgErr

	if err := paperCmd.Start(); err != nil {
		return fmt.Errorf("start paperkey: %w", err)
	}
	if err := exportCmd.Start(); err != nil {
		_ = paperCmd.Process.Kill()
		_ = paperCmd.Wait()
		return fmt.Errorf("start gpg: %w", err)
	}
	if err := exportCmd.Wait(); err != nil {
		_ = paperCmd.Process.Kill()
		_ = paperCmd.Wait()
		return fmt.Errorf("gpg export: %w (stderr: %s)", err, strings.TrimSpace(gpgErr.String()))
	}
	if err := paperCmd.Wait(); err != nil {
		return fmt.Errorf("paperkey: %w (stderr: %s)", err, strings.TrimSpace(paperErr.String()))
	}
	return nil
}

// ArmoredExport streams an ASCII-armored export of the secret key. When
// symmetric is true the armored export is additionally piped through
// `gpg --symmetric --cipher-algo AES256` using passphrase as AES key — this
// is the safe-for-USB variant. passphrase must be non-empty if symmetric is
// true; it is ignored otherwise.
func ArmoredExport(ctx context.Context, w io.Writer, keyID string, symmetric bool, passphrase string) error {
	if err := RequireBinaries("gpg"); err != nil {
		return err
	}
	if symmetric && passphrase == "" {
		return errors.New("symmetric export requires a passphrase")
	}

	args := []string{"--armor", "--export-secret-keys"}
	if keyID != "" {
		args = append(args, keyID)
	}
	exportCmd := exec.CommandContext(ctx, "gpg", args...)
	var exportErr bytes.Buffer
	exportCmd.Stderr = &exportErr

	if !symmetric {
		exportCmd.Stdout = w
		if err := exportCmd.Run(); err != nil {
			return fmt.Errorf("gpg armored export: %w (stderr: %s)", err,
				strings.TrimSpace(exportErr.String()))
		}
		return nil
	}

	// Symmetric: feed the armored export into gpg --symmetric. Passphrase is
	// delivered on fd 3 via --passphrase-fd so it never appears in argv.
	symCmd := exec.CommandContext(ctx, "gpg",
		"--symmetric",
		"--cipher-algo", "AES256",
		"--batch",
		"--passphrase-fd", "3",
		"--armor",
		"--output", "-",
	)

	// Build pipes: export stdout → symCmd stdin; passphrase → symCmd fd 3.
	pipe, err := exportCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("gpg export stdout pipe: %w", err)
	}
	symCmd.Stdin = pipe

	passR, passW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("passphrase pipe: %w", err)
	}
	symCmd.ExtraFiles = []*os.File{passR}
	symCmd.Stdout = w
	var symErr bytes.Buffer
	symCmd.Stderr = &symErr

	if err := symCmd.Start(); err != nil {
		_ = passR.Close()
		_ = passW.Close()
		return fmt.Errorf("start gpg symmetric: %w", err)
	}
	// Parent side of the passphrase pipe is no longer needed.
	_ = passR.Close()

	// Write passphrase (with a trailing newline) and close the write end so
	// gpg's read loop returns EOF after the single line.
	if _, err := io.WriteString(passW, passphrase+"\n"); err != nil {
		_ = passW.Close()
		_ = symCmd.Process.Kill()
		_ = symCmd.Wait()
		return fmt.Errorf("write passphrase: %w", err)
	}
	_ = passW.Close()

	if err := exportCmd.Start(); err != nil {
		_ = symCmd.Process.Kill()
		_ = symCmd.Wait()
		return fmt.Errorf("start gpg export: %w", err)
	}
	if err := exportCmd.Wait(); err != nil {
		_ = symCmd.Process.Kill()
		_ = symCmd.Wait()
		return fmt.Errorf("gpg export: %w (stderr: %s)", err,
			strings.TrimSpace(exportErr.String()))
	}
	if err := symCmd.Wait(); err != nil {
		return fmt.Errorf("gpg symmetric: %w (stderr: %s)", err,
			strings.TrimSpace(symErr.String()))
	}
	return nil
}
