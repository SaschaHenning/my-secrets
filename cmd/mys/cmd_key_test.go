package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/keybackup"
)

// withFakeHome redirects $HOME so `mys key backup --status` reads our test
// ledger path instead of the real user's state.
func withFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// TestKeyBackupStatusEmpty verifies the --status sub-mode on a virgin
// system: no ledger file present, must report "no backups recorded yet".
func TestKeyBackupStatusEmpty(t *testing.T) {
	withFakeHome(t)

	var req string
	cmd := keyCmd(&req)
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"backup", "--status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute --status (empty): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no backups recorded yet") {
		t.Errorf("expected empty-state message, got: %q", out)
	}
}

// TestKeyBackupStatusWithEntries pre-populates the ledger and asserts the
// --status sub-mode renders one line per record.
func TestKeyBackupStatusWithEntries(t *testing.T) {
	home := withFakeHome(t)
	ledgerDir := filepath.Join(home, ".local", "share", "my-secrets")
	if err := os.MkdirAll(ledgerDir, 0o700); err != nil {
		t.Fatalf("mkdir ledger dir: %v", err)
	}

	records := []keybackup.BackupRecord{
		{
			Timestamp:   time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
			Method:      keybackup.MethodPaper,
			Fingerprint: "AAAA1111",
			OutputPath:  "/tmp/k.paper",
		},
		{
			Timestamp:   time.Date(2026, 4, 2, 13, 30, 0, 0, time.UTC),
			Method:      keybackup.MethodArmoredSymmetric,
			Fingerprint: "BBBB2222",
		},
	}
	payload, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ledgerDir, "backups.json"), payload, 0o600); err != nil {
		t.Fatalf("write ledger: %v", err)
	}

	var req string
	cmd := keyCmd(&req)
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"backup", "--status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute --status (populated): %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AAAA1111") {
		t.Errorf("status missing fingerprint AAAA1111: %q", out)
	}
	if !strings.Contains(out, "BBBB2222") {
		t.Errorf("status missing fingerprint BBBB2222: %q", out)
	}
	if !strings.Contains(out, string(keybackup.MethodPaper)) {
		t.Errorf("status missing method paper: %q", out)
	}
	if !strings.Contains(out, string(keybackup.MethodArmoredSymmetric)) {
		t.Errorf("status missing method armored-symmetric: %q", out)
	}
	if !strings.Contains(out, "(stdout)") {
		t.Errorf("status should render empty output path as (stdout): %q", out)
	}
}

// TestKeyBackupModeValidation makes sure the mutually-exclusive flags are
// enforced before we ever spawn a subprocess.
func TestKeyBackupModeValidation(t *testing.T) {
	withFakeHome(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no mode", []string{"backup"}, "pick exactly one"},
		{"two modes", []string{"backup", "--paper", "--armored"}, "pick exactly one"},
		{"symmetric without armored", []string{"backup", "--paper", "--symmetric"}, "only makes sense with --armored"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req string
			cmd := keyCmd(&req)
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("%s: expected error, got nil (out=%q)", tc.name, buf.String())
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestEnsurePaperkey_NonInteractiveReturnsInstallHint verifies that
// when paperkey is missing AND stdin is not a TTY, ensurePaperkey
// returns the crisp install-hint error instead of hanging on an
// unanswerable y/n prompt. Scripted / piped invocations rely on this.
func TestEnsurePaperkey_NonInteractiveReturnsInstallHint(t *testing.T) {
	// Pretend paperkey is missing by shadowing PATH.
	t.Setenv("PATH", t.TempDir())
	prev := isInteractiveStdin
	isInteractiveStdin = func() bool { return false }
	t.Cleanup(func() { isInteractiveStdin = prev })

	var out, errOut bytes.Buffer
	err := ensurePaperkey(t.Context(), &out, bytes.NewReader(nil), &errOut)
	if err == nil {
		t.Fatal("expected error when paperkey missing + non-interactive, got nil")
	}
	if !strings.Contains(err.Error(), "brew install paperkey") {
		t.Errorf("error should name the brew install command, got: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("non-interactive branch must not write explainer text, got: %q", out.String())
	}
}

// TestEnsurePaperkey_InteractiveDecline verifies that an interactive
// user who answers "n" gets the same install-hint error and the brew
// command is NOT invoked.
func TestEnsurePaperkey_InteractiveDecline(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	prev := isInteractiveStdin
	isInteractiveStdin = func() bool { return true }
	t.Cleanup(func() { isInteractiveStdin = prev })

	var out, errOut bytes.Buffer
	// Empty answer = default = n.
	err := ensurePaperkey(t.Context(), &out, strings.NewReader("\n"), &errOut)
	if err == nil {
		t.Fatal("expected error when user declines install, got nil")
	}
	if !strings.Contains(err.Error(), "brew install paperkey") {
		t.Errorf("error should name the brew install command, got: %v", err)
	}
	if !strings.Contains(out.String(), "paperkey") {
		t.Errorf("interactive branch must print the explainer, got: %q", out.String())
	}
}
