package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/keybackup"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// keyCmd builds the `mys key` subcommand tree. The parent exists so we can
// later add sibling sub-commands (rotate, export-pub, …) without reshaping
// the CLI surface.
func keyCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "key",
		Short: "GPG key operations (backup, later: rotate, export-pub)",
		Long: `Commands that operate on the GPG secret key that decrypts the gopass store.

SCOPE: Backups produced here are PERSONAL. They reconstruct the key that
owns the store — never share them with colleagues. Use ` + "`mys bw-export`" + ` for
team sharing instead.`,
	}
	root.AddCommand(keyBackupCmd(requester))
	return root
}

// keyBackupCmd implements `mys key backup` with three mutually-exclusive
// modes: --paper, --armored, --status. Each run writes an audit row and
// (on success, for --paper/--armored) a ledger entry in
// ~/.local/share/my-secrets/backups.json.
func keyBackupCmd(requester *string) *cobra.Command {
	var (
		paper     bool
		armored   bool
		symmetric bool
		status    bool
		keyID     string
		outPath   string
	)
	c := &cobra.Command{
		Use:   "backup",
		Short: "Produce a personal backup of the GPG secret key",
		Long: `Produce a personal backup of the GPG secret key that decrypts the store.

Three modes, exactly one required:

  --paper      Runs paperkey on the secret-key export. Default output is
               stdout ("pipe into lp"); use --out FILE to save.

  --armored    Writes the ASCII-armored secret key. With --symmetric the
               export is additionally wrapped in gpg --symmetric
               (AES256) — safe to carry on a USB stick without the GPG
               agent that wrote it.

  --status     Prints the recorded backups from
               ~/.local/share/my-secrets/backups.json (metadata only —
               never key material).

SCOPE: These backups are PERSONAL. They reconstruct the key that owns
the whole store. Never share them with colleagues — use mys bw-export
for team sharing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Exactly one mode flag.
			modes := 0
			if paper {
				modes++
			}
			if armored {
				modes++
			}
			if status {
				modes++
			}
			if modes != 1 {
				return errors.New("pick exactly one of --paper, --armored, --status")
			}
			if symmetric && !armored {
				return errors.New("--symmetric only makes sense with --armored")
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			if status {
				return runBackupStatus(cmd.OutOrStdout())
			}

			// Open audit-only app: we never touch the gopass store here,
			// so no GPG unlock is triggered by `store.Open`. GPG calls
			// happen only inside the keybackup subprocesses.
			a, err := app.OpenAuditOnly()
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			a.Override = *requester

			method := keybackup.MethodPaper
			if armored {
				if symmetric {
					method = keybackup.MethodArmoredSymmetric
				} else {
					method = keybackup.MethodArmored
				}
			}

			// Resolve the fingerprint up front so we can log it even if the
			// export itself fails. If the user passed --key-id we trust it
			// verbatim and still try to enrich via a lookup for the ledger.
			fpr := keyID
			if fpr == "" {
				resolved, rerr := keybackup.ResolveFingerprint(ctx)
				if rerr != nil {
					writeKeyBackupAudit(ctx, a, *requester, method, "", audit.ResultError, rerr.Error())
					return rerr
				}
				fpr = resolved
			}

			// Open destination writer.
			w, cleanup, err := openBackupWriter(cmd, outPath)
			if err != nil {
				writeKeyBackupAudit(ctx, a, *requester, method, fpr, audit.ResultError, err.Error())
				return err
			}
			defer cleanup()

			// Passphrase for symmetric mode.
			var passphrase string
			if symmetric {
				pp, perr := readSymmetricPassphrase(cmd.ErrOrStderr())
				if perr != nil {
					writeKeyBackupAudit(ctx, a, *requester, method, fpr, audit.ResultError, perr.Error())
					return perr
				}
				passphrase = pp
			}

			switch {
			case paper:
				err = keybackup.PaperExport(ctx, w, keyID)
			case armored:
				err = keybackup.ArmoredExport(ctx, w, keyID, symmetric, passphrase)
			}
			if err != nil {
				writeKeyBackupAudit(ctx, a, *requester, method, fpr, audit.ResultError, err.Error())
				return err
			}

			// Success: record ledger row (metadata only).
			rec := keybackup.BackupRecord{
				Method:      method,
				Fingerprint: fpr,
				OutputPath:  outPath,
			}
			if lerr := keybackup.AppendRecord(rec); lerr != nil {
				// Log a warning but do not fail — the backup is written.
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not record backup ledger: %v\n", lerr)
			}
			writeKeyBackupAudit(ctx, a, *requester, method, fpr, audit.ResultOK,
				fmt.Sprintf("method=%s fingerprint=%s", method, fpr))
			if outPath != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "backup method=%s fingerprint=%s written to %s\n",
					method, fpr, outPath)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&paper, "paper", false, "produce a paperkey-encoded backup (needs `paperkey`)")
	c.Flags().BoolVar(&armored, "armored", false, "produce an ASCII-armored secret-key backup")
	c.Flags().BoolVar(&symmetric, "symmetric", false, "wrap --armored output in gpg --symmetric (AES256)")
	c.Flags().BoolVar(&status, "status", false, "list recorded backups (metadata only) and exit")
	c.Flags().StringVar(&keyID, "key-id", "", "GPG key ID / fingerprint / email (default: first secret key)")
	c.Flags().StringVar(&outPath, "out", "", "destination file (default: stdout)")
	return c
}

// openBackupWriter returns a writer for the backup payload plus a cleanup
// function. An empty path streams to stdout. Files are created 0600, with
// O_EXCL to avoid silently overwriting an existing backup.
func openBackupWriter(cmd *cobra.Command, outPath string) (io.Writer, func(), error) {
	if outPath == "" {
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", outPath, err)
	}
	cleanup := func() { _ = f.Close() }
	return f, cleanup, nil
}

// readSymmetricPassphrase obtains the AES passphrase. When stdin is piped
// we read the first line (no TTY, no prompt, no confirmation — the caller
// has already committed). On a TTY we prompt twice without echo and insist
// on a match.
func readSymmetricPassphrase(errOut io.Writer) (string, error) {
	fi, _ := os.Stdin.Stat()
	isPiped := (fi.Mode() & os.ModeCharDevice) == 0
	if isPiped {
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", errors.New("empty passphrase on stdin")
		}
		return line, nil
	}
	// Interactive: prompt twice, no echo.
	fmt.Fprint(errOut, "passphrase: ")
	first, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(errOut)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(first) == 0 {
		return "", errors.New("empty passphrase")
	}
	fmt.Fprint(errOut, "confirm:    ")
	second, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(errOut)
	if err != nil {
		return "", fmt.Errorf("read confirmation: %w", err)
	}
	if string(first) != string(second) {
		return "", errors.New("passphrase confirmation did not match")
	}
	return string(first), nil
}

// runBackupStatus prints the ledger. Empty ledger is not an error.
func runBackupStatus(w io.Writer) error {
	records, err := keybackup.List()
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(w, "no backups recorded yet")
		return nil
	}
	for _, r := range records {
		out := r.OutputPath
		if out == "" {
			out = "(stdout)"
		}
		fmt.Fprintf(w, "%s  method=%s  fingerprint=%s  output=%s\n",
			r.Timestamp.Format("2006-01-02 15:04:05"), r.Method, r.Fingerprint, out)
	}
	return nil
}

// writeKeyBackupAudit writes a key_backup audit row.
func writeKeyBackupAudit(ctx context.Context, a *app.App, override string, method keybackup.Method,
	fingerprint, result, reason string) {
	if a == nil || a.Audit == nil {
		return
	}
	d := caller.Identify(override)
	detail, _ := json.Marshal(d)
	r := reason
	if r == "" {
		r = fmt.Sprintf("method=%s fingerprint=%s", method, fingerprint)
	}
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      audit.ActionKeyBackup,
		SecretPath:  "",
		Org:         "",
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      r,
	})
}
