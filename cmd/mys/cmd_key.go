package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
		paperRaw  bool
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

  --paper      Runs paperkey on the secret-key export. Output is
               base16 (printable, hand-copiable hex with per-line CRC).
               Add --paper-raw for the compact binary encoding (only
               useful as input to a QR encoder or similar). Use
               --out FILE to save, or pipe into lp / qrencode.

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
				// Paperkey is an optional dependency — offer to install
				// it rather than bouncing the user out with a bare
				// error. Analogous to the pinentry-mac install prompt
				// in `mys init`. Non-interactive sessions (piped stdin
				// or --no-install) skip the prompt and let the
				// existing "not on PATH" error surface.
				if ierr := ensurePaperkey(ctx, cmd.OutOrStdout(), cmd.InOrStdin(), cmd.ErrOrStderr()); ierr != nil {
					writeKeyBackupAudit(ctx, a, *requester, method, fpr, audit.ResultError, ierr.Error())
					return ierr
				}
				format := keybackup.PaperBase16
				if paperRaw {
					format = keybackup.PaperRaw
				}
				err = keybackup.PaperExport(ctx, w, keyID, format)
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
	c.Flags().BoolVar(&paper, "paper", false, "produce a paperkey-encoded backup (needs `paperkey`; default format is base16 / printable)")
	c.Flags().BoolVar(&paperRaw, "paper-raw", false, "use paperkey's compact binary format instead of printable base16 (for QR-encoding etc.)")
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
//
// Safety gate: if the caller did NOT pass --out AND stdout is an
// interactive terminal, refuse. The backup payload is secret-key
// material; dumping it into the user's terminal scrollback defeats
// every other precaution mys takes. On a TTY the operator must pick
// a concrete destination (`--out <file>`) or pipe into something
// (`| lp`, `| qrencode`, …). Scripted/pipe invocations are unaffected.
func openBackupWriter(cmd *cobra.Command, outPath string) (io.Writer, func(), error) {
	if outPath == "" {
		if isStdoutTTY() {
			return nil, func() {}, errors.New(
				"refusing to write secret-key material to an interactive terminal — " +
					"pass `--out <file>` to save to disk, or pipe into a downstream " +
					"command (e.g. `mys key backup --paper | lp` or `| qrencode …`)")
		}
		return cmd.OutOrStdout(), func() {}, nil
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", outPath, err)
	}
	cleanup := func() { _ = f.Close() }
	return f, cleanup, nil
}

// isStdoutTTY reports whether the current process's stdout is a
// terminal. Wrapped as a variable so tests can flip it without
// juggling file descriptors.
var isStdoutTTY = func() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
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

// ensurePaperkey makes sure the `paperkey` binary is on PATH, offering
// to install it via Homebrew if it is missing and the session is
// interactive. Mirrors the pinentry-mac install prompt in `mys init`.
//
// Returns nil if paperkey is already available or was successfully
// installed. Returns an error with an actionable install hint in every
// other case (user declined, brew missing, install failed, …) so the
// caller can surface it verbatim.
func ensurePaperkey(ctx context.Context, out io.Writer, in io.Reader, errOut io.Writer) error {
	if _, err := exec.LookPath("paperkey"); err == nil {
		return nil
	}
	// Skip the prompt if stdin is not an interactive terminal: scripted
	// / piped invocations should still get the crisp "not on PATH"
	// error rather than hang on a y/n question nobody can answer.
	if !isInteractiveStdin() {
		return errors.New("paperkey not on PATH (install with `brew install paperkey`)")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "`paperkey` ist nicht installiert.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "`paperkey` destilliert aus deinem GPG-Secret-Key den minimalen")
	fmt.Fprintln(out, "geheimen Teil — klein genug, um ihn zu drucken oder ins Feuerwehr-")
	fmt.Fprintln(out, "Tresor-Fach zu legen. Ohne Binary kein `--paper`-Backup.")
	fmt.Fprintln(out)
	if _, err := exec.LookPath("brew"); err != nil {
		fmt.Fprintln(out, "`brew` ist nicht auf PATH — Installation wird hier übersprungen.")
		fmt.Fprintln(out, "Installiere Homebrew unter https://brew.sh oder paperkey manuell,")
		fmt.Fprintln(out, "dann re-run `mys key backup --paper`.")
		return errors.New("paperkey not on PATH (install with `brew install paperkey`)")
	}
	br := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "Jetzt `brew install paperkey`? [j/N]: ")
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("read answer: %w", err)
		}
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "", "n", "nein", "no":
			return errors.New("paperkey not on PATH (install with `brew install paperkey`)")
		case "j", "ja", "y", "yes":
			fmt.Fprintln(out, "→ brew install paperkey …")
			cmd := exec.CommandContext(ctx, "brew", "install", "paperkey")
			cmd.Stdout = out
			cmd.Stderr = errOut
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("brew install paperkey failed: %w", err)
			}
			if _, err := exec.LookPath("paperkey"); err != nil {
				return errors.New("paperkey installed via brew but still not on PATH — open a new shell and retry")
			}
			return nil
		default:
			fmt.Fprintln(out, "Bitte j oder n.")
		}
	}
}

// isInteractiveStdin reports whether stdin is attached to a TTY.
// Wrapped as a function so tests can override it.
var isInteractiveStdin = func() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
