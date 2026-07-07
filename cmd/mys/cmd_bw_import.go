package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/spf13/cobra"
)

// bwImportCmd builds the `mys bw-import` subcommand.
func bwImportCmd(requester *string) *cobra.Command {
	var opts bwImportOptions
	c := &cobra.Command{
		Use:   "bw-import",
		Short: "Diff the Bitwarden mys/ namespace against the store and selectively import changes",
		Long: `Compares the items in your Bitwarden mys/* folders (the bw-push mirror
namespace) against the store and shows what changed on the Bitwarden side —
e.g. a password rotated on the phone, or an item newly created in a mys/<org>
folder. Nothing outside the mys/* namespace is ever read.

Default mode is diff-only: a table of paths, diff classes and changed field
NAMES (never values), with zero writes on either side. --apply walks the
NEW and CHANGED rows with a per-item confirmation (y/n/a/q); --apply --yes
takes all of them. CHANGED rows overwrite exactly the changed fields;
STORE-ONLY rows are informational — the reverse channel never deletes store
entries, and Bitwarden is never written to.

Session handling matches bw-push (inherited BW_SESSION or unlock via the
master password from the store). AI callers cannot invoke this command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Nested prefixes like "jasp/stage" would make the store
			// filter and the mys/<org> folder mapping diverge silently.
			if strings.Contains(opts.Org, "/") {
				return fmt.Errorf("--org must be a top-level org name (no '/'): %q", opts.Org)
			}
			// Deny AI-flagged callers outright — with a forensic audit
			// row, same contract as bw-push: a channel that writes vault
			// content into the store is exactly what an AI caller must
			// never trigger.
			detected := caller.Identify(*requester)
			if detected.Kind == caller.KindAI {
				if aa, aerr := openAuditOnly(); aerr == nil {
					aa.Override = *requester
					aa.AuditBWImport(ctx, opts.Org, audit.ResultDenied, "bw-import refused for AI caller")
					_ = aa.Close(ctx)
				}
				return fmt.Errorf("bw-import is refused for AI callers")
			}
			cfg, err := bw.LoadConfig("")
			if err != nil {
				return err
			}
			opts.Config = cfg
			opts.Session = os.Getenv("BW_SESSION")
			opts.Interactive = isTerminalStdin(cmd.InOrStdin())
			release, err := bw.AcquireLock("")
			if err != nil {
				return err
			}
			defer release()
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return runBwImport(ctx, a, bw.NewClient(nil), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}
	c.Flags().StringVar(&opts.Org, "org", "", "import only this org")
	c.Flags().BoolVar(&opts.Apply, "apply", false, "apply NEW/CHANGED rows to the store after per-item confirmation")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "with --apply: take every NEW/CHANGED row without prompting")
	return c
}

// bwImportOptions carries the flag and environment inputs of one import run.
type bwImportOptions struct {
	Org     string
	Apply   bool
	Yes     bool
	Session string
	Config  *bw.Config
	// Interactive marks stdin as a real TTY. RunE derives it from
	// os.Stdin; tests set it to drive the per-item prompt through an
	// injected reader.
	Interactive bool
}

// runBwImport resolves the session, diffs the vault namespace against
// the store and (on --apply) writes confirmed rows through the audited
// app layer. Split from RunE so tests can drive it with a fake store
// and a fake bw runner.
func runBwImport(ctx context.Context, a *app.App, c *bw.Client, stdin io.Reader, stdout, stderr io.Writer, opts bwImportOptions) error {
	cfg := opts.Config
	if cfg == nil {
		cfg = &bw.Config{}
	}
	// fail audits an early abort under bw_import so failed attempts are
	// reconstructable from the log. The reason carries only OUR stage
	// label, never err.Error(): bw's stderr is embedded in those errors
	// and a third-party binary's stderr must not end up verbatim in the
	// persistent audit DB. The full error still reaches the caller (and
	// the CLI's own ephemeral stderr).
	fail := func(stage string, err error) error {
		a.AuditBWImport(ctx, opts.Org, audit.ResultError, stage+" failed")
		return err
	}
	// Pin the server BEFORE anything touches the master password: a bw
	// CLI pointed at the wrong server must not even trigger the audited
	// password read, let alone an unlock. `bw status` works unlocked.
	st, err := c.Status(ctx)
	if err != nil {
		return fail("bw status", err)
	}
	if cfg.ServerURL != "" && st.ServerURL != cfg.ServerURL {
		reason := fmt.Sprintf("server mismatch: bw is configured for %s, expected %s", st.ServerURL, cfg.ServerURL)
		a.AuditBWImport(ctx, opts.Org, audit.ResultError, reason)
		return fmt.Errorf("%s — refusing to import", reason)
	}
	// The master password is fetched through the audited app layer like
	// any other secret — its read shows up in the audit log.
	getPassword := func(ctx context.Context) (string, error) {
		e, err := a.Get(ctx, cfg.PasswordPath())
		if err != nil {
			return "", err
		}
		return e.Password, nil
	}
	if _, err := c.EnsureSession(ctx, opts.Session, getPassword); err != nil {
		return fail("session setup", err)
	}
	if err := c.Sync(ctx); err != nil {
		return fail("bw sync", err)
	}

	paths, err := a.List(ctx, opts.Org)
	if err != nil {
		return fail("store list", err)
	}
	storeEntries := make(map[string]*store.Entry, len(paths))
	for _, p := range paths {
		// The vault's unlock secret never participates in the mirror —
		// bw-push refuses to write it out, and the reverse channel must
		// not drag it into the diff either.
		if p == cfg.PasswordPath() {
			continue
		}
		e, err := a.Get(ctx, p)
		if err != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", p, err)
			continue
		}
		storeEntries[p] = e
	}

	remote, err := bw.FetchRemoteState(ctx, c)
	if err != nil {
		return fail("vault read", err)
	}
	diffs, inSync, warnings := bw.BuildImportDiff(storeEntries, remote, opts.Org)
	// A vault item claiming the master-password path must never reach an
	// apply: it could overwrite the very secret that unlocks the vault.
	kept := diffs[:0]
	for _, d := range diffs {
		if d.Path == cfg.PasswordPath() {
			warnings = append(warnings, d.Path+": the vault's master password is never imported")
			continue
		}
		kept = append(kept, d)
	}
	diffs = kept
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	printImportDiff(stdout, st, diffs, inSync)

	var news, changed, storeOnly int
	for _, d := range diffs {
		switch d.Class {
		case bw.ClassNew:
			news++
		case bw.ClassChanged:
			changed++
		case bw.ClassStoreOnly:
			storeOnly++
		}
	}
	// warnings= keeps skipped items visible in the audit trail — a clean
	// row must not read as "full diff shown" when items were skipped.
	counts := fmt.Sprintf("server=%s new=%d changed=%d store_only=%d in_sync=%d warnings=%d",
		st.ServerURL, news, changed, storeOnly, inSync, len(warnings))
	if !opts.Apply {
		a.AuditBWImport(ctx, opts.Org, audit.ResultOK, "diff-only "+counts)
		if news+changed > 0 {
			fmt.Fprintln(stdout, "diff only — re-run with --apply to import")
		}
		return nil
	}
	if news+changed == 0 {
		a.AuditBWImport(ctx, opts.Org, audit.ResultOK, "no-op "+counts)
		fmt.Fprintln(stdout, "store already in sync — nothing to import")
		return nil
	}
	if !opts.Yes && !opts.Interactive {
		a.AuditBWImport(ctx, opts.Org, audit.ResultDenied, "aborted: non-interactive without --yes "+counts)
		return fmt.Errorf("non-interactive stdin: pass --yes to apply without prompting")
	}

	applied, failed := 0, 0
	applyAll := opts.Yes
	reader := bufio.NewReader(stdin)
apply:
	for _, d := range diffs {
		if d.Class == bw.ClassStoreOnly {
			continue
		}
		if !applyAll {
			answer, perr := promptApply(reader, stdout, d)
			if perr != nil {
				a.AuditBWImport(ctx, opts.Org, audit.ResultError,
					fmt.Sprintf("confirmation read failed after applied=%d failed=%d %s", applied, failed, counts))
				return perr
			}
			switch answer {
			case "n":
				continue
			case "q":
				break apply
			case "a":
				applyAll = true
			}
		}
		entry := d.Incoming
		if d.Class == bw.ClassChanged {
			entry = bw.MergeEntry(storeEntries[d.Path], d.Incoming, d.Changed)
		}
		if err := a.Add(ctx, entry); err != nil {
			fmt.Fprintf(stderr, "failed %s: %v\n", d.Path, err)
			failed++
			continue
		}
		applied++
		fmt.Fprintf(stdout, "  imported %s\n", d.Path)
	}
	skipped := news + changed - applied - failed
	result := fmt.Sprintf("applied=%d skipped=%d failed=%d %s", applied, skipped, failed, counts)
	if failed > 0 {
		a.AuditBWImport(ctx, opts.Org, audit.ResultError, result)
		return fmt.Errorf("%d of %d writes failed", failed, applied+failed)
	}
	a.AuditBWImport(ctx, opts.Org, audit.ResultOK, result)
	fmt.Fprintf(stdout, "imported: %d applied, %d skipped\n", applied, skipped)
	return nil
}

// promptApply asks for one row's import decision and returns "y", "n",
// "a" (this and all remaining) or "q" (skip this and all remaining).
// EOF counts as quit — never as consent.
func promptApply(r *bufio.Reader, out io.Writer, d bw.ImportDiff) (string, error) {
	label := d.Path
	if d.Class == bw.ClassChanged {
		label = fmt.Sprintf("%s (%s)", d.Path, strings.Join(d.Changed, ", "))
	}
	for {
		fmt.Fprintf(out, "import %s %s? [y/n/a/q] ", d.Class, label)
		line, err := r.ReadString('\n')
		switch strings.TrimSpace(line) {
		case "y", "n", "a", "q":
			return strings.TrimSpace(line), nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(out)
				return "q", nil
			}
			return "", err
		}
		fmt.Fprintln(out, "answer y (import), n (skip), a (all remaining), q (quit)")
	}
}

// printImportDiff renders the diff table — paths, classes and changed
// field names only, never values.
func printImportDiff(w io.Writer, st bw.Status, diffs []bw.ImportDiff, inSync int) {
	fmt.Fprintf(w, "Bitwarden import diff (server %s, user %s):\n", st.ServerURL, st.UserEmail)
	for _, d := range diffs {
		switch d.Class {
		case bw.ClassNew:
			fmt.Fprintf(w, "  %-11s %s\n", d.Class, d.Path)
		case bw.ClassChanged:
			fmt.Fprintf(w, "  %-11s %s (%s)\n", d.Class, d.Path, strings.Join(d.Changed, ", "))
		case bw.ClassStoreOnly:
			fmt.Fprintf(w, "  %-11s %s (informational — never deleted)\n", d.Class, d.Path)
		}
	}
	fmt.Fprintf(w, "  %d in sync\n", inSync)
}
