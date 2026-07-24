package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/spf13/cobra"
)

// bwImportCmd builds the `mys bw-import` subcommand.
func bwImportCmd(requester *string) *cobra.Command {
	var opts bwImportOptions
	c := &cobra.Command{
		Use:   "bw-import",
		Short: "Diff the Bitwarden mys/ namespace against the store and selectively import changes",
		Args:  cobra.NoArgs,
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

With --org <source> --mount <shared-target>, canonical source paths are
rebased into an explicitly configured shared mount. The command pulls the
mount before reading Bitwarden and performs one shared sync after the batch.

Session handling matches bw-push (inherited BW_SESSION or unlock via the
master password from the store). AI callers cannot invoke this command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := validateBwImportSyntax(opts); err != nil {
				return err
			}
			// Deny AI-flagged callers outright — with a forensic audit
			// row, same contract as bw-push: a channel that writes vault
			// content into the store is exactly what an AI caller must
			// never trigger.
			detected := caller.Identify(*requester)
			if detected.Kind == caller.KindAI {
				if aa, aerr := openAuditOnly(); aerr == nil {
					aa.Override = *requester
					aa.AuditBWImport(ctx, bwImportAuditOrg(opts),
						audit.ResultDenied, "bw-import refused for AI caller")
					_ = aa.Close(ctx)
				}
				return fmt.Errorf("bw-import is refused for AI callers")
			}
			if opts.Mount != "" {
				syncConfig, err := syncpkg.Load("")
				if err != nil {
					return err
				}
				opts.SyncConfig = syncConfig
			}
			if err := validateBwImportOptions(opts); err != nil {
				return err
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
			if opts.Mount != "" {
				releaseMount, lockErr := syncpkg.AcquireMountLock(ctx, opts.Mount)
				if lockErr != nil {
					return lockErr
				}
				defer func() { _ = releaseMount() }()
				opts.SyncRunner = syncpkg.ExecRunner{}
			}
			a, err := app.Open(ctx, *requester)
			if err != nil {
				return err
			}
			defer a.Close(ctx)
			return runBwImport(ctx, a, bw.NewClient(nil), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}
	c.Flags().StringVar(&opts.Org, "org", "", "import only this org")
	c.Flags().StringVar(&opts.Mount, "mount", "",
		"write one --org namespace into this explicitly shared mount")
	c.Flags().BoolVar(&opts.Apply, "apply", false, "apply NEW/CHANGED rows to the store after per-item confirmation")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "with --apply: take every NEW/CHANGED row without prompting")
	return c
}

// bwImportOptions carries the flag and environment inputs of one import run.
type bwImportOptions struct {
	Org        string
	Mount      string
	Apply      bool
	Yes        bool
	Session    string
	Config     *bw.Config
	SyncConfig *syncpkg.Config
	SyncRunner syncpkg.Runner
	// Interactive marks stdin as a real TTY. RunE derives it from
	// os.Stdin; tests set it to drive the per-item prompt through an
	// injected reader.
	Interactive bool
}

func validateBwImportSyntax(opts bwImportOptions) error {
	if opts.Org != strings.TrimSpace(opts.Org) ||
		strings.ContainsAny(opts.Org, `/\`+"\x00\r\n") ||
		opts.Org == "." || opts.Org == ".." {
		return fmt.Errorf("--org must be a top-level org name (no '/'): %q", opts.Org)
	}
	if opts.Mount == "" {
		return nil
	}
	if opts.Org == "" {
		return errors.New("--mount requires --org")
	}
	if err := syncpkg.ValidateSharedMountName(opts.Mount); err != nil {
		return err
	}
	return nil
}

func validateBwImportOptions(opts bwImportOptions) error {
	if err := validateBwImportSyntax(opts); err != nil {
		return err
	}
	if opts.Mount != "" &&
		(opts.SyncConfig == nil || !opts.SyncConfig.IsSharedMount(opts.Mount)) {
		return fmt.Errorf("mount %q is not configured as shared", opts.Mount)
	}
	return nil
}

func bwImportAuditOrg(opts bwImportOptions) string {
	if opts.Mount != "" {
		return opts.Mount
	}
	return opts.Org
}

func bwImportScopeSummary(opts bwImportOptions) string {
	if opts.Mount == "" {
		return ""
	}
	return fmt.Sprintf(" source_org=%s target_mount=%s", opts.Org, opts.Mount)
}

// runBwImport resolves the session, diffs the vault namespace against
// the store and (on --apply) writes confirmed rows through the audited
// app layer. Split from RunE so tests can drive it with a fake store
// and a fake bw runner.
func runBwImport(ctx context.Context, a *app.App, c *bw.Client, stdin io.Reader, stdout, stderr io.Writer, opts bwImportOptions) error {
	if err := validateBwImportOptions(opts); err != nil {
		return err
	}
	bwConfig := opts.Config
	if bwConfig == nil {
		bwConfig = &bw.Config{}
	}
	auditOrg := bwImportAuditOrg(opts)
	// fail audits an early abort under bw_import so failed attempts are
	// reconstructable from the log. The reason carries only OUR stage
	// label, never err.Error(): bw's stderr is embedded in those errors
	// and a third-party binary's stderr must not end up verbatim in the
	// persistent audit DB. The full error still reaches the caller (and
	// the CLI's own ephemeral stderr).
	fail := func(stage string, err error) error {
		a.AuditBWImport(ctx, auditOrg, audit.ResultError,
			stage+" failed"+bwImportScopeSummary(opts))
		return err
	}
	if opts.Mount != "" {
		a.SuppressAutoSync = true
		if _, err := syncpkg.GopassMountPath(
			ctx, opts.SyncRunner, opts.Mount,
		); err != nil {
			return fail("shared mount validation", err)
		}
		if _, err := syncpkg.GopassGitPull(
			ctx, opts.SyncRunner, opts.Mount,
		); err != nil {
			return fail("shared pull", err)
		}
	}
	// Pin the server BEFORE anything touches the master password: a bw
	// CLI pointed at the wrong server must not even trigger the audited
	// password read, let alone an unlock. `bw status` works unlocked.
	st, err := c.Status(ctx)
	if err != nil {
		return fail("bw status", err)
	}
	if bwConfig.ServerURL != "" && st.ServerURL != bwConfig.ServerURL {
		a.AuditBWImport(ctx, auditOrg, audit.ResultError,
			"server mismatch"+bwImportScopeSummary(opts))
		return fmt.Errorf(
			"server mismatch: bw is configured for %s, expected %s — refusing to import",
			st.ServerURL, bwConfig.ServerURL)
	}
	// The master password is fetched through the audited app layer like
	// any other secret — its read shows up in the audit log.
	getPassword := func(ctx context.Context) (string, error) {
		e, err := a.Get(ctx, bwConfig.PasswordPath())
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

	storeScope := opts.Org
	if opts.Mount != "" {
		storeScope = opts.Mount
	}
	paths, err := a.List(ctx, storeScope)
	if err != nil {
		return fail("store list", err)
	}
	storeEntries := make(map[string]*store.Entry, len(paths))
	for _, p := range paths {
		// The vault's unlock secret never participates in the mirror —
		// bw-push refuses to write it out, and the reverse channel must
		// not drag it into the diff either.
		if p == bwConfig.PasswordPath() {
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
	preWarnings := make([]string, 0)
	// Policy-invisible paths stay invisible in the diff too: a caller
	// whose scope policy hides an org must not learn that org's paths
	// from the vault side either. The count-only warning deliberately
	// names no paths. (App.Add would refuse the write anyway — this
	// keeps the read surface consistent with the store's.)
	det := caller.Identify(a.Override)
	visible := remote.Items[:0]
	hidden := 0
	for _, it := range remote.Items {
		sourcePath := bw.PathForItem(it, remote.FolderNames[it.FolderID])
		if opts.Org != "" && !strings.HasPrefix(sourcePath, opts.Org+"/") {
			// Keep out-of-scope items for BuildImportDiffForTarget to
			// discard without warnings or policy-visible counts.
			visible = append(visible, it)
			continue
		}
		targetPath, mapErr := bw.RebaseImportPath(
			sourcePath, opts.Org, opts.Mount)
		// The unlock secret is protected in both namespaces: checking
		// before and after the rebase prevents a target mount named
		// "private" from receiving it under its canonical path.
		if sourcePath == bwConfig.PasswordPath() ||
			(mapErr == nil && targetPath == bwConfig.PasswordPath()) {
			preWarnings = append(preWarnings,
				"the vault's master password is never imported")
			continue
		}
		if mapErr != nil {
			// BuildImportDiffForTarget emits one sanitized warning.
			visible = append(visible, it)
			continue
		}
		if !a.Policy.Evaluate(
			string(det.Kind), det.AgentLabel, targetPath,
		).Allowed {
			hidden++
			continue
		}
		visible = append(visible, it)
	}
	remote.Items = visible
	if hidden > 0 {
		fmt.Fprintf(stderr, "warning: %d vault item(s) policy-invisible for this caller — skipped\n", hidden)
	}
	diffs, inSync, warnings, err := bw.BuildImportDiffForTarget(
		storeEntries, remote, opts.Org, opts.Mount)
	if err != nil {
		return fail("diff mapping", err)
	}
	warnings = append(preWarnings, warnings...)
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
	counts += bwImportScopeSummary(opts)
	if !opts.Apply {
		a.AuditBWImport(ctx, auditOrg, audit.ResultOK, "diff-only "+counts)
		if news+changed > 0 {
			fmt.Fprintln(stdout, "diff only — re-run with --apply to import")
		}
		return nil
	}
	if news+changed == 0 {
		a.AuditBWImport(ctx, auditOrg, audit.ResultOK, "no-op "+counts)
		fmt.Fprintln(stdout, "store already in sync — nothing to import")
		return nil
	}
	if !opts.Yes && !opts.Interactive {
		a.AuditBWImport(ctx, auditOrg, audit.ResultDenied,
			"aborted: non-interactive without --yes "+counts)
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
				a.AuditBWImport(ctx, auditOrg, audit.ResultError,
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
		// App.Add restamps RotatedAt — accepted: the dominant import
		// case IS a credential rotated on the phone, and Add is the
		// only audited full-entry write path. A metadata-only apply
		// thus reads as freshly rotated; the gopass git history keeps
		// the precise record.
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
	var finalErrors []error
	if failed > 0 {
		finalErrors = append(finalErrors,
			fmt.Errorf("%d of %d writes failed", failed, applied+failed))
	}
	syncStage := ""
	if opts.Mount != "" && applied > 0 {
		if err := syncpkg.SyncSharedMountWithRetry(
			ctx, opts.SyncRunner, opts.SyncConfig, opts.Mount,
		); err != nil {
			syncStage = "shared sync failed"
			finalErrors = append(finalErrors, err)
		} else {
			current, err := syncpkg.MarkSharedSyncedAndSave(
				ctx, "", opts.Mount, time.Now().UTC(),
			)
			if err != nil {
				syncStage = "shared sync state save failed"
				finalErrors = append(finalErrors, err)
			} else {
				*opts.SyncConfig = *current
			}
		}
	}
	if len(finalErrors) > 0 {
		stage := "apply failed"
		if failed == 0 {
			stage = syncStage
		} else if syncStage != "" {
			stage += " and " + syncStage
		}
		a.AuditBWImport(ctx, auditOrg, audit.ResultError, stage+" "+result)
		return errors.Join(finalErrors...)
	}
	a.AuditBWImport(ctx, auditOrg, audit.ResultOK, result)
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
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		switch strings.TrimSpace(line) {
		case "y", "n", "a", "q":
			return strings.TrimSpace(line), nil
		}
		if err != nil { // EOF without a valid answer
			fmt.Fprintln(out)
			return "q", nil
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
