package main

import (
	"context"
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

// bwPushCmd builds the `mys bw-push` subcommand.
func bwPushCmd(requester *string) *cobra.Command {
	var opts bwPushOptions
	c := &cobra.Command{
		Use:   "bw-push",
		Short: "Mirror the store one-way into the Bitwarden mys/ folder namespace",
		Long: `Mirrors the store (or one org) into your Bitwarden vault via the bw CLI.
One-way: mys stays the source of truth; Bitwarden is a read consumer.

All mirrored items live in dedicated "mys/<org>" folders and are matched by
their "mys-path" custom field, so repeated pushes are idempotent and nothing
outside the mys/* namespace is ever read or touched.

Session: an inherited BW_SESSION is used when valid; otherwise the vault is
unlocked with the master password read from the store (default path
` + bw.DefaultMasterPasswordPath + `, configurable in ~/.config/my-secrets/bw.yaml
via master_password_path; server_url pins the expected server). Run
"bw login" once per machine beforehand — login is never automated.

--prune moves items whose mys-path no longer exists in the store to the
Bitwarden trash (soft delete only). AI callers cannot invoke this command.`,
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
			// row, same contract as bw-export: a bulk mirror of the
			// store is exactly what an AI caller must never trigger.
			detected := caller.Identify(*requester)
			if detected.Kind == caller.KindAI {
				if aa, aerr := openAuditOnly(); aerr == nil {
					aa.Override = *requester
					aa.AuditBWPush(ctx, opts.Org, audit.ResultDenied, "bw-push refused for AI caller")
					_ = aa.Close(ctx)
				}
				return fmt.Errorf("bw-push is refused for AI callers")
			}
			cfg, err := bw.LoadConfig("")
			if err != nil {
				return err
			}
			opts.Config = cfg
			opts.Session = os.Getenv("BW_SESSION")
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
			return runBwPush(ctx, a, bw.NewClient(nil), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}
	c.Flags().StringVar(&opts.Org, "org", "", "mirror only this org")
	c.Flags().BoolVar(&opts.DryRun, "dry-run", false, "print the plan without writing to Bitwarden")
	c.Flags().BoolVar(&opts.Prune, "prune", false, "move items whose mys-path left the store to the Bitwarden trash")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "skip the interactive confirmation")
	return c
}

// bwPushOptions carries the flag and environment inputs of one push run.
type bwPushOptions struct {
	Org     string
	DryRun  bool
	Prune   bool
	Yes     bool
	Session string
	Config  *bw.Config
}

// runBwPush resolves the session, diffs store against vault namespace
// and applies the plan. Split from RunE so tests can drive it with a
// fake store and a fake bw runner.
func runBwPush(ctx context.Context, a *app.App, c *bw.Client, stdin io.Reader, stdout, stderr io.Writer, opts bwPushOptions) error {
	cfg := opts.Config
	if cfg == nil {
		cfg = &bw.Config{}
	}
	// fail audits an early abort under bw_push so failed attempts are
	// reconstructable from the log. The reason carries only OUR stage
	// label, never err.Error(): bw's stderr is embedded in those errors
	// and a third-party binary's stderr must not end up verbatim in the
	// persistent audit DB. The full error still reaches the caller (and
	// the CLI's own ephemeral stderr).
	fail := func(stage string, err error) error {
		a.AuditBWPush(ctx, opts.Org, audit.ResultError, stage+" failed")
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
		a.AuditBWPush(ctx, opts.Org, audit.ResultError, reason)
		return fmt.Errorf("%s — refusing to push", reason)
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
	entries := make([]*store.Entry, 0, len(paths))
	for _, p := range paths {
		// The vault's own unlock secret must never be mirrored into the
		// vault it unlocks: Emergency Access or a vault export would
		// hand out the master password itself.
		if p == cfg.PasswordPath() {
			continue
		}
		e, err := a.Get(ctx, p)
		if err != nil {
			fmt.Fprintf(stderr, "skip %s: %v\n", p, err)
			continue
		}
		entries = append(entries, e)
	}
	// Prune safety net: judge "gone from the store" against the FULL
	// path list, not the --org slice, so a mirror item whose entry still
	// exists can never be trashed by a filtered run.
	storePaths := map[string]bool{}
	allPaths := paths
	if opts.Org != "" {
		if allPaths, err = a.List(ctx, ""); err != nil {
			return fail("store list", err)
		}
	}
	for _, p := range allPaths {
		storePaths[p] = true
	}
	// Deliberately absent from the prune safety net: if an earlier run
	// (or a hand copy) put the master password into the mirror, --prune
	// heals that by trashing it even though the store entry exists.
	delete(storePaths, cfg.PasswordPath())

	remote, err := bw.FetchRemoteState(ctx, c)
	if err != nil {
		return fail("vault read", err)
	}
	// Policy-invisible paths count as "still present": a caller whose
	// scope policy hides an org sees its paths missing from List — that
	// must never let --prune trash the org's mirror items.
	det := caller.Identify(a.Override)
	for _, it := range remote.Items {
		p := bw.PathOf(it)
		if p == "" || storePaths[p] {
			continue
		}
		if !a.Policy.Evaluate(string(det.Kind), det.AgentLabel, p).Allowed {
			storePaths[p] = true
			fmt.Fprintf(stderr, "warning: %s is policy-invisible for this caller — its mirror item is left alone\n", p)
		}
	}
	plan := bw.BuildPushPlan(entries, storePaths, remote, opts.Prune, opts.Org)
	for _, w := range plan.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	printPushPlan(stdout, st, plan)

	// warnings= keeps skipped entries visible in the audit trail — a
	// no-op row must not read as "everything mirrored cleanly" when
	// entries were skipped.
	counts := fmt.Sprintf("server=%s create=%d update=%d prune=%d unchanged=%d warnings=%d",
		st.ServerURL, len(plan.Creates), len(plan.Updates), len(plan.Prunes), plan.Unchanged, len(plan.Warnings))
	if opts.DryRun {
		a.AuditBWPush(ctx, opts.Org, audit.ResultOK, "dry-run "+counts)
		fmt.Fprintln(stdout, "dry-run: no changes written")
		return nil
	}
	if !plan.HasWrites() {
		a.AuditBWPush(ctx, opts.Org, audit.ResultOK, "no-op "+counts)
		fmt.Fprintln(stdout, "vault already in sync — nothing to do")
		return nil
	}
	fmt.Fprintf(stdout, "push %d create / %d update / %d prune to %s as %s? [y/N] ",
		len(plan.Creates), len(plan.Updates), len(plan.Prunes), st.ServerURL, st.UserEmail)
	ok, err := confirmAdd(stdin, stdout, opts.Yes)
	if err != nil {
		return err
	}
	if !ok {
		a.AuditBWPush(ctx, opts.Org, audit.ResultDenied, "aborted at confirmation "+counts)
		return fmt.Errorf("aborted")
	}
	res, err := bw.ExecutePush(ctx, c, plan, remote)
	if err != nil {
		// Counts only, no err text — see the fail() comment above.
		a.AuditBWPush(ctx, opts.Org, audit.ResultError,
			fmt.Sprintf("push failed after folders=%d created=%d updated=%d pruned=%d", res.CreatedFolders, res.Created, res.Updated, res.Pruned))
		return err
	}
	a.AuditBWPush(ctx, opts.Org, audit.ResultOK, counts)
	fmt.Fprintf(stdout, "pushed: %d created, %d updated, %d pruned (%d unchanged)\n",
		res.Created, res.Updated, res.Pruned, plan.Unchanged)
	return nil
}

// printPushPlan renders the decision set — paths only, never values.
func printPushPlan(w io.Writer, st bw.Status, plan bw.PushPlan) {
	fmt.Fprintf(w, "Bitwarden mirror plan (server %s, user %s):\n", st.ServerURL, st.UserEmail)
	for _, c := range plan.CreateFolders {
		fmt.Fprintf(w, "  + folder %s\n", c)
	}
	for _, c := range plan.Creates {
		fmt.Fprintf(w, "  + %s\n", c.Path)
	}
	for _, u := range plan.Updates {
		fmt.Fprintf(w, "  ~ %s\n", u.Path)
	}
	for _, p := range plan.Prunes {
		fmt.Fprintf(w, "  - %s (to trash)\n", p.Path)
	}
	fmt.Fprintf(w, "  %d unchanged", plan.Unchanged)
	if plan.Foreign > 0 {
		fmt.Fprintf(w, ", %d foreign items in mys/* left untouched", plan.Foreign)
	}
	fmt.Fprintln(w)
}
