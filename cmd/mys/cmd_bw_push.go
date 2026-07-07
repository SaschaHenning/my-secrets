package main

import (
	"context"
	"fmt"
	"io"
	"os"

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
	// The master password is fetched through the audited app layer like
	// any other secret — its read shows up in the audit log.
	getPassword := func(ctx context.Context) (string, error) {
		e, err := a.Get(ctx, cfg.PasswordPath())
		if err != nil {
			return "", err
		}
		return e.Password, nil
	}
	if err := c.EnsureSession(ctx, opts.Session, getPassword); err != nil {
		return err
	}
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if cfg.ServerURL != "" && st.ServerURL != cfg.ServerURL {
		reason := fmt.Sprintf("server mismatch: bw is configured for %s, expected %s", st.ServerURL, cfg.ServerURL)
		a.AuditBWPush(ctx, opts.Org, audit.ResultError, reason)
		return fmt.Errorf("%s — refusing to push", reason)
	}
	if err := c.Sync(ctx); err != nil {
		return err
	}

	paths, err := a.List(ctx, opts.Org)
	if err != nil {
		return err
	}
	entries := make([]*store.Entry, 0, len(paths))
	for _, p := range paths {
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
			return err
		}
	}
	for _, p := range allPaths {
		storePaths[p] = true
	}

	remote, err := bw.FetchRemoteState(ctx, c, opts.Org)
	if err != nil {
		return err
	}
	plan := bw.BuildPushPlan(entries, storePaths, remote, opts.Prune)
	for _, w := range plan.Warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	printPushPlan(stdout, st, plan)

	counts := fmt.Sprintf("server=%s create=%d update=%d prune=%d unchanged=%d",
		st.ServerURL, len(plan.Creates), len(plan.Updates), len(plan.Prunes), plan.Unchanged)
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
		a.AuditBWPush(ctx, opts.Org, audit.ResultError,
			fmt.Sprintf("failed after folders=%d created=%d updated=%d pruned=%d: %v", res.CreatedFolders, res.Created, res.Updated, res.Pruned, err))
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
