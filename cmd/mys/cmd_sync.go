package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/spf13/cobra"
)

// Audit action names for sync operations. Aliases for the exported
// constants in the audit package, kept to minimise diff noise in the
// rest of this file.
const (
	actionSyncSetup = audit.ActionSyncSetup
	actionSyncPush  = audit.ActionSyncPush
	actionSyncPull  = audit.ActionSyncPull
)

// syncCmd builds the `mys sync` subcommand tree.
//
// Scope anchor: Git-sync is for personal device redundancy only. Team
// secret sharing uses Bitwarden — the setup wizard prints this up front
// and requires confirmation before any destructive step.
func syncCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "sync",
		Short: "Git-backed sync for redundancy across your own devices (NOT for team sharing — use Bitwarden)",
		Long: `mys sync verwaltet einen git-gestützten Remote für den gopass-Store.

Einsatzzweck: Redundanz über deine EIGENEN Geräte. Für das Teilen mit
Kolleg:innen ist my-secrets nicht gedacht — ein geteilter GPG-Key kann
nicht zwischen Menschen unterscheiden und macht das Audit-Log wertlos.
Für Team-Secrets nutze Bitwarden oder einen vergleichbaren Tresor mit
personalisiertem Login.`,
	}

	root.AddCommand(
		syncSetupCmd(requester),
		syncPushCmd(requester),
		syncPullCmd(requester),
		syncStatusCmd(),
	)
	return root
}

func syncSetupCmd(requester *string) *cobra.Command {
	var (
		yes      bool
		layout   string
		useHTTPS bool
		repoName string
	)
	c := &cobra.Command{
		Use:   "setup",
		Short: "Interaktiver Wizard zum Einrichten eines git-basierten Remote-Stores",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			// Enumerate orgs for the per-org layout offer. Tolerate a
			// missing / uninitialised store: in dry runs or first-time
			// setups there may be no entries yet, so we surface an empty
			// list rather than a hard failure.
			var orgs []string
			if st, err := store.Open(ctx); err == nil {
				orgs, _ = st.Orgs(ctx)
				_ = st.Close(ctx)
			}

			chosen := syncpkg.Layout(strings.ToLower(strings.TrimSpace(layout)))
			if chosen == "" && yes {
				chosen = syncpkg.LayoutSingle
			}
			// Leave the style empty unless --https forces it: the wizard
			// then picks the protocol via `gh auth status` and falls back
			// to HTTPS when GitHub is not reachable over SSH.
			var style syncpkg.RemoteStyle
			if useHTTPS {
				style = syncpkg.RemoteHTTPS
			}

			opts := syncpkg.WizardOptions{
				NonInteractive: yes,
				Layout:         chosen,
				RemoteStyle:    style,
				SingleRepoName: repoName,
				Orgs:           orgs,
				Runner:         syncpkg.ExecRunner{},
			}

			cfg, err := syncpkg.RunWizard(ctx, syncpkg.WizardIO{
				In:  cmd.InOrStdin(),
				Out: cmd.OutOrStdout(),
			}, opts)
			if err != nil {
				// Best-effort audit: setup failure is still worth a row.
				writeSyncAudit(ctx, *requester, actionSyncSetup, "", audit.ResultError, err.Error())
				return err
			}

			path, perr := syncpkg.DefaultPath()
			if perr != nil {
				return perr
			}
			if err := syncpkg.Save(path, cfg); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nSync-Konfiguration gespeichert: %s\n", path)
			for _, r := range cfg.Remotes {
				fmt.Fprintf(cmd.OutOrStdout(), "  mount=%s  remote=%s\n", r.Mount, r.URL)
			}

			reason := fmt.Sprintf("layout=%s remotes=%d", cfg.Layout, len(cfg.Remotes))
			writeSyncAudit(ctx, *requester, actionSyncSetup, "", audit.ResultOK, reason)
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "Non-interaktiv — nimmt Defaults (single-repo, Protokoll via gh auth status) ohne Rückfrage")
	c.Flags().StringVar(&layout, "layout", "", "single | per-org (optional im --yes-Modus)")
	c.Flags().BoolVar(&useHTTPS, "https", false, "HTTPS-URLs für die Remote erzwingen (sonst: Protokoll via gh auth status, HTTPS-Fallback wenn SSH nicht erreichbar)")
	c.Flags().StringVar(&repoName, "repo", "", "Repo-Name für single-repo (default: my-secrets-store)")
	return c
}

func syncPushCmd(requester *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "push",
		Short: "gopass sync auf allen konfigurierten Stores",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := syncpkg.Load("")
			if err != nil {
				return err
			}
			if len(cfg.Remotes) == 0 {
				return fmt.Errorf("keine Sync-Konfiguration — `mys sync setup` zuerst ausführen")
			}
			runner := syncpkg.ExecRunner{}
			for _, r := range cfg.Remotes {
				fmt.Fprintf(cmd.OutOrStdout(), "→ sync %s (%s)\n", r.Mount, r.URL)
				out, err := syncpkg.GopassSync(ctx, runner, r.Mount)
				if len(out) > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), strings.TrimRight(string(out), "\n"))
				}
				if err != nil {
					writeSyncAudit(ctx, *requester, actionSyncPush, r.Mount, audit.ResultError, err.Error())
					return err
				}
				cfg.MarkSynced(r.Mount, time.Now())
				writeSyncAudit(ctx, *requester, actionSyncPush, r.Mount, audit.ResultOK,
					fmt.Sprintf("remote=%s", r.URL))
			}
			path, _ := syncpkg.DefaultPath()
			if err := syncpkg.Save(path, cfg); err != nil {
				return err
			}
			return nil
		},
	}
	return c
}

func syncPullCmd(requester *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "pull",
		Short: "gopass git pull auf allen konfigurierten Stores (nur herunterziehen)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := syncpkg.Load("")
			if err != nil {
				return err
			}
			if len(cfg.Remotes) == 0 {
				return fmt.Errorf("keine Sync-Konfiguration — `mys sync setup` zuerst ausführen")
			}
			runner := syncpkg.ExecRunner{}
			for _, r := range cfg.Remotes {
				fmt.Fprintf(cmd.OutOrStdout(), "← pull %s (%s)\n", r.Mount, r.URL)
				out, err := syncpkg.GopassGitPull(ctx, runner, r.Mount)
				if len(out) > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), strings.TrimRight(string(out), "\n"))
				}
				if err != nil {
					writeSyncAudit(ctx, *requester, actionSyncPull, r.Mount, audit.ResultError, err.Error())
					return err
				}
				cfg.MarkSynced(r.Mount, time.Now())
				writeSyncAudit(ctx, *requester, actionSyncPull, r.Mount, audit.ResultOK,
					fmt.Sprintf("remote=%s", r.URL))
			}
			path, _ := syncpkg.DefaultPath()
			if err := syncpkg.Save(path, cfg); err != nil {
				return err
			}
			return nil
		},
	}
	return c
}

func syncStatusCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Zeigt pro konfiguriertem Store den letzten Sync und die Remote-Erreichbarkeit",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := syncpkg.Load("")
			if err != nil {
				return err
			}
			if len(cfg.Remotes) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Keine Sync-Konfiguration. `mys sync setup` ausführen.")
				return nil
			}
			type row struct {
				Mount     string    `json:"mount"`
				URL       string    `json:"url"`
				LastSync  time.Time `json:"last_sync,omitempty"`
				Reachable bool      `json:"reachable"`
				Error     string    `json:"error,omitempty"`
			}
			rows := make([]row, 0, len(cfg.Remotes))
			for _, r := range cfg.Remotes {
				rr := row{Mount: r.Mount, URL: r.URL, LastSync: r.LastSync}
				if _, err := exec.LookPath("git"); err == nil {
					// Use `git ls-remote` via the shell so we don't need to know
					// where the on-disk gopass repo lives. Fast and read-only.
					c := exec.CommandContext(ctx, "git", "ls-remote", "--heads", r.URL)
					if out, err := c.CombinedOutput(); err != nil {
						rr.Error = strings.TrimSpace(string(out))
					} else {
						rr.Reachable = true
					}
				}
				rows = append(rows, rr)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Layout: %s (owner=%s)\n", cfg.Layout, cfg.Owner)
			for _, rr := range rows {
				last := "nie"
				if !rr.LastSync.IsZero() {
					last = rr.LastSync.Local().Format("2006-01-02 15:04")
				}
				reach := "ok"
				if !rr.Reachable {
					reach = "ERR: " + firstLine(rr.Error)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %-10s last=%-16s url=%s  [%s]\n",
					rr.Mount, last, rr.URL, reach)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "JSON statt Text")
	return c
}

// writeSyncAudit opens the audit DB just long enough to append one row.
// Sync operations do not need the gopass store (no decrypt), so
// OpenAuditOnly is the cheapest safe entry point. Writes are best-effort:
// if the audit DB is unavailable we log to stderr but still finish the
// user-visible operation.
func writeSyncAudit(ctx context.Context, override, action, mount, result, reason string) {
	a, err := app.OpenAuditOnly()
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit write skipped: %v\n", err)
		return
	}
	defer a.Close(ctx)
	d := caller.Identify(override)
	detail, _ := json.Marshal(d)
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      action,
		SecretPath:  mountPath(mount),
		Org:         mount,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
}

func mountPath(mount string) string {
	if mount == "" {
		return ""
	}
	return "mount=" + mount
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
