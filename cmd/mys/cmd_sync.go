package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
// The default setup path remains scoped to personal device redundancy.
// Explicitly shared mounts live under the separate `sync shared` subtree
// so a caller cannot accidentally turn the default store into a team store.
func syncCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "sync",
		Short: "Git-backed sync for personal stores and explicitly shared team mounts",
		Long: `mys sync verwaltet git-gestützte Remotes für gopass-Stores.

Der normale Setup-Wizard dient weiterhin ausschließlich der Redundanz
deines PERSÖNLICHEN Stores über deine eigenen Geräte.

Ein Team-Store muss ausdrücklich mit „mys sync shared setup“ angelegt
werden. Dort hat jedes Teammitglied einen eigenen GPG-Schlüssel und
team-keys.yaml dokumentiert die Identität zu jedem Fingerprint.

Wichtig: Lokale Entschlüsselung kann mys umgehen. Ein späteres
client-seitiges Read-Audit ist daher nur nachvollziehbar, nicht technisch
erzwingbar. Nutze für auditkritische Secrets einen zentralen Tresor.`,
	}

	root.AddCommand(
		syncSetupCmd(requester),
		syncSharedCmd(requester),
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
			previous, err := syncpkg.Load("")
			if err != nil {
				return err
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
			orgs = filterSharedMounts(orgs, previous)

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
			if err := cfg.MergeSharedFrom(previous); err != nil {
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

var errSyncSharedAIDenied = errors.New(
	"shared mount setup is refused for AI callers — use a human session")

type syncSharedSetupOptions struct {
	Mount        string
	StorePath    string
	TeamKeysPath string
	Fingerprints []string
	RemoteURL    string
	Owner        string
	Repo         string
	UseHTTPS     bool
	Yes          bool
}

type syncSharedSetupDeps struct {
	Runner    syncpkg.Runner
	Load      func(string) (*syncpkg.Config, error)
	Save      func(string, *syncpkg.Config) error
	Provision func(context.Context, syncpkg.SharedProvisionOptions) (*syncpkg.SharedProvisionResult, error)
	OpenAudit func() (*app.App, error)
}

func defaultSyncSharedSetupDeps() syncSharedSetupDeps {
	return syncSharedSetupDeps{
		Runner:    syncpkg.ExecRunner{},
		Load:      syncpkg.Load,
		Save:      syncpkg.Save,
		Provision: syncpkg.ProvisionSharedMount,
		OpenAudit: app.OpenAuditOnly,
	}
}

func syncSharedCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "shared",
		Short: "Explizit geteilte Team-Mounts mit individuellen GPG-Schlüsseln verwalten",
		Long: `Explizit geteilte Mounts verwenden für jedes Teammitglied einen eigenen
GPG-Schlüssel. team-keys.yaml im Store ordnet Fingerprints zu Personen.

Die Entschlüsselung bleibt lokal und kann mys umgehen. Das Trust-Modell
ist deshalb advisory; ein client-seitiges Read-Audit ist nicht erzwingbar.`,
	}
	root.AddCommand(syncSharedSetupCmd(requester))
	return root
}

func syncSharedSetupCmd(requester *string) *cobra.Command {
	opts := syncSharedSetupOptions{Repo: "mys-store-shared"}
	c := &cobra.Command{
		Use:   "setup",
		Short: "Shared-Mount provisionieren und Team-Recipients exakt abgleichen",
		Long: `Erstellt oder verbindet einen explizit geteilten gopass-Mount, importiert
optionale Public-Key-Dateien aus team-keys.yaml, gleicht .gpg-id exakt
mit dem Team-Key-Set ab und pusht die Metadaten zum Git-Remote.

Mindestens einer der Team-Fingerprints muss lokal einen Secret Key haben,
damit die ausführende Person den Store anschließend entschlüsseln kann.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSyncSharedSetup(
				cmd.Context(), cmd, *requester, opts, defaultSyncSharedSetupDeps())
		},
	}
	c.Flags().StringVar(&opts.Mount, "mount", "", "Name des Shared-Mounts, z. B. jasp (Pflicht)")
	c.Flags().StringVar(&opts.StorePath, "path", "", "lokaler Store-Pfad (default: XDG-Datenverzeichnis)")
	c.Flags().StringVar(&opts.TeamKeysPath, "team-keys", "", "Pfad zur team-keys.yaml")
	c.Flags().StringSliceVar(&opts.Fingerprints, "fingerprint", nil,
		"bereits importierter Team-Fingerprint; wiederholbar, alternativ zu --team-keys")
	c.Flags().StringVar(&opts.RemoteURL, "remote", "", "bestehende Git-Remote-URL oder lokaler Bare-Repo-Pfad")
	c.Flags().StringVar(&opts.Owner, "owner", "", "GitHub-Organisation/-Owner; erstellt das Repo, wenn --remote fehlt")
	c.Flags().StringVar(&opts.Repo, "repo", opts.Repo, "GitHub-Repo-Name bei Verwendung von --owner")
	c.Flags().BoolVar(&opts.UseHTTPS, "https", false, "HTTPS statt erkanntem GitHub-Protokoll verwenden")
	c.Flags().BoolVar(&opts.Yes, "yes", false, "sensible Einrichtung ohne interaktive Bestätigung ausführen")
	return c
}

func runSyncSharedSetup(
	ctx context.Context,
	cmd *cobra.Command,
	requester string,
	opts syncSharedSetupOptions,
	deps syncSharedSetupDeps,
) error {
	return runSyncSharedSetupAs(
		ctx, cmd, caller.Identify(requester), opts, deps)
}

func runSyncSharedSetupAs(
	ctx context.Context,
	cmd *cobra.Command,
	detail caller.Detail,
	opts syncSharedSetupOptions,
	deps syncSharedSetupDeps,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	a, err := deps.OpenAudit()
	if err != nil {
		return fmt.Errorf("open audit log before shared setup: %w", err)
	}
	defer a.Close(ctx)

	if detail.Kind == caller.KindAI {
		denied := errSyncSharedAIDenied
		auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
			audit.ResultDenied, "ai caller refused shared mount setup")
		return errors.Join(denied, auditErr)
	}
	if err := validateSyncSharedSetupOptions(opts); err != nil {
		auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
			audit.ResultError, err.Error())
		return errors.Join(err, auditErr)
	}

	out := cmd.OutOrStdout()
	if !opts.Yes {
		fmt.Fprintln(out, "Dieser Mount gibt allen aufgeführten Team-Schlüsseln Zugriff auf jedes Secret.")
		fmt.Fprintln(out, "Lokale Entschlüsselung außerhalb von mys bleibt möglich und wäre nicht auditierbar.")
		ok, promptErr := syncpkg.PromptYesNo(
			bufio.NewReader(cmd.InOrStdin()), out, "Shared-Mount jetzt provisionieren?", false)
		if promptErr != nil {
			auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
				audit.ResultError, "confirmation: "+promptErr.Error())
			return errors.Join(promptErr, auditErr)
		}
		if !ok {
			if auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
				audit.ResultDenied, "operator declined shared mount setup"); auditErr != nil {
				return auditErr
			}
			fmt.Fprintln(out, "abgebrochen")
			return nil
		}
	}

	cfg, err := deps.Load("")
	if err != nil {
		auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
			audit.ResultError, "load config: "+err.Error())
		return errors.Join(err, auditErr)
	}
	if err := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
		audit.ResultStarted, "shared mount provisioning started"); err != nil {
		return err
	}

	var style syncpkg.RemoteStyle
	if opts.UseHTTPS {
		style = syncpkg.RemoteHTTPS
	}
	result, err := deps.Provision(ctx, syncpkg.SharedProvisionOptions{
		Config:       cfg,
		Mount:        opts.Mount,
		StorePath:    opts.StorePath,
		TeamKeysPath: opts.TeamKeysPath,
		Fingerprints: opts.Fingerprints,
		RemoteURL:    opts.RemoteURL,
		Owner:        opts.Owner,
		Repo:         opts.Repo,
		RemoteStyle:  style,
		Runner:       deps.Runner,
	})
	if err != nil {
		auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
			audit.ResultError, "provision: "+err.Error())
		return errors.Join(err, auditErr)
	}
	if err := deps.Save("", result.Config); err != nil {
		auditErr := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
			audit.ResultError, "save config: "+err.Error())
		return errors.Join(err, auditErr)
	}
	reason := fmt.Sprintf("shared=true remote=%s recipients=%d", result.RemoteURL, len(result.Fingerprints))
	if err := writeSyncAuditStrict(ctx, a, detail, actionSyncSetup, opts.Mount,
		audit.ResultOK, reason); err != nil {
		return err
	}

	configPath, _ := syncpkg.DefaultPath()
	fmt.Fprintf(out, "Shared-Mount %s bereit: %s\n", result.Mount, result.StorePath)
	fmt.Fprintf(out, "Remote: %s\n", result.RemoteURL)
	fmt.Fprintf(out, "Recipients: %d\n", len(result.Fingerprints))
	if result.TeamKeysPath != "" {
		fmt.Fprintf(out, "Team-Keys: %s\n", result.TeamKeysPath)
	}
	fmt.Fprintf(out, "Sync-Konfiguration gespeichert: %s\n", configPath)
	return nil
}

func validateSyncSharedSetupOptions(opts syncSharedSetupOptions) error {
	if err := syncpkg.ValidateSharedMountName(opts.Mount); err != nil {
		return err
	}
	hasManifest := strings.TrimSpace(opts.TeamKeysPath) != ""
	hasFingerprints := len(opts.Fingerprints) > 0
	if hasManifest == hasFingerprints {
		return errors.New("genau eine Quelle angeben: --team-keys oder mindestens ein --fingerprint")
	}
	if strings.TrimSpace(opts.RemoteURL) == "" && strings.TrimSpace(opts.Owner) == "" {
		return errors.New("--remote oder --owner ist erforderlich")
	}
	return nil
}

func filterSharedMounts(orgs []string, cfg *syncpkg.Config) []string {
	shared := make(map[string]struct{})
	if cfg != nil {
		for _, remote := range cfg.Remotes {
			if remote.Shared {
				shared[remote.Mount] = struct{}{}
			}
		}
	}
	filtered := make([]string, 0, len(orgs))
	for _, org := range orgs {
		if _, ok := shared[org]; !ok {
			filtered = append(filtered, org)
		}
	}
	return filtered
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
				Shared    bool      `json:"shared"`
				Reachable bool      `json:"reachable"`
				Error     string    `json:"error,omitempty"`
			}
			rows := make([]row, 0, len(cfg.Remotes))
			for _, r := range cfg.Remotes {
				rr := row{Mount: r.Mount, URL: r.URL, LastSync: r.LastSync, Shared: r.Shared}
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
				kind := "personal"
				if rr.Shared {
					kind = "shared"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %-10s type=%-8s last=%-16s url=%s  [%s]\n",
					rr.Mount, kind, last, rr.URL, reach)
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
	if err := writeSyncAuditStrict(ctx, a, d, action, mount, result, reason); err != nil {
		fmt.Fprintf(os.Stderr, "audit write skipped: %v\n", err)
	}
}

// writeSyncAuditStrict is used for shared-mount setup, where a recorded
// administrative action is part of the command's success contract.
func writeSyncAuditStrict(
	ctx context.Context,
	a *app.App,
	d caller.Detail,
	action, mount, result, reason string,
) error {
	if a == nil || a.Audit == nil {
		return errors.New("audit log is unavailable")
	}
	detail, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal audit actor: %w", err)
	}
	_, err = a.Audit.Write(ctx, audit.Entry{
		Action:      action,
		SecretPath:  mountPath(mount),
		Org:         mount,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
	if err != nil {
		return fmt.Errorf("write sync audit: %w", err)
	}
	return nil
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
