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
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
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
	root.AddCommand(
		syncSharedSetupCmd(requester),
		syncSharedAuditCmd(requester),
	)
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

var errSyncSharedAuditHumanOnly = errors.New(
	"team audit setup requires a human caller in an interactive or explicitly human session",
)

const defaultTeamAuditRepo = "mys-audit"

type syncSharedAuditSetupOptions struct {
	Mount              string
	SigningFingerprint string
	RemoteURL          string
	Owner              string
	Repo               string
	UseHTTPS           bool
	Yes                bool
}

type syncSharedAuditSetupDeps struct {
	Runner    syncpkg.Runner
	Load      func(string) (*syncpkg.Config, error)
	MountPath func(
		context.Context,
		syncpkg.Runner,
		string,
	) (string, error)
	ResolveRemote func(
		context.Context,
		syncpkg.Runner,
		*syncpkg.Config,
		syncSharedAuditSetupOptions,
		string,
	) (string, error)
	NewClient   newTeamAuditClientFunc
	BeginPolicy func(
		context.Context,
		string,
	) (syncSharedPolicyTransaction, error)
	// EnsurePolicy remains as a compatibility seam for focused command tests.
	// Production setup always uses BeginPolicy.
	EnsurePolicy func(string) (string, error)
	Update       func(
		context.Context,
		string,
		string,
		syncpkg.TeamAuditConfig,
	) (*syncpkg.Config, error)
	OpenAudit func() (*app.App, error)
}

func defaultSyncSharedAuditSetupDeps() syncSharedAuditSetupDeps {
	return syncSharedAuditSetupDeps{
		Runner:        syncpkg.ExecRunner{},
		Load:          syncpkg.Load,
		MountPath:     syncpkg.GopassMountPath,
		ResolveRemote: ensureSyncSharedAuditRemote,
		NewClient:     newDefaultTeamAuditClient,
		BeginPolicy: func(
			ctx context.Context,
			mount string,
		) (syncSharedPolicyTransaction, error) {
			return policy.BeginSharedDefaultContext(ctx, mount)
		},
		EnsurePolicy: policy.EnsureSharedDefault,
		Update:       syncpkg.UpdateSharedTeamAuditAndSave,
		OpenAudit:    app.OpenAuditOnly,
	}
}

type syncSharedPolicyTransaction interface {
	Path() string
	Verify() error
	Commit() error
	Rollback() error
}

type retainedSyncSharedPolicy struct {
	path string
}

func (transaction retainedSyncSharedPolicy) Path() string {
	return transaction.path
}

func (retainedSyncSharedPolicy) Verify() error {
	return nil
}

func (retainedSyncSharedPolicy) Commit() error {
	return nil
}

func (retainedSyncSharedPolicy) Rollback() error {
	return nil
}

func syncSharedAuditCmd(requester *string) *cobra.Command {
	root := &cobra.Command{
		Use:   "audit",
		Short: "GPG-signed advisory read-audit for shared mounts",
		Long: `The team read-audit is advisory: recipients can still decrypt shared
secrets outside mys with gpg or gopass, without creating an audit event.`,
	}
	root.AddCommand(syncSharedAuditSetupCmd(requester))
	return root
}

func syncSharedAuditSetupCmd(requester *string) *cobra.Command {
	options := syncSharedAuditSetupOptions{Repo: defaultTeamAuditRepo}
	command := &cobra.Command{
		Use:   "setup",
		Short: "Provision a separate signed team-audit repository",
		Long: `Provision a per-device append-only audit branch for one existing shared
mount. This administrative command is human-only. The audit repository is
configured only after the remote was provisioned and completely verified.`,
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return runSyncSharedAuditSetup(
				command.Context(),
				command,
				*requester,
				options,
				defaultSyncSharedAuditSetupDeps(),
			)
		},
	}
	command.Flags().StringVar(
		&options.Mount,
		"mount",
		"",
		"existing shared mount (required)",
	)
	command.Flags().StringVar(
		&options.SigningFingerprint,
		"fingerprint",
		"",
		"40-character primary GPG signing fingerprint (required)",
	)
	command.Flags().StringVar(
		&options.RemoteURL,
		"remote",
		"",
		"existing credential-free Git URL or absolute local bare-repo path",
	)
	command.Flags().StringVar(
		&options.Owner,
		"owner",
		"",
		"GitHub owner (default: owner from sync.yaml)",
	)
	command.Flags().StringVar(
		&options.Repo,
		"repo",
		options.Repo,
		"GitHub repository name when --remote is omitted",
	)
	command.Flags().BoolVar(
		&options.UseHTTPS,
		"https",
		false,
		"force HTTPS for a GitHub audit repository",
	)
	command.Flags().BoolVar(
		&options.Yes,
		"yes",
		false,
		"provision the sensitive audit configuration without confirmation",
	)
	return command
}

func runSyncSharedAuditSetup(
	ctx context.Context,
	command *cobra.Command,
	requester string,
	options syncSharedAuditSetupOptions,
	deps syncSharedAuditSetupDeps,
) error {
	return runSyncSharedAuditSetupAs(
		ctx,
		command,
		caller.Identify(requester),
		options,
		deps,
	)
}

func runSyncSharedAuditSetupAs(
	ctx context.Context,
	command *cobra.Command,
	detail caller.Detail,
	options syncSharedAuditSetupOptions,
	deps syncSharedAuditSetupDeps,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateSyncSharedAuditSetupDeps(deps); err != nil {
		return err
	}
	localAudit, err := deps.OpenAudit()
	if err != nil {
		return fmt.Errorf("open audit log before team audit setup: %w", err)
	}
	defer localAudit.Close(ctx)

	execution := syncSharedAuditExecution{
		Context:    ctx,
		Command:    command,
		Detail:     detail,
		Deps:       deps,
		LocalAudit: localAudit,
	}
	return execution.Run(options)
}

type syncSharedAuditSetupState struct {
	Options     syncSharedAuditSetupOptions
	Fingerprint string
	Config      *syncpkg.Config
	Target      string
}

type syncSharedAuditExecution struct {
	Context    context.Context
	Command    *cobra.Command
	Detail     caller.Detail
	Deps       syncSharedAuditSetupDeps
	LocalAudit *app.App
}

func (execution syncSharedAuditExecution) Run(
	options syncSharedAuditSetupOptions,
) error {
	if execution.Detail.Kind != caller.KindHuman {
		auditErr := writeSyncAuditStrict(
			execution.Context,
			execution.LocalAudit,
			execution.Detail,
			actionSyncSetup,
			options.Mount,
			audit.ResultDenied,
			"non-human caller refused team audit setup",
		)
		return errors.Join(errSyncSharedAuditHumanOnly, auditErr)
	}
	state, err := prepareSyncSharedAuditSetup(options, execution.Deps)
	if err != nil {
		return execution.fail(
			options.Mount,
			"team audit setup preflight failed",
			err,
		)
	}
	confirmed, err := confirmSyncSharedAuditSetup(
		execution.Command,
		execution.Command.OutOrStdout(),
		state,
	)
	if err != nil {
		return execution.fail(state.Options.Mount, "confirmation failed", err)
	}
	if !confirmed {
		return execution.decline(state.Options.Mount)
	}
	return execution.runConfirmed(state)
}

func (execution syncSharedAuditExecution) decline(mount string) error {
	if err := writeSyncAuditStrict(
		execution.Context,
		execution.LocalAudit,
		execution.Detail,
		actionSyncSetup,
		mount,
		audit.ResultDenied,
		"operator declined team audit setup",
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(
		execution.Command.OutOrStdout(),
		"abgebrochen",
	); err != nil {
		return fmt.Errorf("write team audit cancellation: %w", err)
	}
	return nil
}

func (execution syncSharedAuditExecution) runConfirmed(
	state syncSharedAuditSetupState,
) error {
	lockedContext, release, err := lockanchor.AcquireContext(
		execution.Context,
	)
	if err != nil {
		return execution.fail(
			state.Options.Mount,
			"team audit setup lock failed",
			err,
		)
	}
	execution.Context = lockedContext
	if err := writeSyncAuditStrict(
		execution.Context,
		execution.LocalAudit,
		execution.Detail,
		actionSyncSetup,
		state.Options.Mount,
		audit.ResultStarted,
		"team audit provisioning started",
	); err != nil {
		return errors.Join(err, release())
	}

	remoteURL, updated, operationErr := execution.runConfirmedUnderAnchor(
		state,
	)
	releaseErr := release()
	if operationErr != nil {
		return errors.Join(operationErr, releaseErr)
	}
	if releaseErr != nil {
		return execution.fail(
			state.Options.Mount,
			"team audit setup lock release failed",
			releaseErr,
		)
	}
	return execution.finish(state, remoteURL, updated)
}

func (execution syncSharedAuditExecution) runConfirmedUnderAnchor(
	state syncSharedAuditSetupState,
) (string, *syncpkg.Config, error) {
	provisioned, err := provisionSyncSharedAudit(
		execution.Context,
		state,
		execution.Deps,
	)
	if err != nil {
		err = abortSyncSharedPolicy(provisioned.Policy, err)
		return "", nil, execution.fail(
			state.Options.Mount,
			"team audit provisioning failed",
			err,
		)
	}
	updated, err := persistSyncSharedAudit(
		execution.Context,
		state.Options.Mount,
		provisioned.RemoteURL,
		state.Fingerprint,
		execution.Deps,
	)
	if err != nil {
		err = abortSyncSharedPolicy(provisioned.Policy, err)
		return "", nil, execution.fail(
			state.Options.Mount,
			"sync config update failed after audit provisioning",
			err,
		)
	}
	if err := provisioned.Policy.Verify(); err != nil {
		err = abortSyncSharedPolicy(
			provisioned.Policy,
			fmt.Errorf("verify shared policy before commit: %w", err),
		)
		return "", nil, execution.fail(
			state.Options.Mount,
			"shared policy verification failed after config update",
			err,
		)
	}
	if err := provisioned.Policy.Commit(); err != nil {
		return "", nil, execution.fail(
			state.Options.Mount,
			"shared policy commit failed after config update",
			fmt.Errorf("commit shared policy: %w", err),
		)
	}
	return provisioned.RemoteURL, updated, nil
}

func (execution syncSharedAuditExecution) finish(
	state syncSharedAuditSetupState,
	remoteURL string,
	updated *syncpkg.Config,
) error {
	if err := writeSyncAuditStrict(
		execution.Context,
		execution.LocalAudit,
		execution.Detail,
		actionSyncSetup,
		state.Options.Mount,
		audit.ResultOK,
		"team audit provisioned and verified",
	); err != nil {
		return err
	}
	return reportSyncSharedAuditSetup(
		execution.Command.OutOrStdout(),
		state.Options.Mount,
		remoteURL,
		state.Fingerprint,
		updated,
	)
}

func (execution syncSharedAuditExecution) fail(
	mount string,
	stage string,
	operationErr error,
) error {
	return joinTeamAuditSetupError(
		execution.Context,
		execution.LocalAudit,
		execution.Detail,
		mount,
		stage,
		operationErr,
	)
}

func prepareSyncSharedAuditSetup(
	options syncSharedAuditSetupOptions,
	deps syncSharedAuditSetupDeps,
) (syncSharedAuditSetupState, error) {
	fingerprint, err := syncpkg.NormalizeTeamAuditFingerprint(
		options.SigningFingerprint,
	)
	if err != nil {
		return syncSharedAuditSetupState{}, err
	}
	if err := validateSyncSharedAuditSetupOptions(options); err != nil {
		return syncSharedAuditSetupState{}, err
	}
	config, err := deps.Load("")
	if err != nil {
		return syncSharedAuditSetupState{}, fmt.Errorf(
			"load sync config: %w",
			err,
		)
	}
	if !config.IsSharedMount(options.Mount) {
		return syncSharedAuditSetupState{}, fmt.Errorf(
			"mount %q is not freshly configured as shared",
			options.Mount,
		)
	}
	options.SigningFingerprint = fingerprint
	target, err := syncSharedAuditTarget(config, options)
	if err != nil {
		return syncSharedAuditSetupState{}, err
	}
	return syncSharedAuditSetupState{
		Options:     options,
		Fingerprint: fingerprint,
		Config:      config,
		Target:      target,
	}, nil
}

func confirmSyncSharedAuditSetup(
	command *cobra.Command,
	output io.Writer,
	state syncSharedAuditSetupState,
) (bool, error) {
	if state.Options.Yes {
		return true, nil
	}
	if _, err := fmt.Fprintln(
		output,
		"Team-Audit ist advisory: direkte Entschlüsselung außerhalb von mys bleibt unsichtbar.",
	); err != nil {
		return false, fmt.Errorf("write team audit confirmation: %w", err)
	}
	for _, line := range []string{
		"Mount: " + state.Options.Mount,
		"Audit-Remote: " + state.Target,
		"Signing-Fingerprint: " + state.Fingerprint,
	} {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return false, fmt.Errorf("write team audit confirmation: %w", err)
		}
	}
	return syncpkg.PromptYesNo(
		bufio.NewReader(command.InOrStdin()),
		output,
		"Signiertes Team-Audit jetzt provisionieren?",
		false,
	)
}

func provisionSyncSharedAudit(
	ctx context.Context,
	state syncSharedAuditSetupState,
	deps syncSharedAuditSetupDeps,
) (syncSharedAuditProvision, error) {
	storePath, err := deps.MountPath(
		ctx,
		deps.Runner,
		state.Options.Mount,
	)
	if err != nil {
		return syncSharedAuditProvision{}, fmt.Errorf(
			"resolve live shared store: %w",
			err,
		)
	}
	remoteURL, err := deps.ResolveRemote(
		ctx,
		deps.Runner,
		state.Config,
		state.Options,
		state.Fingerprint,
	)
	if err != nil {
		return syncSharedAuditProvision{}, fmt.Errorf(
			"provision audit remote: %w",
			err,
		)
	}
	client, err := deps.NewClient(
		state.Options.Mount,
		remoteURL,
		state.Fingerprint,
		storePath,
	)
	if err != nil {
		return syncSharedAuditProvision{}, fmt.Errorf(
			"configure team audit: %w",
			err,
		)
	}
	transaction, err := beginSyncSharedPolicy(
		ctx,
		state.Options.Mount,
		deps,
	)
	if err != nil {
		return syncSharedAuditProvision{}, fmt.Errorf(
			"initialize shared policy: %w",
			err,
		)
	}
	provisioned := syncSharedAuditProvision{
		RemoteURL: remoteURL,
		Policy:    transaction,
	}
	if err := client.Provision(ctx); err != nil {
		return provisioned, err
	}
	return provisioned, nil
}

type syncSharedAuditProvision struct {
	RemoteURL string
	Policy    syncSharedPolicyTransaction
}

func beginSyncSharedPolicy(
	ctx context.Context,
	mount string,
	deps syncSharedAuditSetupDeps,
) (syncSharedPolicyTransaction, error) {
	if deps.BeginPolicy != nil {
		transaction, err := deps.BeginPolicy(ctx, mount)
		if transaction != nil && err != nil {
			return nil, abortSyncSharedPolicy(transaction, err)
		}
		if err != nil {
			return nil, err
		}
		if transaction == nil {
			return nil, errors.New(
				"shared policy transaction returned no policy path",
			)
		}
		if transaction.Path() == "" {
			return nil, abortSyncSharedPolicy(
				transaction,
				errors.New(
					"shared policy transaction returned no policy path",
				),
			)
		}
		return transaction, nil
	}
	path, err := deps.EnsurePolicy(mount)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, errors.New("shared policy setup returned no policy path")
	}
	return retainedSyncSharedPolicy{path: path}, nil
}

func abortSyncSharedPolicy(
	transaction syncSharedPolicyTransaction,
	operationErr error,
) error {
	if transaction == nil {
		return operationErr
	}
	abortErr := transaction.Rollback()
	if abortErr == nil {
		return operationErr
	}
	return errors.Join(
		operationErr,
		fmt.Errorf("release shared policy setup lock after failure: %w", abortErr),
	)
}

func persistSyncSharedAudit(
	ctx context.Context,
	mount string,
	remoteURL string,
	fingerprint string,
	deps syncSharedAuditSetupDeps,
) (*syncpkg.Config, error) {
	_, updateErr := deps.Update(
		ctx,
		"",
		mount,
		syncpkg.TeamAuditConfig{
			URL:                remoteURL,
			SigningFingerprint: fingerprint,
		},
	)
	persisted, loadErr := deps.Load("")
	if loadErr != nil {
		return nil, errors.Join(
			updateErr,
			fmt.Errorf("reload persisted sync config: %w", loadErr),
		)
	}
	if persisted == nil {
		return nil, errors.Join(
			updateErr,
			errors.New("reload persisted sync config returned nil state"),
		)
	}
	remote, ok := persisted.Remote(mount)
	if !ok || remote.TeamAudit == nil ||
		remote.TeamAudit.URL != remoteURL ||
		remote.TeamAudit.SigningFingerprint != fingerprint {
		return nil, errors.Join(
			updateErr,
			errors.New(
				"persisted team audit config does not match requested state",
			),
		)
	}
	return persisted, nil
}

func reportSyncSharedAuditSetup(
	output io.Writer,
	mount string,
	remoteURL string,
	fingerprint string,
	updated *syncpkg.Config,
) error {
	if updated == nil {
		return errors.New("team audit config update returned nil state")
	}
	configPath, err := syncpkg.DefaultPath()
	if err != nil {
		return fmt.Errorf("resolve sync config path: %w", err)
	}
	for _, line := range []string{
		"Team-Audit für " + mount + " bereit.",
		"Audit-Remote: " + remoteURL,
		"Signing-Fingerprint: " + fingerprint,
		"Sync-Konfiguration gespeichert: " + configPath,
	} {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return fmt.Errorf("write team audit setup result: %w", err)
		}
	}
	return nil
}

func validateSyncSharedAuditSetupDeps(
	deps syncSharedAuditSetupDeps,
) error {
	if deps.Load == nil ||
		deps.MountPath == nil ||
		deps.BeginPolicy == nil && deps.EnsurePolicy == nil ||
		deps.ResolveRemote == nil ||
		deps.NewClient == nil ||
		deps.Update == nil ||
		deps.OpenAudit == nil {
		return errors.New("team audit setup dependencies are incomplete")
	}
	return nil
}

func validateSyncSharedAuditSetupOptions(
	options syncSharedAuditSetupOptions,
) error {
	if err := syncpkg.ValidateSharedMountName(options.Mount); err != nil {
		return err
	}
	hasRemote := strings.TrimSpace(options.RemoteURL) != ""
	hasOwner := strings.TrimSpace(options.Owner) != ""
	if hasRemote && hasOwner {
		return errors.New("--remote and --owner are mutually exclusive")
	}
	if hasRemote && options.UseHTTPS {
		return errors.New("--https applies only when --remote is omitted")
	}
	if hasRemote &&
		strings.TrimSpace(options.Repo) != "" &&
		strings.TrimSpace(options.Repo) != defaultTeamAuditRepo {
		return errors.New("--repo applies only when --remote is omitted")
	}
	return nil
}

func syncSharedAuditTarget(
	config *syncpkg.Config,
	options syncSharedAuditSetupOptions,
) (string, error) {
	if remoteURL := strings.TrimSpace(options.RemoteURL); remoteURL != "" {
		normalized, _, _, _, err := normalizeSyncSharedAuditRemote(
			remoteURL,
		)
		if err != nil {
			return "", err
		}
		candidate := syncpkg.TeamAuditConfig{
			URL:                normalized,
			SigningFingerprint: options.SigningFingerprint,
		}
		if err := validateTeamAuditCandidate(
			config,
			options.Mount,
			candidate,
		); err != nil {
			return "", err
		}
		return normalized, nil
	}
	owner := strings.TrimSpace(options.Owner)
	if owner == "" && config != nil {
		owner = strings.TrimSpace(config.Owner)
	}
	repo := strings.TrimSpace(options.Repo)
	if repo == "" {
		repo = defaultTeamAuditRepo
	}
	if err := validateGitHubAuditComponent("owner", owner, 39); err != nil {
		return "", err
	}
	if err := validateGitHubAuditComponent("repository", repo, 100); err != nil {
		return "", err
	}
	return owner + "/" + repo, nil
}

func validateGitHubAuditComponent(
	label string,
	value string,
	limit int,
) error {
	if value == "" || len(value) > limit ||
		strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") ||
		strings.HasPrefix(value, "-") ||
		strings.HasSuffix(value, "-") ||
		strings.Contains(value, "..") {
		return fmt.Errorf("GitHub %s is invalid", label)
	}
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' ||
			label == "repository" && (character == '_' || character == '.')
		if !valid {
			return fmt.Errorf("GitHub %s is invalid", label)
		}
	}
	return nil
}

func ensureSyncSharedAuditRemote(
	ctx context.Context,
	runner syncpkg.Runner,
	config *syncpkg.Config,
	options syncSharedAuditSetupOptions,
	fingerprint string,
) (string, error) {
	if remoteURL := strings.TrimSpace(options.RemoteURL); remoteURL != "" {
		return ensureDirectSharedAuditRemote(
			ctx,
			runner,
			config,
			options.Mount,
			remoteURL,
			fingerprint,
		)
	}
	return ensureManagedSharedAuditRemote(
		ctx,
		runner,
		config,
		options,
		fingerprint,
	)
}

func ensureManagedSharedAuditRemote(
	ctx context.Context,
	runner syncpkg.Runner,
	config *syncpkg.Config,
	options syncSharedAuditSetupOptions,
	fingerprint string,
) (string, error) {
	owner := strings.TrimSpace(options.Owner)
	if owner == "" && config != nil {
		owner = strings.TrimSpace(config.Owner)
	}
	repo := strings.TrimSpace(options.Repo)
	if repo == "" {
		repo = defaultTeamAuditRepo
	}
	if err := validateGitHubAuditComponent("owner", owner, 39); err != nil {
		return "", err
	}
	if err := validateGitHubAuditComponent("repository", repo, 100); err != nil {
		return "", err
	}
	var style syncpkg.RemoteStyle
	if options.UseHTTPS {
		style = syncpkg.RemoteHTTPS
	} else {
		style = syncpkg.DetectRemoteStyle(ctx, runner)
	}
	remoteURL, err := syncpkg.BuildRemoteURL(style, owner, repo)
	if err != nil {
		return "", err
	}
	auditConfig := syncpkg.TeamAuditConfig{
		URL:                remoteURL,
		SigningFingerprint: fingerprint,
	}
	if err := validateTeamAuditCandidate(
		config,
		options.Mount,
		auditConfig,
	); err != nil {
		return "", err
	}
	if err := ensurePrivateGitHubAuditRepo(
		ctx,
		runner,
		owner,
		repo,
		true,
	); err != nil {
		return "", err
	}
	return remoteURL, nil
}

func ensureDirectSharedAuditRemote(
	ctx context.Context,
	runner syncpkg.Runner,
	config *syncpkg.Config,
	mount string,
	remoteURL string,
	fingerprint string,
) (string, error) {
	normalized, owner, repo, isGitHub, err := normalizeSyncSharedAuditRemote(
		remoteURL,
	)
	if err != nil {
		return "", err
	}
	auditConfig := syncpkg.TeamAuditConfig{
		URL:                normalized,
		SigningFingerprint: fingerprint,
	}
	if err := validateTeamAuditCandidate(
		config,
		mount,
		auditConfig,
	); err != nil {
		return "", err
	}
	if isGitHub {
		if err := ensurePrivateGitHubAuditRepo(
			ctx,
			runner,
			owner,
			repo,
			false,
		); err != nil {
			return "", err
		}
	}
	return normalized, nil
}

func ensurePrivateGitHubAuditRepo(
	ctx context.Context,
	runner syncpkg.Runner,
	owner string,
	repo string,
	create bool,
) error {
	visibility, exists, err := syncpkg.GhRepoVisibility(
		ctx,
		runner,
		owner,
		repo,
	)
	if err != nil {
		return fmt.Errorf(
			"check audit repository %s/%s: %w",
			owner,
			repo,
			err,
		)
	}
	if !exists {
		visibility, err = createAndConfirmPrivateGitHubAuditRepo(
			ctx,
			runner,
			owner,
			repo,
			create,
		)
		if err != nil {
			return err
		}
	}
	if visibility != syncpkg.RepoVisibilityPrivate {
		return fmt.Errorf(
			"audit repository %s/%s must be PRIVATE, got %s",
			owner,
			repo,
			visibility,
		)
	}
	return nil
}

func createAndConfirmPrivateGitHubAuditRepo(
	ctx context.Context,
	runner syncpkg.Runner,
	owner string,
	repo string,
	create bool,
) (syncpkg.RepoVisibility, error) {
	if !create {
		return "", fmt.Errorf(
			"check audit repository %s/%s: repository is unavailable",
			owner,
			repo,
		)
	}
	if _, err := syncpkg.GhRepoCreate(ctx, runner, owner, repo); err != nil {
		return "", fmt.Errorf(
			"create private audit repository %s/%s: %w",
			owner,
			repo,
			err,
		)
	}
	visibility, exists, err := syncpkg.GhRepoVisibility(
		ctx,
		runner,
		owner,
		repo,
	)
	if err != nil {
		return "", fmt.Errorf(
			"confirm private audit repository %s/%s: %w",
			owner,
			repo,
			err,
		)
	}
	if !exists {
		return "", fmt.Errorf(
			"confirm private audit repository %s/%s: repository is unavailable after creation",
			owner,
			repo,
		)
	}
	return visibility, nil
}

func parseGitHubAuditRemote(
	remoteURL string,
) (owner string, repo string, isGitHub bool, err error) {
	return teamaudit.ParseGitHubRemote(remoteURL)
}

func normalizeSyncSharedAuditRemote(
	remoteURL string,
) (
	normalized string,
	owner string,
	repo string,
	isGitHub bool,
	err error,
) {
	owner, repo, isGitHub, err = parseGitHubAuditRemote(remoteURL)
	if err != nil {
		return remoteURL, "", "", false, errors.New(
			"invalid team audit remote URL",
		)
	}
	if !isGitHub {
		return remoteURL, owner, repo, isGitHub, err
	}
	if strings.Contains(remoteURL, "://") {
		return remoteURL, owner, repo, true, nil
	}
	hostPart, _, found := strings.Cut(remoteURL, ":")
	if found && !strings.Contains(hostPart, "@") {
		return fmt.Sprintf(
			"git@github.com:%s/%s.git",
			owner,
			repo,
		), owner, repo, true, nil
	}
	return remoteURL, owner, repo, true, nil
}

func validateTeamAuditCandidate(
	config *syncpkg.Config,
	mount string,
	auditConfig syncpkg.TeamAuditConfig,
) error {
	if config == nil {
		return errors.New("sync config is unavailable")
	}
	candidate := *config
	candidate.Remotes = append(
		[]syncpkg.StoreRemote(nil),
		config.Remotes...,
	)
	found := false
	for index := range candidate.Remotes {
		if candidate.Remotes[index].Mount != mount {
			continue
		}
		copy := auditConfig
		candidate.Remotes[index].TeamAudit = &copy
		found = true
		break
	}
	if !found {
		return fmt.Errorf("shared mount %q is not configured", mount)
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("validate team audit target: %w", err)
	}
	return nil
}

func joinTeamAuditSetupError(
	ctx context.Context,
	localAudit *app.App,
	detail caller.Detail,
	mount string,
	stage string,
	operationErr error,
) error {
	auditErr := writeSyncAuditStrict(
		ctx,
		localAudit,
		detail,
		actionSyncSetup,
		mount,
		audit.ResultError,
		stage,
	)
	return errors.Join(operationErr, auditErr)
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
