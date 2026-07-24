package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
	"github.com/spf13/cobra"
)

const defaultTeamAuditLimit = 200

type teamAuditClient interface {
	Provision(context.Context) error
	Aggregate(context.Context) ([]teamaudit.VerifiedEvent, error)
}

type newTeamAuditClientFunc func(
	mount string,
	remoteURL string,
	signingFingerprint string,
	storePath string,
) (teamAuditClient, error)

func newDefaultTeamAuditClient(
	mount string,
	remoteURL string,
	signingFingerprint string,
	storePath string,
) (teamAuditClient, error) {
	config, err := teamaudit.DefaultConfig(
		mount,
		remoteURL,
		signingFingerprint,
		storePath,
	)
	if err != nil {
		return nil, err
	}
	return teamaudit.NewManager(config, nil)
}

type auditTeamOptions struct {
	Mount       string
	User        string
	Fingerprint string
	Actor       string
	Path        string
	Since       string
	Limit       int
	Format      string
}

type auditTeamDeps struct {
	LoadConfig func(string) (*syncpkg.Config, error)
	MountPath  func(context.Context, syncpkg.Runner, string) (string, error)
	NewClient  newTeamAuditClientFunc
	Runner     syncpkg.Runner
}

func defaultAuditTeamDeps() auditTeamDeps {
	return auditTeamDeps{
		LoadConfig: syncpkg.Load,
		MountPath:  syncpkg.GopassMountPath,
		NewClient:  newDefaultTeamAuditClient,
		Runner:     syncpkg.ExecRunner{},
	}
}

func auditTeamCmd() *cobra.Command {
	return auditTeamCmdWithDeps(defaultAuditTeamDeps())
}

func auditTeamCmdWithDeps(deps auditTeamDeps) *cobra.Command {
	options := auditTeamOptions{
		Limit:  defaultTeamAuditLimit,
		Format: "text",
	}
	command := &cobra.Command{
		Use:   "team",
		Short: "Verify and aggregate signed read logs from shared mounts",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return runAuditTeam(command.Context(), command, options, deps)
		},
	}
	command.Flags().StringVar(
		&options.Mount,
		"mount",
		"",
		"shared mount to inspect (default: all configured team-audit mounts)",
	)
	command.Flags().StringVar(
		&options.User,
		"user",
		"",
		"exact signer name or email",
	)
	command.Flags().StringVar(
		&options.Fingerprint,
		"fingerprint",
		"",
		"exact primary signing fingerprint",
	)
	command.Flags().StringVar(
		&options.Actor,
		"actor",
		"",
		"exact actor kind or agent label",
	)
	command.Flags().StringVar(
		&options.Path,
		"path",
		"",
		"exact secret path or path prefix",
	)
	command.Flags().StringVar(
		&options.Since,
		"since",
		"",
		"include events since YYYY-MM-DD or an RFC3339 timestamp",
	)
	command.Flags().IntVar(
		&options.Limit,
		"limit",
		options.Limit,
		"maximum newest events after filtering (0 means unlimited)",
	)
	command.Flags().StringVar(
		&options.Format,
		"format",
		options.Format,
		"output format: text | json",
	)
	return command
}

func runAuditTeam(
	ctx context.Context,
	command *cobra.Command,
	options auditTeamOptions,
	deps auditTeamDeps,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	filter, err := normalizeAuditTeamFilter(options)
	if err != nil {
		return err
	}
	if deps.LoadConfig == nil || deps.MountPath == nil || deps.NewClient == nil {
		return errors.New("team audit dependencies are incomplete")
	}

	config, err := deps.LoadConfig("")
	if err != nil {
		return fmt.Errorf("load sync config: %w", err)
	}
	remotes, err := selectTeamAuditRemotes(config, filter.Mount)
	if err != nil {
		return err
	}

	events, err := aggregateTeamAuditRemotes(ctx, remotes, deps)
	if err != nil {
		return err
	}
	sortTeamAuditEvents(events)
	events = filterTeamAuditEvents(events, filter)
	if filter.Limit > 0 && len(events) > filter.Limit {
		events = events[:filter.Limit]
	}
	if filter.Format == "json" {
		return writeTeamAuditJSON(command, events)
	}
	return writeTeamAuditText(command, events)
}

func aggregateTeamAuditRemotes(
	ctx context.Context,
	remotes []syncpkg.StoreRemote,
	deps auditTeamDeps,
) ([]teamaudit.VerifiedEvent, error) {
	// Deliberately buffer every mount. No user-visible byte is written until
	// every remote has passed the core's full signature, chain, and rollback
	// verification.
	events := make([]teamaudit.VerifiedEvent, 0)
	for _, remote := range remotes {
		storePath, err := deps.MountPath(ctx, deps.Runner, remote.Mount)
		if err != nil {
			return nil, fmt.Errorf(
				"resolve shared mount %q before team audit: %w",
				remote.Mount,
				err,
			)
		}
		client, err := deps.NewClient(
			remote.Mount,
			remote.TeamAudit.URL,
			remote.TeamAudit.SigningFingerprint,
			storePath,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"configure team audit for mount %q: %w",
				remote.Mount,
				err,
			)
		}
		verified, err := client.Aggregate(ctx)
		if err != nil {
			return nil, fmt.Errorf(
				"verify team audit for mount %q: %w",
				remote.Mount,
				err,
			)
		}
		events = append(events, verified...)
	}
	return events, nil
}

type normalizedAuditTeamFilter struct {
	Mount       string
	User        string
	Fingerprint string
	Actor       string
	Path        string
	Since       time.Time
	HasSince    bool
	Limit       int
	Format      string
}

func normalizeAuditTeamFilter(
	options auditTeamOptions,
) (normalizedAuditTeamFilter, error) {
	filter := normalizedAuditTeamFilter{
		Mount: strings.TrimSpace(options.Mount),
		User:  strings.TrimSpace(options.User),
		Actor: strings.TrimSpace(options.Actor),
		Path:  strings.TrimSpace(options.Path),
		Limit: options.Limit,
		Format: strings.ToLower(
			strings.TrimSpace(options.Format),
		),
	}
	if filter.Mount != "" {
		if err := syncpkg.ValidateSharedMountName(filter.Mount); err != nil {
			return normalizedAuditTeamFilter{}, err
		}
	}
	for label, value := range map[string]string{
		"user filter":  filter.User,
		"actor filter": filter.Actor,
		"path filter":  filter.Path,
	} {
		if err := validateTeamAuditFilterText(label, value); err != nil {
			return normalizedAuditTeamFilter{}, err
		}
	}
	if options.Fingerprint != "" {
		fingerprint, err := syncpkg.NormalizeTeamAuditFingerprint(
			options.Fingerprint,
		)
		if err != nil {
			return normalizedAuditTeamFilter{}, err
		}
		filter.Fingerprint = fingerprint
	}
	if options.Since != "" {
		since, err := parseSince(strings.TrimSpace(options.Since))
		if err != nil {
			return normalizedAuditTeamFilter{}, err
		}
		filter.Since = since.UTC()
		filter.HasSince = true
	}
	if filter.Limit < 0 {
		return normalizedAuditTeamFilter{}, errors.New(
			"team audit limit must be zero or positive",
		)
	}
	switch filter.Format {
	case "text", "json":
	default:
		return normalizedAuditTeamFilter{}, fmt.Errorf(
			"unsupported team audit format %q (use text or json)",
			options.Format,
		)
	}
	return filter, nil
}

func validateTeamAuditFilterText(label, value string) error {
	if len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s contains unsafe characters or is too long", label)
	}
	return nil
}

func selectTeamAuditRemotes(
	config *syncpkg.Config,
	mount string,
) ([]syncpkg.StoreRemote, error) {
	if config == nil {
		return nil, errors.New("sync config is unavailable")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate sync config: %w", err)
	}
	if mount != "" {
		remote, ok := config.Remote(mount)
		if !ok || !remote.Shared {
			return nil, fmt.Errorf("mount %q is not configured as shared", mount)
		}
		if remote.TeamAudit == nil {
			return nil, fmt.Errorf(
				"mount %q has no team audit; run `mys sync shared audit setup`",
				mount,
			)
		}
		return []syncpkg.StoreRemote{remote}, nil
	}

	remotes := make([]syncpkg.StoreRemote, 0)
	for _, remote := range config.Remotes {
		if remote.Shared && remote.TeamAudit != nil {
			remotes = append(remotes, remote)
		}
	}
	if len(remotes) == 0 {
		return nil, errors.New(
			"no shared team audit is configured; run `mys sync shared audit setup`",
		)
	}
	sort.Slice(remotes, func(first, second int) bool {
		return remotes[first].Mount < remotes[second].Mount
	})
	return remotes, nil
}

func sortTeamAuditEvents(events []teamaudit.VerifiedEvent) {
	sort.SliceStable(events, func(first, second int) bool {
		left := events[first]
		right := events[second]
		switch {
		case left.Timestamp != right.Timestamp:
			return left.Timestamp > right.Timestamp
		case left.Mount != right.Mount:
			return left.Mount < right.Mount
		case left.SignerFingerprint != right.SignerFingerprint:
			return left.SignerFingerprint < right.SignerFingerprint
		case left.DeviceID != right.DeviceID:
			return left.DeviceID < right.DeviceID
		case left.Seq != right.Seq:
			return left.Seq > right.Seq
		case left.EventID != right.EventID:
			return left.EventID < right.EventID
		default:
			return left.Branch < right.Branch
		}
	})
}

func filterTeamAuditEvents(
	events []teamaudit.VerifiedEvent,
	filter normalizedAuditTeamFilter,
) []teamaudit.VerifiedEvent {
	filtered := make([]teamaudit.VerifiedEvent, 0, len(events))
	for _, event := range events {
		if filter.User != "" &&
			!equalFoldAny(filter.User, event.SignerName, event.SignerEmail) {
			continue
		}
		if filter.Fingerprint != "" &&
			!strings.EqualFold(filter.Fingerprint, event.SignerFingerprint) {
			continue
		}
		if filter.Actor != "" &&
			!equalFoldAny(
				filter.Actor,
				event.Actor.Kind,
				event.Actor.AgentLabel,
			) {
			continue
		}
		if filter.Path != "" && !matchesAuditPathPrefix(filter.Path, event.Path) {
			continue
		}
		if filter.HasSince {
			timestamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
			if err != nil || timestamp.Before(filter.Since) {
				continue
			}
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func equalFoldAny(filter string, values ...string) bool {
	for _, value := range values {
		if strings.EqualFold(filter, value) {
			return true
		}
	}
	return false
}

func matchesAuditPathPrefix(filter, secretPath string) bool {
	filter = strings.TrimSuffix(filter, "/")
	return secretPath == filter || strings.HasPrefix(secretPath, filter+"/")
}

func writeTeamAuditText(
	command *cobra.Command,
	events []teamaudit.VerifiedEvent,
) error {
	for _, event := range events {
		actor := event.Actor.Kind
		if event.Actor.AgentLabel != "" {
			actor += "/" + event.Actor.AgentLabel
		}
		if _, err := fmt.Fprintf(
			command.OutOrStdout(),
			"ts=%s mount=%s user=%s email=%s fingerprint=%s host=%s "+
				"device=%s actor=%s action=%s path=%s seq=%d branch=%s commit=%s\n",
			terminalSafe(event.Timestamp),
			terminalSafe(event.Mount),
			terminalSafe(event.SignerName),
			terminalSafe(event.SignerEmail),
			terminalSafe(event.SignerFingerprint),
			terminalSafe(event.Host),
			terminalSafe(event.DeviceID),
			terminalSafe(actor),
			terminalSafe(event.Action),
			terminalSafe(event.Path),
			event.Seq,
			terminalSafe(event.Branch),
			terminalSafe(event.Commit),
		); err != nil {
			return fmt.Errorf("write team audit output: %w", err)
		}
	}
	return nil
}

type teamAuditJSONEvent struct {
	teamaudit.Event
	Branch string `json:"branch"`
	Commit string `json:"commit"`
}

func writeTeamAuditJSON(
	command *cobra.Command,
	events []teamaudit.VerifiedEvent,
) error {
	rows := make([]teamAuditJSONEvent, len(events))
	for index, event := range events {
		rows[index] = teamAuditJSONEvent{
			Event:  event.Event,
			Branch: event.Branch,
			Commit: event.Commit,
		}
	}
	if err := json.NewEncoder(command.OutOrStdout()).Encode(rows); err != nil {
		return fmt.Errorf("write team audit JSON: %w", err)
	}
	return nil
}

func terminalSafe(value string) string {
	return strconv.QuoteToGraphic(value)
}
