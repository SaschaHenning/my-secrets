package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
	"github.com/spf13/cobra"
)

type fakeTeamAuditClient struct {
	provision func(context.Context) error
	aggregate func(context.Context) ([]teamaudit.VerifiedEvent, error)
}

func (client fakeTeamAuditClient) Provision(ctx context.Context) error {
	if client.provision == nil {
		return nil
	}
	return client.provision(ctx)
}

func (client fakeTeamAuditClient) Aggregate(
	ctx context.Context,
) ([]teamaudit.VerifiedEvent, error) {
	if client.aggregate == nil {
		return nil, nil
	}
	return client.aggregate(ctx)
}

func TestAuditTeamCommandIsDiscoverable(t *testing.T) {
	root := auditCmd()
	command, _, err := root.Find([]string{"team"})
	if err != nil {
		t.Fatalf("find audit team: %v", err)
	}
	if command == nil || command.Name() != "team" {
		t.Fatalf("found command = %#v, want audit team", command)
	}
	for _, name := range []string{
		"mount", "user", "fingerprint", "actor",
		"path", "since", "limit", "format",
	} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("audit team flag --%s is missing", name)
		}
	}
}

func TestNewDefaultTeamAuditClientUsesCanonicalLayout(t *testing.T) {
	root := t.TempDir()
	configHome := filepath.Join(root, "config")
	cacheHome := filepath.Join(root, "cache")
	stateHome := filepath.Join(root, "state")
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("XDG_STATE_HOME", stateHome)

	client, err := newDefaultTeamAuditClient(
		"jasp",
		filepath.Join(root, "audit.git"),
		syncSharedTestFingerprint,
		filepath.Join(root, "store"),
	)
	if err != nil {
		t.Fatalf("newDefaultTeamAuditClient: %v", err)
	}
	if client == nil {
		t.Fatal("newDefaultTeamAuditClient returned nil")
	}
}

func TestRunAuditTeamVerifiesEveryRemoteBeforeOutput(t *testing.T) {
	config := teamAuditTestConfig("alpha", "bravo")
	var output bytes.Buffer
	command := teamAuditTestCommand(&output)
	deps := auditTeamDeps{
		LoadConfig: func(string) (*syncpkg.Config, error) {
			return config, nil
		},
		MountPath: func(
			_ context.Context,
			_ syncpkg.Runner,
			mount string,
		) (string, error) {
			return "/stores/" + mount, nil
		},
		NewClient: func(
			mount string,
			_ string,
			_ string,
			_ string,
		) (teamAuditClient, error) {
			return fakeTeamAuditClient{
				aggregate: func(
					context.Context,
				) ([]teamaudit.VerifiedEvent, error) {
					if mount == "bravo" {
						return nil, errors.New("signature mismatch")
					}
					return []teamaudit.VerifiedEvent{
						teamAuditTestEvent("alpha", "2026-07-24T10:00:00.000000000Z"),
					}, nil
				},
			}, nil
		},
	}

	err := runAuditTeam(
		context.Background(),
		command,
		auditTeamOptions{Format: "text", Limit: 200},
		deps,
	)
	if err == nil || !strings.Contains(err.Error(), "signature mismatch") {
		t.Fatalf("error = %v, want signature failure", err)
	}
	if output.Len() != 0 {
		t.Fatalf("partial output escaped before full verification: %q", output.String())
	}
}

func TestRunAuditTeamFiltersSortsLimitsAndEscapesText(t *testing.T) {
	older := teamAuditTestEvent(
		"jasp",
		"2026-07-24T10:00:00.000000000Z",
	)
	older.EventID = "00000000-0000-4000-8000-000000000001"
	older.Path = "jasp/older"
	newer := teamAuditTestEvent(
		"jasp",
		"2026-07-24T11:00:00.000000000Z",
	)
	newer.EventID = "00000000-0000-4000-8000-000000000002"
	newer.Path = "jasp/newer"
	newer.SignerName = "Alice\x1b[31m"
	newer.Actor = teamaudit.Actor{Kind: "ai", AgentLabel: "claude-code"}

	var output bytes.Buffer
	err := runAuditTeam(
		context.Background(),
		teamAuditTestCommand(&output),
		auditTeamOptions{
			Actor:  "claude-code",
			Path:   "jasp",
			Since:  "2026-07-24T10:30:00Z",
			Limit:  1,
			Format: "text",
		},
		auditTeamDeps{
			LoadConfig: func(string) (*syncpkg.Config, error) {
				return teamAuditTestConfig("jasp"), nil
			},
			MountPath: func(
				context.Context,
				syncpkg.Runner,
				string,
			) (string, error) {
				return "/stores/jasp", nil
			},
			NewClient: func(
				string,
				string,
				string,
				string,
			) (teamAuditClient, error) {
				return fakeTeamAuditClient{
					aggregate: func(
						context.Context,
					) ([]teamaudit.VerifiedEvent, error) {
						return []teamaudit.VerifiedEvent{older, newer}, nil
					},
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runAuditTeam: %v", err)
	}
	got := output.String()
	if strings.Contains(got, "\x1b") {
		t.Fatalf("raw terminal escape reached output: %q", got)
	}
	for _, want := range []string{
		`user="Alice\x1b[31m"`,
		`path="jasp/newer"`,
		`actor="ai/claude-code"`,
		`fingerprint="` + syncSharedTestFingerprint + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "jasp/older") {
		t.Fatalf("filtered event reached output: %q", got)
	}
}

func TestRunAuditTeamJSONUsesStableStructuredFields(t *testing.T) {
	event := teamAuditTestEvent(
		"jasp",
		"2026-07-24T11:00:00.000000000Z",
	)
	var output bytes.Buffer
	err := runAuditTeam(
		context.Background(),
		teamAuditTestCommand(&output),
		auditTeamOptions{
			Mount:       "jasp",
			User:        "alice@example.com",
			Fingerprint: strings.ToLower(syncSharedTestFingerprint),
			Actor:       "human",
			Path:        "jasp/example",
			Limit:       0,
			Format:      "json",
		},
		auditTeamDeps{
			LoadConfig: func(string) (*syncpkg.Config, error) {
				return teamAuditTestConfig("jasp"), nil
			},
			MountPath: func(
				context.Context,
				syncpkg.Runner,
				string,
			) (string, error) {
				return "/stores/jasp", nil
			},
			NewClient: func(
				string,
				string,
				string,
				string,
			) (teamAuditClient, error) {
				return fakeTeamAuditClient{
					aggregate: func(
						context.Context,
					) ([]teamaudit.VerifiedEvent, error) {
						return []teamaudit.VerifiedEvent{event}, nil
					},
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("runAuditTeam: %v", err)
	}

	var rows []map[string]any
	if err := json.Unmarshal(output.Bytes(), &rows); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want one", rows)
	}
	for key, want := range map[string]any{
		"mount":              "jasp",
		"path":               "jasp/example",
		"signer_fingerprint": syncSharedTestFingerprint,
		"branch":             "audit/v1/jasp/signer/device",
		"commit":             strings.Repeat("b", 40),
	} {
		if got := rows[0][key]; got != want {
			t.Errorf("JSON %s = %#v, want %#v", key, got, want)
		}
	}
	if _, leakedCapitalized := rows[0]["Branch"]; leakedCapitalized {
		t.Fatalf("JSON contains unstable capitalized Branch field: %s", output.String())
	}
}

func TestNormalizeAuditTeamFilterRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name    string
		options auditTeamOptions
	}{
		{
			name:    "negative limit",
			options: auditTeamOptions{Limit: -1, Format: "text"},
		},
		{
			name:    "unknown format",
			options: auditTeamOptions{Format: "yaml"},
		},
		{
			name: "invalid fingerprint",
			options: auditTeamOptions{
				Fingerprint: "DEADBEEF",
				Format:      "text",
			},
		},
		{
			name:    "control in path",
			options: auditTeamOptions{Path: "jasp/\nsecret", Format: "text"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeAuditTeamFilter(test.options); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func teamAuditTestConfig(mounts ...string) *syncpkg.Config {
	config := &syncpkg.Config{Version: 1}
	for _, mount := range mounts {
		config.Remotes = append(config.Remotes, syncpkg.StoreRemote{
			Mount:  mount,
			URL:    "/remotes/" + mount + "-store.git",
			Shared: true,
			TeamAudit: &syncpkg.TeamAuditConfig{
				URL:                "/remotes/" + mount + "-audit.git",
				SigningFingerprint: syncSharedTestFingerprint,
			},
		})
	}
	return config
}

func teamAuditTestEvent(
	mount string,
	timestamp string,
) teamaudit.VerifiedEvent {
	return teamaudit.VerifiedEvent{
		Event: teamaudit.Event{
			SchemaVersion:     1,
			EventID:           "00000000-0000-4000-8000-000000000000",
			Seq:               1,
			Timestamp:         timestamp,
			Mount:             mount,
			Path:              mount + "/example",
			Action:            "get",
			Actor:             teamaudit.Actor{Kind: "human"},
			Host:              "host",
			DeviceID:          "11111111-1111-4111-8111-111111111111",
			Result:            "success",
			SignerFingerprint: syncSharedTestFingerprint,
			SignerName:        "Alice",
			SignerEmail:       "alice@example.com",
			StoreCommit:       strings.Repeat("a", 40),
			PolicyHash:        strings.Repeat("1", 64),
			TeamKeysHash:      strings.Repeat("2", 64),
			RecipientSetHash:  strings.Repeat("3", 64),
			PrevHash:          strings.Repeat("0", 64),
			RowHash:           strings.Repeat("4", 64),
			Signature:         "test-signature",
		},
		Branch: "audit/v1/" + mount + "/signer/device",
		Commit: strings.Repeat("b", 40),
	}
}

func teamAuditTestCommand(output *bytes.Buffer) *cobra.Command {
	command := &cobra.Command{Use: "test"}
	command.SetOut(output)
	command.SetErr(output)
	return command
}
