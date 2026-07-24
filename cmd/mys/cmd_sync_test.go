package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/spf13/cobra"
)

const syncSharedTestFingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"

func TestSyncSharedCommandIsDiscoverable(t *testing.T) {
	requester := ""
	root := syncCmd(&requester)
	shared, _, err := root.Find([]string{"shared", "setup"})
	if err != nil {
		t.Fatalf("find shared setup: %v", err)
	}
	if shared == nil || shared.Name() != "setup" {
		t.Fatalf("found command = %#v, want shared setup", shared)
	}
	for _, name := range []string{
		"mount", "path", "team-keys", "fingerprint", "remote",
		"owner", "repo", "https", "yes",
	} {
		if shared.Flags().Lookup(name) == nil {
			t.Errorf("shared setup flag --%s is missing", name)
		}
	}
}

func TestValidateSyncSharedSetupOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    syncSharedSetupOptions
		wantErr string
	}{
		{
			name: "manifest and local remote",
			opts: syncSharedSetupOptions{
				Mount:        "jasp",
				TeamKeysPath: "team-keys.yaml",
				RemoteURL:    "/tmp/shared.git",
			},
		},
		{
			name: "preimported fingerprints and github owner",
			opts: syncSharedSetupOptions{
				Mount:        "jasp",
				Fingerprints: []string{syncSharedTestFingerprint},
				Owner:        "jasp",
			},
		},
		{
			name: "root cannot be shared",
			opts: syncSharedSetupOptions{
				Mount:        syncpkg.DefaultStoreMount,
				TeamKeysPath: "team-keys.yaml",
				RemoteURL:    "/tmp/shared.git",
			},
			wantErr: "cannot be shared",
		},
		{
			name: "identity source required",
			opts: syncSharedSetupOptions{
				Mount:     "jasp",
				RemoteURL: "/tmp/shared.git",
			},
			wantErr: "genau eine Quelle",
		},
		{
			name: "identity sources are exclusive",
			opts: syncSharedSetupOptions{
				Mount:        "jasp",
				TeamKeysPath: "team-keys.yaml",
				Fingerprints: []string{syncSharedTestFingerprint},
				RemoteURL:    "/tmp/shared.git",
			},
			wantErr: "genau eine Quelle",
		},
		{
			name: "remote target required",
			opts: syncSharedSetupOptions{
				Mount:        "jasp",
				TeamKeysPath: "team-keys.yaml",
			},
			wantErr: "--remote oder --owner",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSyncSharedSetupOptions(test.opts)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestRunSyncSharedSetupPersistsAndAudits(t *testing.T) {
	clearSyncAISignals(t)
	auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
	openAudit := testSyncAuditOpener(t, auditPath)
	var saved *syncpkg.Config
	var provisioned syncpkg.SharedProvisionOptions
	deps := syncSharedSetupDeps{
		Load: func(string) (*syncpkg.Config, error) {
			return &syncpkg.Config{
				Version: 1,
				Layout:  syncpkg.LayoutSingle,
				Remotes: []syncpkg.StoreRemote{{
					Mount: syncpkg.DefaultStoreMount,
					URL:   "personal.git",
				}},
			}, nil
		},
		Save: func(_ string, cfg *syncpkg.Config) error {
			copy := *cfg
			copy.Remotes = append([]syncpkg.StoreRemote(nil), cfg.Remotes...)
			saved = &copy
			return nil
		},
		Provision: func(
			_ context.Context,
			opts syncpkg.SharedProvisionOptions,
		) (*syncpkg.SharedProvisionResult, error) {
			provisioned = opts
			cfg := *opts.Config
			cfg.Remotes = append([]syncpkg.StoreRemote(nil), opts.Config.Remotes...)
			if err := cfg.UpdateSharedRemote(opts.Mount, opts.RemoteURL); err != nil {
				return nil, err
			}
			return &syncpkg.SharedProvisionResult{
				Config:       &cfg,
				Mount:        opts.Mount,
				StorePath:    "/stores/jasp",
				RemoteURL:    opts.RemoteURL,
				TeamKeysPath: "/stores/jasp/team-keys.yaml",
				Fingerprints: []string{syncSharedTestFingerprint},
			}, nil
		},
		OpenAudit: openAudit,
	}
	var output bytes.Buffer
	cmd := newSyncTestCommand(&bytes.Buffer{}, &output)
	opts := syncSharedSetupOptions{
		Mount:        "jasp",
		TeamKeysPath: "/input/team-keys.yaml",
		RemoteURL:    "/remotes/jasp.git",
		Yes:          true,
	}

	if err := runSyncSharedSetupAs(
		context.Background(), cmd, humanSyncDetail(), opts, deps); err != nil {
		t.Fatalf("runSyncSharedSetup: %v", err)
	}
	if saved == nil || !saved.IsSharedMount("jasp") {
		t.Fatalf("saved config = %+v, want jasp shared", saved)
	}
	if provisioned.TeamKeysPath != opts.TeamKeysPath ||
		provisioned.RemoteURL != opts.RemoteURL ||
		provisioned.Mount != opts.Mount {
		t.Fatalf("provision options = %+v", provisioned)
	}
	if !strings.Contains(output.String(), "Shared-Mount jasp bereit") {
		t.Fatalf("output = %q", output.String())
	}

	rows := readSyncAuditRows(t, auditPath)
	var results []string
	for _, row := range rows {
		if row.Action != audit.ActionSyncSetup || row.Org != "jasp" {
			continue
		}
		results = append(results, row.Result)
		if row.SecretPath != "mount=jasp" {
			t.Errorf("secret_path = %q, want mount=jasp", row.SecretPath)
		}
	}
	if !slices.Contains(results, audit.ResultStarted) ||
		!slices.Contains(results, audit.ResultOK) {
		t.Fatalf("sync setup audit results = %v, want started and ok", results)
	}
}

func TestRunSyncSharedSetupStopsBeforeMutation(t *testing.T) {
	tests := []struct {
		name       string
		requester  string
		input      string
		yes        bool
		wantErr    error
		wantResult string
	}{
		{
			name:       "ai is hard denied even with yes",
			requester:  "ai",
			yes:        true,
			wantErr:    errSyncSharedAIDenied,
			wantResult: audit.ResultDenied,
		},
		{
			name:       "human declines confirmation",
			requester:  "human",
			input:      "\n",
			wantResult: audit.ResultDenied,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearSyncAISignals(t)
			auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
			var calls int
			deps := syncSharedSetupDeps{
				Load: func(string) (*syncpkg.Config, error) {
					calls++
					return &syncpkg.Config{Version: 1}, nil
				},
				Save: func(string, *syncpkg.Config) error {
					calls++
					return nil
				},
				Provision: func(
					context.Context,
					syncpkg.SharedProvisionOptions,
				) (*syncpkg.SharedProvisionResult, error) {
					calls++
					return nil, errors.New("must not run")
				},
				OpenAudit: testSyncAuditOpener(t, auditPath),
			}
			var output bytes.Buffer
			cmd := newSyncTestCommand(bytes.NewBufferString(test.input), &output)
			opts := syncSharedSetupOptions{
				Mount:        "jasp",
				TeamKeysPath: "team-keys.yaml",
				RemoteURL:    "/remotes/jasp.git",
				Yes:          test.yes,
			}
			var err error
			if test.requester == "ai" {
				err = runSyncSharedSetup(
					context.Background(), cmd, test.requester, opts, deps)
			} else {
				err = runSyncSharedSetupAs(
					context.Background(), cmd, humanSyncDetail(), opts, deps)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if calls != 0 {
				t.Fatalf("mutation dependencies called %d times", calls)
			}
			rows := readSyncAuditRows(t, auditPath)
			if len(rows) != 1 ||
				rows[0].Action != audit.ActionSyncSetup ||
				rows[0].Result != test.wantResult {
				t.Fatalf("audit rows = %+v, want one %s row", rows, test.wantResult)
			}
		})
	}
}

func TestFilterSharedMounts(t *testing.T) {
	got := filterSharedMounts([]string{"home", "jasp", "zuhause"}, &syncpkg.Config{
		Version: 1,
		Remotes: []syncpkg.StoreRemote{
			{Mount: "jasp", URL: "shared.git", Shared: true},
			{Mount: "home", URL: "personal.git"},
		},
	})
	want := []string{"home", "zuhause"}
	if !slices.Equal(got, want) {
		t.Fatalf("filterSharedMounts = %v, want %v", got, want)
	}
}

func newSyncTestCommand(input *bytes.Buffer, output *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetIn(input)
	cmd.SetOut(output)
	cmd.SetErr(output)
	return cmd
}

func clearSyncAISignals(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"CLAUDECODE",
		"CLAUDE_CODE_ENTRYPOINT",
		"CLAUDE_CODE_SESSION",
		"CURSOR",
		"CURSOR_SESSION",
	} {
		t.Setenv(name, "")
	}
}

func humanSyncDetail() caller.Detail {
	return caller.Detail{
		Kind:   caller.KindHuman,
		Reason: "test human caller",
	}
}

func testSyncAuditOpener(t *testing.T, path string) func() (*app.App, error) {
	t.Helper()
	return func() (*app.App, error) {
		log, err := audit.Open(path)
		if err != nil {
			return nil, err
		}
		return &app.App{Audit: log}, nil
	}
}

func readSyncAuditRows(t *testing.T, path string) []audit.Entry {
	t.Helper()
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open audit for assertion: %v", err)
	}
	defer log.Close()
	rows, err := log.Tail(context.Background(), audit.Filter{Limit: 20})
	if err != nil {
		t.Fatalf("read audit rows: %v", err)
	}
	return rows
}
