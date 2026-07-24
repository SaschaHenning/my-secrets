package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/spf13/cobra"
)

const syncSharedTestFingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"

type recordingSyncSharedPolicy struct {
	path      string
	steps     *[]string
	verifyErr error
	commitErr error
	abortErr  error
}

func (transaction recordingSyncSharedPolicy) Path() string {
	return transaction.path
}

func (transaction recordingSyncSharedPolicy) Verify() error {
	*transaction.steps = append(*transaction.steps, "verify-policy")
	return transaction.verifyErr
}

func (transaction recordingSyncSharedPolicy) Commit() error {
	*transaction.steps = append(*transaction.steps, "commit-policy")
	return transaction.commitErr
}

func (transaction recordingSyncSharedPolicy) Rollback() error {
	*transaction.steps = append(*transaction.steps, "abort-policy")
	return transaction.abortErr
}

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

func TestSyncSharedAuditSetupCommandIsDiscoverable(t *testing.T) {
	requester := ""
	root := syncCmd(&requester)
	command, _, err := root.Find([]string{"shared", "audit", "setup"})
	if err != nil {
		t.Fatalf("find shared audit setup: %v", err)
	}
	if command == nil || command.Name() != "setup" {
		t.Fatalf("found command = %#v, want shared audit setup", command)
	}
	for _, name := range []string{
		"mount", "fingerprint", "remote", "owner", "repo", "https", "yes",
	} {
		if command.Flags().Lookup(name) == nil {
			t.Errorf("shared audit setup flag --%s is missing", name)
		}
	}
}

func TestRunSyncSharedAuditSetupProvisionsBeforeCASUpdate(t *testing.T) {
	clearSyncAISignals(t)
	auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	var steps []string
	persisted := config
	deps := syncSharedAuditSetupDeps{
		Load: func(string) (*syncpkg.Config, error) {
			steps = append(steps, "load")
			return persisted, nil
		},
		MountPath: func(
			_ context.Context,
			_ syncpkg.Runner,
			mount string,
		) (string, error) {
			steps = append(steps, "mount-path")
			if mount != "jasp" {
				t.Fatalf("mount path requested for %q", mount)
			}
			return "/stores/jasp", nil
		},
		BeginPolicy: func(
			_ context.Context,
			mount string,
		) (syncSharedPolicyTransaction, error) {
			steps = append(steps, "policy")
			if mount != "jasp" {
				t.Fatalf("policy requested for %q", mount)
			}
			return recordingSyncSharedPolicy{
				path:  "/config/shared-policies/jasp.yaml",
				steps: &steps,
			}, nil
		},
		ResolveRemote: func(
			_ context.Context,
			_ syncpkg.Runner,
			gotConfig *syncpkg.Config,
			options syncSharedAuditSetupOptions,
			fingerprint string,
		) (string, error) {
			steps = append(steps, "remote")
			if gotConfig != config || options.Owner != "" ||
				fingerprint != syncSharedTestFingerprint {
				t.Fatalf(
					"remote args config=%p options=%+v fingerprint=%q",
					gotConfig,
					options,
					fingerprint,
				)
			}
			return "git@github.com:jasp/mys-audit.git", nil
		},
		NewClient: func(
			mount string,
			remoteURL string,
			fingerprint string,
			storePath string,
		) (teamAuditClient, error) {
			steps = append(steps, "manager")
			if mount != "jasp" ||
				remoteURL != "git@github.com:jasp/mys-audit.git" ||
				fingerprint != syncSharedTestFingerprint ||
				storePath != "/stores/jasp" {
				t.Fatalf(
					"manager args = %q %q %q %q",
					mount,
					remoteURL,
					fingerprint,
					storePath,
				)
			}
			return fakeTeamAuditClient{
				provision: func(context.Context) error {
					steps = append(steps, "provision")
					return nil
				},
			}, nil
		},
		Update: func(
			_ context.Context,
			path string,
			mount string,
			auditConfig syncpkg.TeamAuditConfig,
		) (*syncpkg.Config, error) {
			steps = append(steps, "update")
			if path != "" || mount != "jasp" ||
				auditConfig.URL != "git@github.com:jasp/mys-audit.git" ||
				auditConfig.SigningFingerprint != syncSharedTestFingerprint {
				t.Fatalf(
					"update args path=%q mount=%q audit=%+v",
					path,
					mount,
					auditConfig,
				)
			}
			updated := *config
			updated.Remotes = append(
				[]syncpkg.StoreRemote(nil),
				config.Remotes...,
			)
			copy := auditConfig
			updated.Remotes[0].TeamAudit = &copy
			persisted = &updated
			return &updated, nil
		},
		OpenAudit: testSyncAuditOpener(t, auditPath),
	}
	var output bytes.Buffer
	command := newSyncTestCommand(&bytes.Buffer{}, &output)
	options := syncSharedAuditSetupOptions{
		Mount:              "jasp",
		SigningFingerprint: strings.ToLower(syncSharedTestFingerprint),
		Repo:               defaultTeamAuditRepo,
		Yes:                true,
	}

	if err := runSyncSharedAuditSetupAs(
		context.Background(),
		command,
		humanSyncDetail(),
		options,
		deps,
	); err != nil {
		t.Fatalf("runSyncSharedAuditSetupAs: %v", err)
	}
	wantSteps := []string{
		"load",
		"mount-path",
		"remote",
		"manager",
		"policy",
		"provision",
		"update",
		"load",
		"verify-policy",
		"commit-policy",
	}
	if !slices.Equal(steps, wantSteps) {
		t.Fatalf("steps = %v, want %v", steps, wantSteps)
	}
	for _, want := range []string{
		"Team-Audit für jasp bereit",
		"git@github.com:jasp/mys-audit.git",
		syncSharedTestFingerprint,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output %q does not contain %q", output.String(), want)
		}
	}
	rows := readSyncAuditRows(t, auditPath)
	var results []string
	for _, row := range rows {
		results = append(results, row.Result)
	}
	if !slices.Contains(results, audit.ResultStarted) ||
		!slices.Contains(results, audit.ResultOK) {
		t.Fatalf("audit results = %v, want started and ok", results)
	}
}

func TestRunSyncSharedAuditSetupIsHumanOnlyAndConfirmed(t *testing.T) {
	tests := []struct {
		name       string
		detail     caller.Detail
		input      string
		yes        bool
		wantErr    error
		wantResult string
	}{
		{
			name:       "AI cannot bypass with yes",
			detail:     caller.Detail{Kind: caller.KindAI, AgentLabel: "claude-code"},
			yes:        true,
			wantErr:    errSyncSharedAuditHumanOnly,
			wantResult: audit.ResultDenied,
		},
		{
			name:       "script is denied",
			detail:     caller.Detail{Kind: caller.KindScript},
			yes:        true,
			wantErr:    errSyncSharedAuditHumanOnly,
			wantResult: audit.ResultDenied,
		},
		{
			name:       "human declines",
			detail:     humanSyncDetail(),
			input:      "\n",
			wantResult: audit.ResultDenied,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
			config := &syncpkg.Config{
				Version: 1,
				Owner:   "jasp",
				Remotes: []syncpkg.StoreRemote{{
					Mount:  "jasp",
					URL:    "/remotes/jasp-store.git",
					Shared: true,
				}},
			}
			var mutations int
			deps := syncSharedAuditSetupDeps{
				Load: func(string) (*syncpkg.Config, error) {
					return config, nil
				},
				MountPath: func(
					context.Context,
					syncpkg.Runner,
					string,
				) (string, error) {
					mutations++
					return "", errors.New("must not run")
				},
				EnsurePolicy: func(string) (string, error) {
					mutations++
					return "", errors.New("must not run")
				},
				ResolveRemote: func(
					context.Context,
					syncpkg.Runner,
					*syncpkg.Config,
					syncSharedAuditSetupOptions,
					string,
				) (string, error) {
					mutations++
					return "", errors.New("must not run")
				},
				NewClient: func(
					string,
					string,
					string,
					string,
				) (teamAuditClient, error) {
					mutations++
					return nil, errors.New("must not run")
				},
				Update: func(
					context.Context,
					string,
					string,
					syncpkg.TeamAuditConfig,
				) (*syncpkg.Config, error) {
					mutations++
					return nil, errors.New("must not run")
				},
				OpenAudit: testSyncAuditOpener(t, auditPath),
			}
			var output bytes.Buffer
			command := newSyncTestCommand(
				bytes.NewBufferString(test.input),
				&output,
			)
			err := runSyncSharedAuditSetupAs(
				context.Background(),
				command,
				test.detail,
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					Repo:               defaultTeamAuditRepo,
					Yes:                test.yes,
				},
				deps,
			)
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mutations != 0 {
				t.Fatalf("mutation dependencies called %d times", mutations)
			}
			rows := readSyncAuditRows(t, auditPath)
			if len(rows) != 1 || rows[0].Result != test.wantResult {
				t.Fatalf(
					"audit rows = %+v, want one %s row",
					rows,
					test.wantResult,
				)
			}
		})
	}
}

func TestRunSyncSharedAuditSetupRejectsRootRemoteBeforeMutation(t *testing.T) {
	for _, remoteURL := range []string{"/", "file:///"} {
		t.Run(remoteURL, func(t *testing.T) {
			auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
			config := &syncpkg.Config{
				Version: 1,
				Remotes: []syncpkg.StoreRemote{{
					Mount:  "jasp",
					URL:    "/remotes/jasp-store.git",
					Shared: true,
				}},
			}
			var mutations int
			mutate := func() error {
				mutations++
				return errors.New("must not run")
			}
			err := runSyncSharedAuditSetupAs(
				context.Background(),
				newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
				humanSyncDetail(),
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					RemoteURL:          remoteURL,
					Repo:               defaultTeamAuditRepo,
					Yes:                true,
				},
				syncSharedAuditSetupDeps{
					Load: func(string) (*syncpkg.Config, error) {
						return config, nil
					},
					MountPath: func(
						context.Context,
						syncpkg.Runner,
						string,
					) (string, error) {
						return "", mutate()
					},
					EnsurePolicy: func(string) (string, error) {
						return "", mutate()
					},
					ResolveRemote: func(
						context.Context,
						syncpkg.Runner,
						*syncpkg.Config,
						syncSharedAuditSetupOptions,
						string,
					) (string, error) {
						return "", mutate()
					},
					NewClient: func(
						string,
						string,
						string,
						string,
					) (teamAuditClient, error) {
						mutations++
						return nil, errors.New("must not run")
					},
					Update: func(
						context.Context,
						string,
						string,
						syncpkg.TeamAuditConfig,
					) (*syncpkg.Config, error) {
						mutations++
						return nil, errors.New("must not run")
					},
					OpenAudit: testSyncAuditOpener(t, auditPath),
				},
			)
			if err == nil || !strings.Contains(
				err.Error(),
				"invalid team audit remote URL",
			) {
				t.Fatalf("error = %v, want invalid remote rejection", err)
			}
			if mutations != 0 {
				t.Fatalf("mutation dependencies called %d times", mutations)
			}
		})
	}
}

func TestRunSyncSharedAuditSetupValidatesManagerBeforePolicyMutation(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
	config := &syncpkg.Config{
		Version: 1,
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	var policyCalls int
	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			RemoteURL:          "file:///stores/jasp/audit.git",
			Repo:               defaultTeamAuditRepo,
			Yes:                true,
		},
		syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return config, nil
			},
			MountPath: func(
				context.Context,
				syncpkg.Runner,
				string,
			) (string, error) {
				return "/stores/jasp", nil
			},
			EnsurePolicy: func(string) (string, error) {
				policyCalls++
				return "", errors.New("must not run")
			},
			ResolveRemote: func(
				context.Context,
				syncpkg.Runner,
				*syncpkg.Config,
				syncSharedAuditSetupOptions,
				string,
			) (string, error) {
				return "file:///stores/jasp/audit.git", nil
			},
			NewClient: func(
				string,
				string,
				string,
				string,
			) (teamAuditClient, error) {
				return nil, errors.New(
					"local audit remote must not overlap store paths",
				)
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				return nil, errors.New("must not run")
			},
			OpenAudit: testSyncAuditOpener(t, auditPath),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("error = %v, want manager validation failure", err)
	}
	if policyCalls != 0 {
		t.Fatalf("EnsurePolicy called %d times", policyCalls)
	}
}

func TestRunSyncSharedAuditSetupDoesNotPersistFailedProvision(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	var updated bool
	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
			Yes:                true,
		},
		syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return config, nil
			},
			MountPath: func(
				context.Context,
				syncpkg.Runner,
				string,
			) (string, error) {
				return "/stores/jasp", nil
			},
			EnsurePolicy: func(string) (string, error) {
				return "/config/shared-policy.yaml", nil
			},
			ResolveRemote: func(
				context.Context,
				syncpkg.Runner,
				*syncpkg.Config,
				syncSharedAuditSetupOptions,
				string,
			) (string, error) {
				return "/remotes/jasp-audit.git", nil
			},
			NewClient: func(
				string,
				string,
				string,
				string,
			) (teamAuditClient, error) {
				return fakeTeamAuditClient{
					provision: func(context.Context) error {
						return errors.New("remote verification failed")
					},
				}, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				updated = true
				return nil, nil
			},
			OpenAudit: testSyncAuditOpener(t, auditPath),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "remote verification failed") {
		t.Fatalf("error = %v, want provision failure", err)
	}
	if updated {
		t.Fatal("sync config was updated after failed provisioning")
	}
}

func TestRunSyncSharedAuditSetupRetainsValidPolicyOnProvisionFailures(
	t *testing.T,
) {
	for _, failure := range []string{
		"remote verification failed",
		"remote probe cleanup failed",
	} {
		t.Run(failure, func(t *testing.T) {
			fixture := newSyncSharedAuditPolicyFixture(t)
			beforeConfig := fixture.configBytes(t)
			deps := fixture.deps(t, func(context.Context) error {
				return errors.New(failure)
			})
			deps.Update = func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				t.Fatal("config update ran after failed provision")
				return nil, nil
			}

			err := runSyncSharedAuditSetupAs(
				context.Background(),
				newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
				humanSyncDetail(),
				fixture.options(),
				deps,
			)
			if err == nil || !strings.Contains(err.Error(), failure) {
				t.Fatalf("error = %v, want %q", err, failure)
			}
			if _, _, _, err := policy.LoadShared("jasp"); err != nil {
				t.Fatalf(
					"policy after failed provision must remain valid: %v",
					err,
				)
			}
			if got := fixture.configBytes(t); !bytes.Equal(got, beforeConfig) {
				t.Fatal("sync config changed after failed provision")
			}
		})
	}
}

func TestRunSyncSharedAuditSetupRetainsValidPolicyOnUpdateFailure(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	beforeConfig := fixture.configBytes(t)
	deps := fixture.deps(t, nil)
	deps.Update = func(
		context.Context,
		string,
		string,
		syncpkg.TeamAuditConfig,
	) (*syncpkg.Config, error) {
		return nil, errors.New("simulated config persistence failure")
	}

	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"simulated config persistence failure",
	) {
		t.Fatalf("error = %v, want config persistence failure", err)
	}
	if _, _, _, err := policy.LoadShared("jasp"); err != nil {
		t.Fatalf("policy after failed update must remain valid: %v", err)
	}
	if got := fixture.configBytes(t); !bytes.Equal(got, beforeConfig) {
		t.Fatal("sync config changed after failed update")
	}
}

func TestRunSyncSharedAuditSetupRetainsValidPolicyOnReloadFailure(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	deps := fixture.deps(t, nil)
	loadCalls := 0
	deps.Load = func(path string) (*syncpkg.Config, error) {
		loadCalls++
		if loadCalls == 1 {
			return syncpkg.Load(path)
		}
		return nil, errors.New("simulated persisted config reload failure")
	}

	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"simulated persisted config reload failure",
	) {
		t.Fatalf("error = %v, want config reload failure", err)
	}
	if _, _, _, err := policy.LoadShared("jasp"); err != nil {
		t.Fatalf("policy after reload failure must remain valid: %v", err)
	}
}

func TestRunSyncSharedAuditSetupRejectsMissingPersistedUpdate(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	beforeConfig := fixture.configBytes(t)
	deps := fixture.deps(t, nil)
	deps.Update = func(
		context.Context,
		string,
		string,
		syncpkg.TeamAuditConfig,
	) (*syncpkg.Config, error) {
		return syncpkg.Load(fixture.configPath)
	}

	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"persisted team audit config does not match requested state",
	) {
		t.Fatalf("error = %v, want persisted-state mismatch", err)
	}
	if _, _, _, err := policy.LoadShared("jasp"); err != nil {
		t.Fatalf("policy after missing update must remain valid: %v", err)
	}
	if got := fixture.configBytes(t); !bytes.Equal(got, beforeConfig) {
		t.Fatal("sync config changed after inconsistent update")
	}
}

func TestPersistSyncSharedAuditReconcilesPersistedState(
	t *testing.T,
) {
	base := &syncpkg.Config{
		Version: 1,
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	desired := cloneSyncConfigWithTeamAudit(
		t,
		base,
		"/remotes/jasp-audit.git",
		syncSharedTestFingerprint,
	)

	t.Run("ambiguous update error with desired persisted state succeeds", func(t *testing.T) {
		persisted := base
		deps := syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return persisted, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				persisted = desired
				return nil, errors.New("simulated lost update response")
			},
		}
		got, err := persistSyncSharedAudit(
			context.Background(),
			"jasp",
			"/remotes/jasp-audit.git",
			syncSharedTestFingerprint,
			deps,
		)
		if err != nil {
			t.Fatalf("ambiguous persisted success: %v", err)
		}
		if got != desired {
			t.Fatalf("reconciled config = %p, want persisted %p", got, desired)
		}
	})

	t.Run("return-only success is rejected", func(t *testing.T) {
		deps := syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return base, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				return desired, nil
			},
		}
		if _, err := persistSyncSharedAudit(
			context.Background(),
			"jasp",
			"/remotes/jasp-audit.git",
			syncSharedTestFingerprint,
			deps,
		); err == nil || !strings.Contains(
			err.Error(),
			"persisted team audit config does not match requested state",
		) {
			t.Fatalf("return-only success error = %v", err)
		}
	})

	t.Run("nil update response is ignored when persisted state matches", func(t *testing.T) {
		deps := syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return desired, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				return nil, nil
			},
		}
		got, err := persistSyncSharedAudit(
			context.Background(),
			"jasp",
			"/remotes/jasp-audit.git",
			syncSharedTestFingerprint,
			deps,
		)
		if err != nil || got != desired {
			t.Fatalf("nil response reconciliation = %p, %v", got, err)
		}
	})

	t.Run("nil persisted state fails closed", func(t *testing.T) {
		deps := syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return nil, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				return desired, nil
			},
		}
		if _, err := persistSyncSharedAudit(
			context.Background(),
			"jasp",
			"/remotes/jasp-audit.git",
			syncSharedTestFingerprint,
			deps,
		); err == nil || !strings.Contains(err.Error(), "nil state") {
			t.Fatalf("nil persisted state error = %v", err)
		}
	})
}

func TestRunSyncSharedAuditSetupNeverChangesExistingPolicy(t *testing.T) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	if _, err := policy.EnsureSharedDefault("jasp"); err != nil {
		t.Fatal(err)
	}
	beforeData, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	deps := fixture.deps(t, func(context.Context) error {
		return errors.New("remote verification failed")
	})

	err = runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !strings.Contains(err.Error(), "remote verification failed") {
		t.Fatalf("error = %v, want provision failure", err)
	}
	afterData, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterData, beforeData) {
		t.Fatal("existing shared policy bytes changed")
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("existing shared policy inode changed")
	}
}

func TestRunSyncSharedAuditSetupRejectsPolicyReplacementBeforeFinalCommit(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	replacement := []byte("version: 1\nactors: {}\n")
	deps := fixture.deps(t, func(context.Context) error {
		replacementPath := filepath.Join(
			filepath.Dir(fixture.policyPath),
			"replacement.yaml",
		)
		if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
			return err
		}
		if err := os.Rename(replacementPath, fixture.policyPath); err != nil {
			return err
		}
		return nil
	})

	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !strings.Contains(err.Error(), "inode") {
		t.Fatalf("policy replacement error = %v, want inode mismatch", err)
	}
	got, readErr := os.ReadFile(fixture.policyPath)
	if readErr != nil {
		t.Fatalf("read replacement: %v", readErr)
	}
	if !bytes.Equal(got, replacement) {
		t.Fatalf("replacement changed: got %q, want %q", got, replacement)
	}
}

func TestRunSyncSharedAuditSetupRejectsPolicyDeletionBeforeFinalCommit(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	deps := fixture.deps(t, func(context.Context) error {
		return os.Remove(fixture.policyPath)
	})

	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy deletion error = %v, want not-exist", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup restored or replaced deleted policy: %v", err)
	}
}

func TestRunSyncSharedAuditSetupCommitsPolicyAfterPersistedConfig(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	deps := fixture.deps(t, nil)

	if err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	); err != nil {
		t.Fatalf("runSyncSharedAuditSetupAs: %v", err)
	}
	if _, _, _, err := policy.LoadShared("jasp"); err != nil {
		t.Fatalf("committed shared policy: %v", err)
	}
	updated, err := syncpkg.Load(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	remote, ok := updated.Remote("jasp")
	if !ok || remote.TeamAudit == nil ||
		remote.TeamAudit.URL != "/remotes/jasp-audit.git" ||
		remote.TeamAudit.SigningFingerprint != syncSharedTestFingerprint {
		t.Fatalf("persisted team audit config = %+v", remote.TeamAudit)
	}
}

func TestRunSyncSharedAuditSetupReusesOnlyExplicitOuterAnchor(
	t *testing.T,
) {
	fixture := newSyncSharedAuditPolicyFixture(t)
	deps := fixture.deps(t, func(lockedContext context.Context) error {
		nestedRelease, err := lockanchor.Acquire(lockedContext)
		if err != nil {
			return fmt.Errorf("nested explicit anchor: %w", err)
		}
		if err := nestedRelease(); err != nil {
			return fmt.Errorf("release nested explicit anchor: %w", err)
		}

		foreignResult := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(
				context.Background(),
				50*time.Millisecond,
			)
			defer cancel()
			release, err := lockanchor.Acquire(ctx)
			if release != nil {
				_ = release()
				foreignResult <- errors.New(
					"foreign goroutine bypassed outer anchor",
				)
				return
			}
			foreignResult <- err
		}()
		if err := <-foreignResult; !errors.Is(
			err,
			context.DeadlineExceeded,
		) {
			return fmt.Errorf("foreign goroutine lock result: %w", err)
		}
		return nil
	})

	if err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
		humanSyncDetail(),
		fixture.options(),
		deps,
	); err != nil {
		t.Fatalf("nested audit setup: %v", err)
	}

	release, err := lockanchor.Acquire(context.Background())
	if err != nil {
		t.Fatalf("outer anchor leaked after setup: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release post-setup anchor: %v", err)
	}
}

func TestRunSyncSharedAuditSetupPropagatesFinalPolicyErrors(t *testing.T) {
	tests := []struct {
		name      string
		verifyErr error
		commitErr error
		wantSteps []string
		wantError string
	}{
		{
			name:      "verify",
			verifyErr: errors.New("simulated final policy verification failure"),
			wantSteps: []string{"verify-policy", "abort-policy"},
			wantError: "simulated final policy verification failure",
		},
		{
			name:      "commit",
			commitErr: errors.New("simulated final policy commit failure"),
			wantSteps: []string{"verify-policy", "commit-policy"},
			wantError: "simulated final policy commit failure",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSyncSharedAuditPolicyFixture(t)
			deps := fixture.deps(t, nil)
			var steps []string
			deps.BeginPolicy = func(
				context.Context,
				string,
			) (syncSharedPolicyTransaction, error) {
				return recordingSyncSharedPolicy{
					path:      fixture.policyPath,
					steps:     &steps,
					verifyErr: test.verifyErr,
					commitErr: test.commitErr,
				}, nil
			}
			var output bytes.Buffer

			err := runSyncSharedAuditSetupAs(
				context.Background(),
				newSyncTestCommand(&bytes.Buffer{}, &output),
				humanSyncDetail(),
				fixture.options(),
				deps,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("final policy error = %v, want %q", err, test.wantError)
			}
			if !slices.Equal(steps, test.wantSteps) {
				t.Fatalf("policy lifecycle steps = %v, want %v", steps, test.wantSteps)
			}
			if output.Len() != 0 {
				t.Fatalf("success output written after policy failure: %q", output.String())
			}
			for _, row := range readSyncAuditRows(t, fixture.auditPath) {
				if row.Result == audit.ResultOK {
					t.Fatalf("OK audit written after policy failure")
				}
			}
		})
	}
}

func TestBeginSyncSharedPolicyFinalizesEveryReturnedTransaction(t *testing.T) {
	beginErr := errors.New("simulated begin failure")
	abortErr := errors.New("simulated abort failure")
	tests := []struct {
		name      string
		path      string
		beginErr  error
		abortErr  error
		wantError []error
	}{
		{
			name:      "transaction with begin error",
			path:      "/config/shared-policy.yaml",
			beginErr:  beginErr,
			abortErr:  abortErr,
			wantError: []error{beginErr, abortErr},
		},
		{
			name:      "transaction with empty path",
			wantError: []error{errors.New("no policy path")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var steps []string
			deps := syncSharedAuditSetupDeps{
				BeginPolicy: func(
					context.Context,
					string,
				) (syncSharedPolicyTransaction, error) {
					return recordingSyncSharedPolicy{
						path:     test.path,
						steps:    &steps,
						abortErr: test.abortErr,
					}, test.beginErr
				},
			}

			transaction, err := beginSyncSharedPolicy(
				context.Background(),
				"jasp",
				deps,
			)
			if transaction != nil {
				t.Fatalf("transaction = %#v, want nil after initialization failure", transaction)
			}
			if err == nil {
				t.Fatal("initialization failure unexpectedly succeeded")
			}
			for _, want := range test.wantError {
				if want == beginErr || want == abortErr {
					if !errors.Is(err, want) {
						t.Fatalf("error = %v, want wrapped %v", err, want)
					}
					continue
				}
				if !strings.Contains(err.Error(), want.Error()) {
					t.Fatalf("error = %v, want %q", err, want)
				}
			}
			if want := []string{"abort-policy"}; !slices.Equal(steps, want) {
				t.Fatalf("policy lifecycle steps = %v, want %v", steps, want)
			}
		})
	}
}

func TestRunSyncSharedAuditSetupChecksPersistedInvariantBeforeSuccess(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	var output bytes.Buffer
	err := runSyncSharedAuditSetupAs(
		context.Background(),
		newSyncTestCommand(&bytes.Buffer{}, &output),
		humanSyncDetail(),
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
			Yes:                true,
		},
		syncSharedAuditSetupDeps{
			Load: func(string) (*syncpkg.Config, error) {
				return config, nil
			},
			MountPath: func(
				context.Context,
				syncpkg.Runner,
				string,
			) (string, error) {
				return "/stores/jasp", nil
			},
			EnsurePolicy: func(string) (string, error) {
				return "/config/shared-policy.yaml", nil
			},
			ResolveRemote: func(
				context.Context,
				syncpkg.Runner,
				*syncpkg.Config,
				syncSharedAuditSetupOptions,
				string,
			) (string, error) {
				return "/remotes/jasp-audit.git", nil
			},
			NewClient: func(
				string,
				string,
				string,
				string,
			) (teamAuditClient, error) {
				return fakeTeamAuditClient{}, nil
			},
			Update: func(
				context.Context,
				string,
				string,
				syncpkg.TeamAuditConfig,
			) (*syncpkg.Config, error) {
				// Simulate a buggy/stale persistence dependency returning a
				// config without the requested team-audit stanza.
				return config, nil
			},
			OpenAudit: testSyncAuditOpener(t, auditPath),
		},
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"persisted team audit config does not match requested state",
	) {
		t.Fatalf("error = %v, want persisted invariant failure", err)
	}
	if output.Len() != 0 {
		t.Fatalf("success output was written before invariant check: %q", output.String())
	}
	rows := readSyncAuditRows(t, auditPath)
	for _, row := range rows {
		if row.Result == audit.ResultOK {
			t.Fatalf("OK audit was written before invariant check: %+v", rows)
		}
	}
}

func TestSyncSharedAuditTargetUsesConfigOwnerAndRejectsStoreRemote(t *testing.T) {
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	target, err := syncSharedAuditTarget(
		config,
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
		},
	)
	if err != nil {
		t.Fatalf("syncSharedAuditTarget: %v", err)
	}
	if target != "jasp/mys-audit" {
		t.Fatalf("target = %q, want jasp/mys-audit", target)
	}

	_, err = syncSharedAuditTarget(
		config,
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			RemoteURL:          "/remotes/jasp-store.git",
			Repo:               defaultTeamAuditRepo,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("collision error = %v, want audit/store separation", err)
	}
}

type syncSequenceRunner struct {
	calls     []string
	responses map[string][]stubResp
}

func (runner *syncSequenceRunner) Run(
	_ context.Context,
	name string,
	args ...string,
) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	runner.calls = append(runner.calls, call)
	responses := runner.responses[call]
	if len(responses) == 0 {
		return nil, fmt.Errorf("unexpected command: %s", call)
	}
	response := responses[0]
	runner.responses[call] = responses[1:]
	return response.out, response.err
}

func installSyncTestGH(t *testing.T) {
	binaryDir := t.TempDir()
	ghPath := filepath.Join(binaryDir, "gh")
	if err := os.WriteFile(ghPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write fake gh: %v", err)
	}
	t.Setenv("PATH", binaryDir)
}

func sharedAuditGitHubTestConfig() *syncpkg.Config {
	return &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
}

func TestEnsureSyncSharedAuditRemoteAcceptsExistingPrivateRepo(t *testing.T) {
	installSyncTestGH(t)
	runner := &stubRunner{handlers: map[string]stubResp{
		"gh repo view jasp/mys-audit --json visibility --jq .visibility": {
			out: []byte("PRIVATE\n"),
		},
	}}
	remoteURL, err := ensureSyncSharedAuditRemote(
		context.Background(),
		runner,
		sharedAuditGitHubTestConfig(),
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
			UseHTTPS:           true,
		},
		syncSharedTestFingerprint,
	)
	if err != nil {
		t.Fatalf("ensureSyncSharedAuditRemote: %v", err)
	}
	if remoteURL != "https://github.com/jasp/mys-audit.git" {
		t.Fatalf("remote URL = %q, want HTTPS GitHub URL", remoteURL)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "repo create") {
			t.Fatalf("existing private repository was recreated: %v", runner.calls)
		}
	}
}

func TestEnsureSyncSharedAuditRemoteRejectsNonPrivateRepo(t *testing.T) {
	for _, visibility := range []string{"PUBLIC", "INTERNAL"} {
		t.Run(strings.ToLower(visibility), func(t *testing.T) {
			installSyncTestGH(t)
			runner := &stubRunner{handlers: map[string]stubResp{
				"gh repo view jasp/mys-audit --json visibility --jq .visibility": {
					out: []byte(visibility + "\n"),
				},
			}}
			_, err := ensureSyncSharedAuditRemote(
				context.Background(),
				runner,
				sharedAuditGitHubTestConfig(),
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					Repo:               defaultTeamAuditRepo,
					UseHTTPS:           true,
				},
				syncSharedTestFingerprint,
			)
			if err == nil || !strings.Contains(err.Error(), "must be PRIVATE") {
				t.Fatalf("error = %v, want PRIVATE visibility rejection", err)
			}
		})
	}
}

func TestEnsureSyncSharedAuditRemoteFailsClosedOnVisibilityQuery(t *testing.T) {
	installSyncTestGH(t)
	runner := &stubRunner{handlers: map[string]stubResp{
		"gh repo view jasp/mys-audit --json visibility --jq .visibility": {
			err: errors.New("API unavailable"),
		},
	}}
	_, err := ensureSyncSharedAuditRemote(
		context.Background(),
		runner,
		sharedAuditGitHubTestConfig(),
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
			UseHTTPS:           true,
		},
		syncSharedTestFingerprint,
	)
	if err == nil || !strings.Contains(err.Error(), "API unavailable") {
		t.Fatalf("error = %v, want visibility query failure", err)
	}
}

func TestEnsureSyncSharedAuditRemoteCreatesAndConfirmsPrivateGitHubRepo(t *testing.T) {
	installSyncTestGH(t)
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	runner := &syncSequenceRunner{responses: map[string][]stubResp{
		"gh repo view jasp/mys-audit --json visibility --jq .visibility": {
			{err: errors.New("not found")},
			{out: []byte("PRIVATE\n")},
		},
		"gh repo create jasp/mys-audit --private": {
			{out: []byte("created\n")},
		},
	}}
	remoteURL, err := ensureSyncSharedAuditRemote(
		context.Background(),
		runner,
		config,
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			Repo:               defaultTeamAuditRepo,
			UseHTTPS:           true,
		},
		syncSharedTestFingerprint,
	)
	if err != nil {
		t.Fatalf("ensureSyncSharedAuditRemote: %v", err)
	}
	if remoteURL != "https://github.com/jasp/mys-audit.git" {
		t.Fatalf("remote URL = %q, want HTTPS GitHub URL", remoteURL)
	}
	if !slices.Contains(
		runner.calls,
		"gh repo create jasp/mys-audit --private",
	) {
		t.Fatalf("private repo create call missing: %v", runner.calls)
	}
	viewCalls := 0
	for _, call := range runner.calls {
		if strings.Contains(call, "repo view") {
			viewCalls++
		}
	}
	if viewCalls != 2 {
		t.Fatalf("visibility query calls = %d, want 2: %v", viewCalls, runner.calls)
	}
}

func TestEnsureSyncSharedAuditRemoteRejectsUnconfirmedCreatedRepo(t *testing.T) {
	tests := []struct {
		name         string
		confirmation stubResp
		wantError    string
	}{
		{
			name:         "created public",
			confirmation: stubResp{out: []byte("PUBLIC\n")},
			wantError:    "must be PRIVATE",
		},
		{
			name:         "confirmation query failed",
			confirmation: stubResp{err: errors.New("API unavailable")},
			wantError:    "API unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installSyncTestGH(t)
			runner := &syncSequenceRunner{responses: map[string][]stubResp{
				"gh repo view jasp/mys-audit --json visibility --jq .visibility": {
					{err: errors.New("not found")},
					test.confirmation,
				},
				"gh repo create jasp/mys-audit --private": {
					{out: []byte("created\n")},
				},
			}}
			_, err := ensureSyncSharedAuditRemote(
				context.Background(),
				runner,
				sharedAuditGitHubTestConfig(),
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					Repo:               defaultTeamAuditRepo,
					UseHTTPS:           true,
				},
				syncSharedTestFingerprint,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRunSyncSharedAuditSetupRejectsVisibilityBeforeMutation(t *testing.T) {
	tests := []struct {
		name     string
		response stubResp
	}{
		{name: "public", response: stubResp{out: []byte("PUBLIC\n")}},
		{name: "internal", response: stubResp{out: []byte("INTERNAL\n")}},
		{name: "malformed", response: stubResp{out: []byte("UNKNOWN\n")}},
		{name: "query error", response: stubResp{err: errors.New("API unavailable")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installSyncTestGH(t)
			auditPath := filepath.Join(t.TempDir(), "audit.sqlite")
			var policyCalls, clientCalls, configCalls int
			runner := &stubRunner{handlers: map[string]stubResp{
				"gh repo view jasp/mys-audit --json visibility --jq .visibility": test.response,
			}}
			err := runSyncSharedAuditSetupAs(
				context.Background(),
				newSyncTestCommand(&bytes.Buffer{}, &bytes.Buffer{}),
				humanSyncDetail(),
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					Repo:               defaultTeamAuditRepo,
					UseHTTPS:           true,
					Yes:                true,
				},
				syncSharedAuditSetupDeps{
					Runner: runner,
					Load: func(string) (*syncpkg.Config, error) {
						return sharedAuditGitHubTestConfig(), nil
					},
					MountPath: func(
						context.Context,
						syncpkg.Runner,
						string,
					) (string, error) {
						return "/stores/jasp", nil
					},
					EnsurePolicy: func(string) (string, error) {
						policyCalls++
						return "", errors.New("must not run")
					},
					ResolveRemote: ensureSyncSharedAuditRemote,
					NewClient: func(
						string,
						string,
						string,
						string,
					) (teamAuditClient, error) {
						clientCalls++
						return nil, errors.New("must not run")
					},
					Update: func(
						context.Context,
						string,
						string,
						syncpkg.TeamAuditConfig,
					) (*syncpkg.Config, error) {
						configCalls++
						return nil, errors.New("must not run")
					},
					OpenAudit: testSyncAuditOpener(t, auditPath),
				},
			)
			if err == nil {
				t.Fatal("expected visibility failure")
			}
			if policyCalls != 0 || clientCalls != 0 || configCalls != 0 {
				t.Fatalf(
					"mutations after visibility failure: policy=%d client=%d config=%d",
					policyCalls,
					clientCalls,
					configCalls,
				)
			}
		})
	}
}

func TestEnsureSyncSharedAuditRemoteChecksDirectGitHubRepo(t *testing.T) {
	tests := []struct {
		name       string
		response   stubResp
		wantError  string
		wantRemote string
	}{
		{
			name:       "private",
			response:   stubResp{out: []byte("PRIVATE\n")},
			wantRemote: "git@github.com:jasp/mys-audit.git",
		},
		{
			name:      "public",
			response:  stubResp{out: []byte("PUBLIC\n")},
			wantError: "must be PRIVATE",
		},
		{
			name:      "internal",
			response:  stubResp{out: []byte("INTERNAL\n")},
			wantError: "must be PRIVATE",
		},
		{
			name:      "query error",
			response:  stubResp{err: errors.New("API unavailable")},
			wantError: "API unavailable",
		},
		{
			name:      "not found",
			response:  stubResp{err: errors.New("not found")},
			wantError: "repository is unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installSyncTestGH(t)
			runner := &stubRunner{handlers: map[string]stubResp{
				"gh repo view jasp/mys-audit --json visibility --jq .visibility": test.response,
			}}
			remoteURL, err := ensureSyncSharedAuditRemote(
				context.Background(),
				runner,
				sharedAuditGitHubTestConfig(),
				syncSharedAuditSetupOptions{
					Mount:              "jasp",
					SigningFingerprint: syncSharedTestFingerprint,
					RemoteURL:          "git@github.com:jasp/mys-audit.git",
					Repo:               defaultTeamAuditRepo,
				},
				syncSharedTestFingerprint,
			)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf(
						"error = %v, want substring %q",
						err,
						test.wantError,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensure direct GitHub audit remote: %v", err)
			}
			if remoteURL != test.wantRemote {
				t.Fatalf("remote URL = %q, want %q", remoteURL, test.wantRemote)
			}
		})
	}
}

func TestParseGitHubAuditRemote(t *testing.T) {
	tests := []struct {
		name       string
		remote     string
		wantOwner  string
		wantRepo   string
		wantGitHub bool
		wantError  bool
	}{
		{
			name:       "scp SSH",
			remote:     "git@github.com:jasp/mys-audit.git",
			wantOwner:  "jasp",
			wantRepo:   "mys-audit",
			wantGitHub: true,
		},
		{
			name:       "SSH URL",
			remote:     "ssh://git@github.com/jasp/mys-audit.git",
			wantOwner:  "jasp",
			wantRepo:   "mys-audit",
			wantGitHub: true,
		},
		{
			name:       "HTTPS URL",
			remote:     "https://github.com/jasp/mys-audit.git",
			wantOwner:  "jasp",
			wantRepo:   "mys-audit",
			wantGitHub: true,
		},
		{
			name:   "non GitHub",
			remote: "ssh://git@gitlab.example/jasp/mys-audit.git",
		},
		{
			name:       "nested GitHub path",
			remote:     "https://github.com/jasp/team/mys-audit.git",
			wantGitHub: true,
			wantError:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner, repo, isGitHub, err := parseGitHubAuditRemote(test.remote)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError=%v", err, test.wantError)
			}
			if owner != test.wantOwner ||
				repo != test.wantRepo ||
				isGitHub != test.wantGitHub {
				t.Fatalf(
					"parse = %q %q %v, want %q %q %v",
					owner,
					repo,
					isGitHub,
					test.wantOwner,
					test.wantRepo,
					test.wantGitHub,
				)
			}
		})
	}
}

func TestEnsureSyncSharedAuditRemoteAcceptsValidatedDirectRemote(t *testing.T) {
	config := &syncpkg.Config{
		Version: 1,
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	remoteURL, err := ensureSyncSharedAuditRemote(
		context.Background(),
		nil,
		config,
		syncSharedAuditSetupOptions{
			Mount:              "jasp",
			SigningFingerprint: syncSharedTestFingerprint,
			RemoteURL:          "/remotes/jasp-audit.git",
			Repo:               defaultTeamAuditRepo,
		},
		syncSharedTestFingerprint,
	)
	if err != nil {
		t.Fatalf("ensureSyncSharedAuditRemote: %v", err)
	}
	if remoteURL != "/remotes/jasp-audit.git" {
		t.Fatalf("remote URL = %q", remoteURL)
	}
}

type syncSharedAuditPolicyFixture struct {
	configPath string
	policyPath string
	auditPath  string
}

func cloneSyncConfigWithTeamAudit(
	t *testing.T,
	source *syncpkg.Config,
	remoteURL string,
	fingerprint string,
) *syncpkg.Config {
	t.Helper()
	clone := *source
	clone.Remotes = append([]syncpkg.StoreRemote(nil), source.Remotes...)
	remote, ok := clone.Remote("jasp")
	if !ok {
		t.Fatal("source sync config lacks jasp remote")
	}
	for index := range clone.Remotes {
		if clone.Remotes[index].Mount == remote.Mount {
			clone.Remotes[index].TeamAudit = &syncpkg.TeamAuditConfig{
				URL:                remoteURL,
				SigningFingerprint: fingerprint,
			}
			break
		}
	}
	return &clone
}

func newSyncSharedAuditPolicyFixture(
	t *testing.T,
) syncSharedAuditPolicyFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	configPath, err := syncpkg.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	config := &syncpkg.Config{
		Version: 1,
		Owner:   "jasp",
		Remotes: []syncpkg.StoreRemote{{
			Mount:  "jasp",
			URL:    "/remotes/jasp-store.git",
			Shared: true,
		}},
	}
	if err := syncpkg.Save(configPath, config); err != nil {
		t.Fatalf("save initial sync config: %v", err)
	}
	policyPath, err := policy.SharedPath("jasp")
	if err != nil {
		t.Fatal(err)
	}
	return syncSharedAuditPolicyFixture{
		configPath: configPath,
		policyPath: policyPath,
		auditPath:  filepath.Join(t.TempDir(), "audit.sqlite"),
	}
}

func (fixture syncSharedAuditPolicyFixture) options() syncSharedAuditSetupOptions {
	return syncSharedAuditSetupOptions{
		Mount:              "jasp",
		SigningFingerprint: syncSharedTestFingerprint,
		RemoteURL:          "/remotes/jasp-audit.git",
		Repo:               defaultTeamAuditRepo,
		Yes:                true,
	}
}

func (fixture syncSharedAuditPolicyFixture) deps(
	t *testing.T,
	provision func(context.Context) error,
) syncSharedAuditSetupDeps {
	t.Helper()
	return syncSharedAuditSetupDeps{
		Load: syncpkg.Load,
		MountPath: func(
			context.Context,
			syncpkg.Runner,
			string,
		) (string, error) {
			return "/stores/jasp", nil
		},
		ResolveRemote: func(
			context.Context,
			syncpkg.Runner,
			*syncpkg.Config,
			syncSharedAuditSetupOptions,
			string,
		) (string, error) {
			return "/remotes/jasp-audit.git", nil
		},
		NewClient: func(
			string,
			string,
			string,
			string,
		) (teamAuditClient, error) {
			return fakeTeamAuditClient{provision: provision}, nil
		},
		BeginPolicy: func(
			ctx context.Context,
			mount string,
		) (syncSharedPolicyTransaction, error) {
			return policy.BeginSharedDefaultContext(ctx, mount)
		},
		Update:    syncpkg.UpdateSharedTeamAuditAndSave,
		OpenAudit: testSyncAuditOpener(t, fixture.auditPath),
	}
}

func (fixture syncSharedAuditPolicyFixture) configBytes(
	t *testing.T,
) []byte {
	t.Helper()
	data, err := os.ReadFile(fixture.configPath)
	if err != nil {
		t.Fatalf("read sync config: %v", err)
	}
	return data
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
