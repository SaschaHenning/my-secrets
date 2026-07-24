package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
)

const testFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var testSnapshot = teamaudit.Snapshot{
	StoreCommit:      strings.Repeat("a", 40),
	PolicyHash:       strings.Repeat("b", 64),
	TeamKeysHash:     strings.Repeat("c", 64),
	RecipientSetHash: strings.Repeat("d", 64),
}

type fakeTeamAuditManager struct {
	mu              sync.Mutex
	snapshot        teamaudit.Snapshot
	preflightErr    error
	appendErr       error
	preflightCalls  int
	appendCalls     [][]teamaudit.Input
	appendSnapshots []teamaudit.Snapshot
	appendCtxErrors []error
	appendDeadlines []bool
	waitForDeadline bool
	mutateEvent     func(teamaudit.Event) teamaudit.Event
}

func (manager *fakeTeamAuditManager) Preflight(
	context.Context,
) (teamaudit.Snapshot, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.preflightCalls++
	if manager.preflightErr != nil {
		return teamaudit.Snapshot{}, manager.preflightErr
	}
	return manager.snapshot, nil
}

func (manager *fakeTeamAuditManager) AppendBatch(
	ctx context.Context,
	snapshot teamaudit.Snapshot,
	inputs []teamaudit.Input,
) ([]teamaudit.Event, error) {
	manager.mu.Lock()
	cloned := append([]teamaudit.Input(nil), inputs...)
	manager.appendCalls = append(manager.appendCalls, cloned)
	manager.appendSnapshots = append(manager.appendSnapshots, snapshot)
	manager.appendCtxErrors = append(manager.appendCtxErrors, ctx.Err())
	_, hasDeadline := ctx.Deadline()
	manager.appendDeadlines = append(manager.appendDeadlines, hasDeadline)
	appendErr := manager.appendErr
	waitForDeadline := manager.waitForDeadline
	mutateEvent := manager.mutateEvent
	manager.mu.Unlock()
	if waitForDeadline {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if appendErr != nil {
		return nil, appendErr
	}
	events := make([]teamaudit.Event, 0, len(inputs))
	for _, input := range inputs {
		event := teamaudit.Event{
			EventID:          input.EventID,
			Mount:            store.OrgOf(input.Path),
			Path:             input.Path,
			Action:           input.Action,
			Actor:            teamaudit.Actor{Kind: input.ActorKind, AgentLabel: input.AgentLabel},
			Result:           "success",
			StoreCommit:      snapshot.StoreCommit,
			PolicyHash:       snapshot.PolicyHash,
			TeamKeysHash:     snapshot.TeamKeysHash,
			RecipientSetHash: snapshot.RecipientSetHash,
		}
		if mutateEvent != nil {
			event = mutateEvent(event)
		}
		events = append(events, event)
	}
	return events, nil
}

func (manager *fakeTeamAuditManager) appendContexts() ([]error, []bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append(
		[]error(nil),
		manager.appendCtxErrors...,
	), append([]bool(nil), manager.appendDeadlines...)
}

func (manager *fakeTeamAuditManager) calls() (
	int,
	[][]teamaudit.Input,
) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	calls := make([][]teamaudit.Input, len(manager.appendCalls))
	for index := range manager.appendCalls {
		calls[index] = append(
			[]teamaudit.Input(nil),
			manager.appendCalls[index]...,
		)
	}
	return manager.preflightCalls, calls
}

func (manager *fakeTeamAuditManager) snapshots() []teamaudit.Snapshot {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]teamaudit.Snapshot(nil), manager.appendSnapshots...)
}

func allowPolicy(pattern string) *policy.Policy {
	return &policy.Policy{Actors: map[string]policy.Rules{
		"human":       {Allow: []string{pattern}},
		"script":      {Allow: []string{pattern}},
		"ai":          {Allow: []string{pattern}},
		"claude-code": {Allow: []string{pattern}},
	}}
}

func denyPolicy() *policy.Policy {
	return &policy.Policy{Actors: map[string]policy.Rules{
		"human":       {Allow: []string{}},
		"script":      {Allow: []string{}},
		"ai":          {Allow: []string{}},
		"claude-code": {Allow: []string{}},
	}}
}

func sharedRemote(mount string) syncpkg.StoreRemote {
	return syncpkg.StoreRemote{
		Mount:  mount,
		URL:    "file:///tmp/" + mount + "-store.git",
		Shared: true,
		TeamAudit: &syncpkg.TeamAuditConfig{
			URL:                "file:///tmp/" + mount + "-audit.git",
			SigningFingerprint: testFingerprint,
		},
	}
}

func gatedRuntime(
	actor caller.Detail,
	config *syncpkg.Config,
	managers map[string]*fakeTeamAuditManager,
) *teamReadRuntime {
	return &teamReadRuntime{
		loadGlobalPolicy: func() (*policy.Policy, error) {
			return allowPolicy("**"), nil
		},
		loadSyncConfig: func() (*syncpkg.Config, error) {
			return config, nil
		},
		loadSharedPolicy: func(mount string) (*policy.Policy, string, error) {
			return allowPolicy(mount + "/**"), testSnapshot.PolicyHash, nil
		},
		acquireAnchor: func(
			ctx context.Context,
		) (context.Context, func() error, error) {
			if ctx == nil {
				ctx = context.Background()
			}
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			return ctx, func() error { return nil }, nil
		},
		resolveMountPath: func(
			_ context.Context,
			mount string,
		) (string, error) {
			return filepath.Join("/tmp", mount+"-store"), nil
		},
		newAuditManager: func(
			mount string,
			_ syncpkg.TeamAuditConfig,
			_ string,
		) (teamAuditManager, error) {
			manager, ok := managers[mount]
			if !ok {
				return nil, errors.New("missing fake manager")
			}
			return manager, nil
		},
		identifyCaller: func(string) caller.Detail { return actor },
	}
}

func runtimeWithInjectedStore(
	runtime *teamReadRuntime,
	injected store.Interface,
) *teamReadRuntime {
	runtime.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		return &accessStoreSession{
			store:            injected,
			resolveMountPath: runtime.resolveMountPath,
		}, nil
	}
	return runtime
}

func gatedApp(
	t *testing.T,
	actor caller.Detail,
	entries ...*store.Entry,
) (*App, *fake.Store, *fakeTeamAuditManager, *bytes.Buffer) {
	t.Helper()
	manager := &fakeTeamAuditManager{snapshot: testSnapshot}
	config := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{sharedRemote("jasp")},
	}
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	fakeStore := fake.NewWithEntries(entries...)
	stderr := &bytes.Buffer{}
	runtime := gatedRuntime(
		actor,
		config,
		map[string]*fakeTeamAuditManager{"jasp": manager},
	)
	app := &App{
		Store:     fakeStore,
		Audit:     log,
		Policy:    allowPolicy("**"),
		Override:  "test",
		Stderr:    stderr,
		teamReads: runtimeWithInjectedStore(runtime, fakeStore),
	}
	return app, fakeStore, manager, stderr
}

func aiActor() caller.Detail {
	return caller.Detail{Kind: caller.KindAI, AgentLabel: "claude-code"}
}

func TestSharedReadGate_AllDecryptingPaths(t *testing.T) {
	totpEntry := &store.Entry{
		Path:          "jasp/totp",
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:    "GitHub",
		TOTPLabel:     "sascha",
		TOTPAlgorithm: "SHA1",
		TOTPDigits:    6,
		TOTPPeriod:    30,
	}
	cases := []struct {
		name   string
		action string
		entry  *store.Entry
		run    func(*App) error
	}{
		{
			name: "get", action: "get",
			entry: &store.Entry{Path: "jasp/one", Password: "secret"},
			run: func(app *App) error {
				_, err := app.Get(context.Background(), "jasp/one")
				return err
			},
		},
		{
			name: "totp", action: "totp_generate", entry: totpEntry,
			run: func(app *App) error {
				details, err := app.GenerateTOTPDetails(
					context.Background(),
					"jasp/totp",
					time.Unix(1_700_000_000, 0),
				)
				if err == nil &&
					(details.Issuer != "GitHub" || details.Label != "sascha") {
					return errors.New("TOTP metadata missing")
				}
				return err
			},
		},
		{
			name: "browse", action: "list_detail",
			entry: &store.Entry{Path: "jasp/one", Password: "secret"},
			run: func(app *App) error {
				_, err := app.BrowseDetailed(context.Background(), "jasp")
				return err
			},
		},
		{
			name: "inspect", action: "inspect",
			entry: &store.Entry{Path: "jasp/one", Password: "secret"},
			run: func(app *App) error {
				_, err := app.Inspect(context.Background(), "jasp/one")
				return err
			},
		},
		{
			name: "search metadata", action: "search",
			entry: &store.Entry{Path: "jasp/one", Username: "needle", Password: "secret"},
			run: func(app *App) error {
				_, err := app.Search(context.Background(), "needle")
				return err
			},
		},
		{
			name: "rotate existing", action: "rotate_read",
			entry: &store.Entry{Path: "jasp/one", Password: "secret"},
			run: func(app *App) error {
				return app.Rotate(context.Background(), "jasp/one", "new")
			},
		},
		{
			name: "search domain", action: "search_domain",
			entry: &store.Entry{
				Path: "jasp/one", Domain: "example.com", Password: "secret",
			},
			run: func(app *App) error {
				_, _, err := app.SearchByDomain(
					context.Background(), "example.com", false,
				)
				return err
			},
		},
		{
			name: "doctor rotation", action: "doctor_rotation",
			entry: &store.Entry{Path: "jasp/one", Password: "secret"},
			run: func(app *App) error {
				_, err := app.DoctorRotationEntries(context.Background())
				return err
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, _, manager, _ := gatedApp(t, aiActor(), testCase.entry)
			if err := testCase.run(app); err != nil {
				t.Fatalf("operation: %v", err)
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 1 || len(appendCalls) != 1 {
				t.Fatalf(
					"preflight=%d append=%d, want 1/1",
					preflightCalls,
					len(appendCalls),
				)
			}
			if len(appendCalls[0]) != 1 ||
				appendCalls[0][0].Action != testCase.action {
				t.Fatalf("inputs = %+v", appendCalls)
			}
			if appendCalls[0][0].EventID == "" {
				t.Fatal("audit input omitted event ID")
			}
			snapshots := manager.snapshots()
			if len(snapshots) != 1 || snapshots[0] != testSnapshot {
				t.Fatalf("append snapshots = %+v, want preflight snapshot", snapshots)
			}
		})
	}
}

func TestSharedReadGate_AIFailuresReturnNoOutput(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*fakeTeamAuditManager)
	}{
		{
			name: "preflight",
			configure: func(manager *fakeTeamAuditManager) {
				manager.preflightErr = errors.New(
					"file:///private/audit.git TOPSECRET",
				)
			},
		},
		{
			name: "append",
			configure: func(manager *fakeTeamAuditManager) {
				manager.appendErr = errors.New(
					"file:///private/audit.git TOPSECRET",
				)
			},
		},
		{
			name: "snapshot race",
			configure: func(manager *fakeTeamAuditManager) {
				manager.mutateEvent = func(event teamaudit.Event) teamaudit.Event {
					event.StoreCommit = strings.Repeat("f", 40)
					return event
				}
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
				&store.Entry{Path: "jasp/two", Password: "SECOND"},
			)
			testCase.configure(manager)
			entries, err := app.BrowseDetailed(context.Background(), "jasp")
			if !errors.Is(err, ErrTeamAuditUnavailable) {
				t.Fatalf("error = %v", err)
			}
			if entries != nil {
				t.Fatalf("partial entries returned: %+v", entries)
			}
			if strings.Contains(err.Error(), "TOPSECRET") ||
				strings.Contains(err.Error(), "file://") {
				t.Fatalf("internal data leaked in error: %v", err)
			}
			if testCase.name == "preflight" &&
				fakeStore.GetCallCount() != 0 {
				t.Fatalf(
					"preflight failure decrypted %d entries",
					fakeStore.GetCallCount(),
				)
			}
		})
	}
}

func TestSharedReadGate_AIPreflightFailureFailsClosedAcrossDecryptingPaths(
	t *testing.T,
) {
	secretSentinel := "sentinel-" + "secret-must-not-leak"
	failingURL := "https://audit.invalid/" + secretSentinel
	path := "jasp/" + "production"
	totpPath := "jasp/" + "totp"
	cases := []struct {
		name string
		run  func(*App) (bool, error)
	}{
		{
			name: "get",
			run: func(application *App) (bool, error) {
				entry, err := application.Get(context.Background(), path)
				return entry == nil, err
			},
		},
		{
			name: "generate TOTP details",
			run: func(application *App) (bool, error) {
				details, err := application.GenerateTOTPDetails(
					context.Background(), totpPath, time.Unix(1_700_000_000, 0),
				)
				return details == (TOTPDetails{}), err
			},
		},
		{
			name: "browse detailed",
			run: func(application *App) (bool, error) {
				entries, err := application.BrowseDetailed(context.Background(), "jasp")
				return entries == nil, err
			},
		},
		{
			name: "inspect",
			run: func(application *App) (bool, error) {
				entry, err := application.Inspect(context.Background(), path)
				return entry == nil, err
			},
		},
		{
			name: "search",
			run: func(application *App) (bool, error) {
				paths, err := application.Search(context.Background(), "needle")
				return paths == nil, err
			},
		},
		{
			name: "rotate",
			run: func(application *App) (bool, error) {
				err := application.Rotate(context.Background(), path, "replacement")
				return true, err
			},
		},
		{
			name: "search by domain",
			run: func(application *App) (bool, error) {
				matches, similar, err := application.SearchByDomain(
					context.Background(), "example.invalid", true,
				)
				return matches == nil && similar == nil, err
			},
		},
		{
			name: "doctor rotation entries",
			run: func(application *App) (bool, error) {
				entries, err := application.DoctorRotationEntries(context.Background())
				return entries == nil, err
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			application, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{
					Path: path, Username: "needle", Domain: "example.invalid",
					Password: secretSentinel,
				},
				&store.Entry{
					Path:          totpPath,
					Kind:          store.KindTOTP,
					Password:      "JBSWY3DPEHPK3PXP",
					TOTPIssuer:    "Example",
					TOTPLabel:     "production",
					TOTPAlgorithm: "SHA1",
					TOTPDigits:    6,
					TOTPPeriod:    30,
				},
			)
			manager.preflightErr = errors.New("preflight failed for " + failingURL)

			empty, err := testCase.run(application)
			if !errors.Is(err, ErrTeamAuditUnavailable) {
				t.Fatalf("error = %v, want %v", err, ErrTeamAuditUnavailable)
			}
			if err.Error() != ErrTeamAuditUnavailable.Error() {
				t.Fatalf("error = %q, want generic failure", err)
			}
			if !empty {
				t.Fatal("operation returned a partial plaintext result")
			}
			if strings.Contains(err.Error(), secretSentinel) ||
				strings.Contains(err.Error(), failingURL) ||
				strings.Contains(err.Error(), path) {
				t.Fatalf("error leaked a secret, URL, or path: %q", err)
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 1 || len(appendCalls) != 0 {
				t.Fatalf(
					"audit calls = preflight:%d append:%d, want 1/0",
					preflightCalls,
					len(appendCalls),
				)
			}
			if fakeStore.GetCallCount() != 0 {
				t.Fatalf(
					"store decrypted %d entries after a failed preflight",
					fakeStore.GetCallCount(),
				)
			}
		})
	}
}

func TestSharedReadGate_DecryptFailureReturnsNoPartialResultsAcrossPaths(
	t *testing.T,
) {
	path := "jasp/production"
	totpPath := "jasp/totp"
	cases := []struct {
		name string
		run  func(*App) (bool, error)
	}{
		{
			name: "get",
			run: func(application *App) (bool, error) {
				entry, err := application.Get(context.Background(), path)
				return entry == nil, err
			},
		},
		{
			name: "generate TOTP details",
			run: func(application *App) (bool, error) {
				details, err := application.GenerateTOTPDetails(
					context.Background(), totpPath, time.Unix(1_700_000_000, 0),
				)
				return details == (TOTPDetails{}), err
			},
		},
		{
			name: "browse detailed",
			run: func(application *App) (bool, error) {
				entries, err := application.BrowseDetailed(context.Background(), "jasp")
				return entries == nil, err
			},
		},
		{
			name: "inspect",
			run: func(application *App) (bool, error) {
				entry, err := application.Inspect(context.Background(), path)
				return entry == nil, err
			},
		},
		{
			name: "search metadata",
			run: func(application *App) (bool, error) {
				paths, err := application.Search(context.Background(), "needle")
				return paths == nil, err
			},
		},
		{
			name: "rotate",
			run: func(application *App) (bool, error) {
				err := application.Rotate(context.Background(), path, "replacement")
				return true, err
			},
		},
		{
			name: "search by domain",
			run: func(application *App) (bool, error) {
				matches, similar, err := application.SearchByDomain(
					context.Background(), "example.invalid", true,
				)
				return matches == nil && similar == nil, err
			},
		},
		{
			name: "doctor rotation entries",
			run: func(application *App) (bool, error) {
				entries, err := application.DoctorRotationEntries(context.Background())
				return entries == nil, err
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			application, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{
					Path: path, Username: "needle", Domain: "example.invalid",
					Password: "protected-value",
				},
				&store.Entry{
					Path:          totpPath,
					Kind:          store.KindTOTP,
					Password:      "JBSWY3DPEHPK3PXP",
					TOTPIssuer:    "Example",
					TOTPLabel:     "production",
					TOTPAlgorithm: "SHA1",
					TOTPDigits:    6,
					TOTPPeriod:    30,
				},
			)
			decryptErr := errors.New("decrypt unavailable")
			fakeStore.GetErr = decryptErr

			empty, err := testCase.run(application)
			if !errors.Is(err, decryptErr) {
				t.Fatalf("error = %v, want %v", err, decryptErr)
			}
			if !empty {
				t.Fatal("operation returned a partial plaintext result")
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 1 || len(appendCalls) != 0 {
				t.Fatalf(
					"audit calls = preflight:%d append:%d, want 1/0",
					preflightCalls,
					len(appendCalls),
				)
			}
			if fakeStore.GetCallCount() != 1 {
				t.Fatalf("decryptions = %d, want 1", fakeStore.GetCallCount())
			}
		})
	}
}

func TestOpenAppWithTeamReadRuntimeClosesOwnedResources(t *testing.T) {
	auditLog, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	fakeStore := fake.New()
	closedAudit := false
	runtime := gatedRuntime(
		aiActor(),
		&syncpkg.Config{Version: 1},
		map[string]*fakeTeamAuditManager{},
	)
	application, err := openApp(nil, "claude-code", appOpenDependencies{
		openStore: func(context.Context) (store.Interface, error) {
			return fakeStore, nil
		},
		openAudit: func() (*audit.Log, error) {
			return auditLog, nil
		},
		loadPolicy: func() (*policy.Policy, error) {
			return allowPolicy("**"), nil
		},
		closeAudit: func(context.Context, *audit.Log) error {
			closedAudit = true
			return auditLog.Close()
		},
		teamReads: func() *teamReadRuntime { return runtime },
	})
	if err != nil {
		t.Fatalf("open app: %v", err)
	}
	if application.Store != fakeStore || application.Audit != auditLog ||
		application.teamReads != runtime {
		t.Fatal("open app did not install its dependencies")
	}
	if err := application.Close(context.Background()); err != nil {
		t.Fatalf("close app: %v", err)
	}
	if !closedAudit {
		t.Fatal("close app did not close the audit log")
	}
}

func TestOpenAppRejectsIncompleteDependenciesAndCleansOpenedResources(
	t *testing.T,
) {
	cases := []struct {
		name      string
		configure func(*appOpenDependencies, *closeRecordingStore, *audit.Log)
		want      string
		wantClose bool
	}{
		{
			name: "missing store opener",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openStore = nil
			},
			want: "store opener is required",
		},
		{
			name: "store opener error",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openStore = func(context.Context) (store.Interface, error) {
					return nil, errors.New("store unavailable")
				}
			},
			want: "store unavailable",
		},
		{
			name: "nil store",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openStore = func(context.Context) (store.Interface, error) {
					return nil, nil
				}
			},
			want: "store opener returned nil",
		},
		{
			name: "missing audit opener",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openAudit = nil
			},
			want:      "audit opener is required",
			wantClose: true,
		},
		{
			name: "audit opener error",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openAudit = func() (*audit.Log, error) {
					return nil, errors.New("audit unavailable")
				}
			},
			want:      "audit unavailable",
			wantClose: true,
		},
		{
			name: "nil audit log",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.openAudit = func() (*audit.Log, error) {
					return nil, nil
				}
			},
			want:      "audit opener returned nil",
			wantClose: true,
		},
		{
			name: "missing policy loader",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.loadPolicy = nil
			},
			want:      "policy loader is required",
			wantClose: true,
		},
		{
			name: "policy loader error",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.loadPolicy = func() (*policy.Policy, error) {
					return nil, errors.New("policy unavailable")
				}
			},
			want:      "policy unavailable",
			wantClose: true,
		},
		{
			name: "nil policy result",
			configure: func(
				dependencies *appOpenDependencies,
				_ *closeRecordingStore,
				_ *audit.Log,
			) {
				dependencies.loadPolicy = func() (*policy.Policy, error) {
					return nil, nil
				}
			},
			want:      ErrPolicyUnavailable.Error(),
			wantClose: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			auditLog, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
			if err != nil {
				t.Fatalf("open audit log: %v", err)
			}
			closedAudit := false
			t.Cleanup(func() {
				if !closedAudit {
					_ = auditLog.Close()
				}
			})
			probe := &closeRecordingStore{Store: fake.New()}
			dependencies := appOpenDependencies{
				openStore: func(context.Context) (store.Interface, error) {
					return probe, nil
				},
				openAudit: func() (*audit.Log, error) { return auditLog, nil },
				loadPolicy: func() (*policy.Policy, error) {
					return allowPolicy("**"), nil
				},
				closeAudit: func(context.Context, *audit.Log) error {
					closedAudit = true
					return auditLog.Close()
				},
			}
			testCase.configure(&dependencies, probe, auditLog)

			application, err := openApp(context.Background(), "claude-code", dependencies)
			if application != nil {
				t.Fatalf("application = %+v, want nil", application)
			}
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
			calls, closeCtxErr, hasDeadline := probe.closeState()
			if testCase.wantClose {
				if calls != 1 || closeCtxErr != nil || !hasDeadline {
					t.Fatalf(
						"store cleanup = calls:%d err:%v deadline:%t",
						calls,
						closeCtxErr,
						hasDeadline,
					)
				}
			} else if calls != 0 {
				t.Fatalf("store cleanup = %d calls, want none", calls)
			}
		})
	}
}

func TestSharedReadGate_AIAuditSetupFailuresStopBeforeDecrypt(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*App)
	}{
		{
			name: "missing team audit config",
			configure: func(application *App) {
				application.teamReads.loadSyncConfig = func() (*syncpkg.Config, error) {
					return &syncpkg.Config{
						Version: 1,
						Layout:  syncpkg.LayoutPerOrg,
						Remotes: []syncpkg.StoreRemote{{Mount: "jasp", Shared: true}},
					}, nil
				}
			},
		},
		{
			name: "mount path resolution",
			configure: func(application *App) {
				application.teamReads.resolveMountPath = func(
					context.Context,
					string,
				) (string, error) {
					return "", errors.New("mount path unavailable")
				}
			},
		},
		{
			name: "audit manager construction",
			configure: func(application *App) {
				application.teamReads.newAuditManager = func(
					string,
					syncpkg.TeamAuditConfig,
					string,
				) (teamAuditManager, error) {
					return nil, errors.New("audit manager unavailable")
				}
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			application, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/production", Password: "protected-value"},
			)
			testCase.configure(application)

			entry, err := application.Get(context.Background(), "jasp/production")
			if !errors.Is(err, ErrTeamAuditUnavailable) {
				t.Fatalf("error = %v, want %v", err, ErrTeamAuditUnavailable)
			}
			if entry != nil {
				t.Fatalf("entry = %+v, want no plaintext", entry)
			}
			if fakeStore.GetCallCount() != 0 {
				t.Fatalf("decryptions = %d, want 0", fakeStore.GetCallCount())
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 0 || len(appendCalls) != 0 {
				t.Fatalf(
					"audit calls = preflight:%d append:%d, want 0/0",
					preflightCalls,
					len(appendCalls),
				)
			}
		})
	}
}

func TestProductionTeamReadRuntimeWithBoundStoreUsesDependencies(t *testing.T) {
	opened := false
	resolved := false
	backing := fake.New()
	runtime := productionTeamReadRuntimeWithBoundStore(boundStoreDependencies{
		openSession: func(
			context.Context,
			[]string,
		) (*accessStoreSession, error) {
			opened = true
			return &accessStoreSession{
				store: backing,
				resolveMountPath: func(context.Context, string) (string, error) {
					return "/tmp/jasp-store", nil
				},
			}, nil
		},
		resolveMountPath: func(context.Context, string) (string, error) {
			resolved = true
			return "/tmp/jasp-store", nil
		},
	})

	session, err := runtime.openStore(context.Background(), []string{"jasp"})
	if err != nil || session == nil || session.store != backing {
		t.Fatalf("open store = %v, %v", session, err)
	}
	if !opened {
		t.Fatal("bound store opener was not called")
	}
	path, err := runtime.resolveMountPath(context.Background(), "jasp")
	if err != nil || path != "/tmp/jasp-store" || !resolved {
		t.Fatalf("resolve mount path = %q, %v, called:%t", path, err, resolved)
	}
	manager, err := runtime.newAuditManager(
		"jasp",
		syncpkg.TeamAuditConfig{
			URL:                "file:///tmp/jasp-audit.git",
			SigningFingerprint: testFingerprint,
		},
		"/tmp/jasp-store",
	)
	if err != nil || manager == nil {
		t.Fatalf("new audit manager = %v, %v", manager, err)
	}
}

func TestProductionTeamReadRuntimeBuildsAuditManager(t *testing.T) {
	runtime := productionTeamReadRuntime()
	manager, err := runtime.newAuditManager(
		"jasp",
		syncpkg.TeamAuditConfig{
			URL:                "file:///tmp/jasp-audit.git",
			SigningFingerprint: testFingerprint,
		},
		"/tmp/jasp-store",
	)
	if err != nil || manager == nil {
		t.Fatalf("new audit manager = %v, %v", manager, err)
	}
}

func TestProductionTeamReadRuntimeWithBoundStoreRejectsNilSession(t *testing.T) {
	runtime := productionTeamReadRuntimeWithBoundStore(boundStoreDependencies{
		openSession: func(
			context.Context,
			[]string,
		) (*accessStoreSession, error) {
			return nil, nil
		},
		resolveMountPath: func(context.Context, string) (string, error) {
			return "/tmp/jasp-store", nil
		},
	})

	session, err := runtime.openStore(context.Background(), []string{"jasp"})
	if session != nil || err == nil ||
		!strings.Contains(err.Error(), "returned nil") {
		t.Fatalf("open store = %v, %v", session, err)
	}
}

func TestSharedReadGate_AIIncompleteRuntimeFailsClosedBeforeDecrypt(t *testing.T) {
	backing := fake.NewWithEntries(&store.Entry{
		Path: "jasp/production", Password: "protected-value",
	})
	application := &App{
		Store:    backing,
		Override: "claude-code",
		teamReads: &teamReadRuntime{
			identifyCaller: func(string) caller.Detail { return aiActor() },
		},
	}

	entry, err := application.Get(context.Background(), "jasp/production")
	if !errors.Is(err, ErrTeamAuditUnavailable) {
		t.Fatalf("error = %v, want %v", err, ErrTeamAuditUnavailable)
	}
	if entry != nil {
		t.Fatalf("entry = %+v, want no plaintext", entry)
	}
	if backing.GetCallCount() != 0 {
		t.Fatalf("decryptions = %d, want 0", backing.GetCallCount())
	}
}

func TestSharedReadGate_AIAnchorFailuresStopBeforeDecrypt(t *testing.T) {
	cases := []struct {
		name    string
		acquire acquireAnchorContextFunc
	}{
		{
			name: "acquire error",
			acquire: func(context.Context) (context.Context, func() error, error) {
				return nil, nil, errors.New("anchor unavailable")
			},
		},
		{
			name: "incomplete lease",
			acquire: func(context.Context) (context.Context, func() error, error) {
				return context.Background(), nil, nil
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			application, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/production", Password: "protected-value"},
			)
			application.teamReads.acquireAnchor = testCase.acquire

			entry, err := application.Get(context.Background(), "jasp/production")
			if !errors.Is(err, ErrTeamAuditUnavailable) {
				t.Fatalf("error = %v, want %v", err, ErrTeamAuditUnavailable)
			}
			if err.Error() != ErrTeamAuditUnavailable.Error() || entry != nil {
				t.Fatalf("result = entry:%+v error:%v", entry, err)
			}
			if fakeStore.GetCallCount() != 0 {
				t.Fatalf("decryptions = %d, want 0", fakeStore.GetCallCount())
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 0 || len(appendCalls) != 0 {
				t.Fatalf(
					"audit calls = preflight:%d append:%d, want 0/0",
					preflightCalls,
					len(appendCalls),
				)
			}
		})
	}
}

func TestSharedReadGate_ListFailuresReturnNoPartialResults(t *testing.T) {
	cases := []struct {
		name string
		run  func(*App) (bool, error)
	}{
		{
			name: "browse detailed",
			run: func(application *App) (bool, error) {
				entries, err := application.BrowseDetailed(context.Background(), "jasp")
				return entries == nil, err
			},
		},
		{
			name: "search",
			run: func(application *App) (bool, error) {
				paths, err := application.Search(context.Background(), "needle")
				return paths == nil, err
			},
		},
		{
			name: "search by domain",
			run: func(application *App) (bool, error) {
				matches, similar, err := application.SearchByDomain(
					context.Background(), "example.invalid", true,
				)
				return matches == nil && similar == nil, err
			},
		},
		{
			name: "doctor rotation entries",
			run: func(application *App) (bool, error) {
				entries, err := application.DoctorRotationEntries(context.Background())
				return entries == nil, err
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			application, fakeStore, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/production", Password: "protected-value"},
			)
			listErr := errors.New("store listing unavailable")
			fakeStore.ListErr = listErr

			empty, err := testCase.run(application)
			if !errors.Is(err, listErr) {
				t.Fatalf("error = %v, want %v", err, listErr)
			}
			if !empty {
				t.Fatal("operation returned a partial plaintext result")
			}
			if fakeStore.GetCallCount() != 0 {
				t.Fatalf("decryptions = %d, want 0", fakeStore.GetCallCount())
			}
			preflightCalls, appendCalls := manager.calls()
			if preflightCalls != 0 || len(appendCalls) != 0 {
				t.Fatalf(
					"audit calls = preflight:%d append:%d, want 0/0",
					preflightCalls,
					len(appendCalls),
				)
			}
		})
	}
}

func TestSearchByDomain_EmptyQueryDoesNotStartAnAccessOperation(t *testing.T) {
	application := &App{teamReads: &teamReadRuntime{}}
	matches, similar, err := application.SearchByDomain(context.Background(), "  ", true)
	if err != nil || matches != nil || similar != nil {
		t.Fatalf("empty query = matches:%v similar:%v err:%v", matches, similar, err)
	}
}

func TestSharedReadGate_DoctorCleanupFailureSuppressesEntries(t *testing.T) {
	application, fakeStore, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/production", Password: "protected-value"},
	)
	closeErr := errors.New("store cleanup unavailable")
	fakeStore.CloseErr = closeErr

	entries, err := application.DoctorRotationEntries(context.Background())
	if !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want %v", err, closeErr)
	}
	if entries != nil {
		t.Fatalf("entries = %+v, want no plaintext after cleanup failure", entries)
	}
	preflightCalls, appendCalls := manager.calls()
	if preflightCalls != 1 || len(appendCalls) != 1 {
		t.Fatalf(
			"audit calls = preflight:%d append:%d, want 1/1",
			preflightCalls,
			len(appendCalls),
		)
	}
}

func TestSharedReadGate_ValidatesEverySnapshotField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*teamaudit.Event)
	}{
		{
			name: "store commit",
			mutate: func(event *teamaudit.Event) {
				event.StoreCommit = strings.Repeat("1", 40)
			},
		},
		{
			name: "policy hash",
			mutate: func(event *teamaudit.Event) {
				event.PolicyHash = strings.Repeat("1", 64)
			},
		},
		{
			name: "team keys hash",
			mutate: func(event *teamaudit.Event) {
				event.TeamKeysHash = strings.Repeat("1", 64)
			},
		},
		{
			name: "recipient set hash",
			mutate: func(event *teamaudit.Event) {
				event.RecipientSetHash = strings.Repeat("1", 64)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, _, manager, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/one", Password: "secret"},
			)
			manager.mutateEvent = func(event teamaudit.Event) teamaudit.Event {
				testCase.mutate(&event)
				return event
			}
			entry, err := app.Get(context.Background(), "jasp/one")
			if !errors.Is(err, ErrTeamAuditUnavailable) || entry != nil {
				t.Fatalf("entry=%+v error=%v", entry, err)
			}
		})
	}
}

func TestValidateAuditEventsRejectsMismatchedEventID(t *testing.T) {
	inputs := []teamaudit.Input{{
		EventID:    "10000000-0000-4000-8000-000000000001",
		Path:       "jasp/one",
		Action:     "get",
		ActorKind:  "ai",
		AgentLabel: "claude-code",
	}}
	events := []teamaudit.Event{{
		EventID:          "10000000-0000-4000-8000-000000000002",
		Mount:            "jasp",
		Path:             "jasp/one",
		Action:           "get",
		Actor:            teamaudit.Actor{Kind: "ai", AgentLabel: "claude-code"},
		Result:           "success",
		StoreCommit:      testSnapshot.StoreCommit,
		PolicyHash:       testSnapshot.PolicyHash,
		TeamKeysHash:     testSnapshot.TeamKeysHash,
		RecipientSetHash: testSnapshot.RecipientSetHash,
	}}

	if err := validateAuditEvents("jasp", inputs, events, testSnapshot); err == nil {
		t.Fatal("mismatched event ID was accepted")
	}
}

func TestSharedReadGate_HumanAndScriptAuditFailureIsAdvisory(t *testing.T) {
	for _, kind := range []caller.Kind{caller.KindHuman, caller.KindScript} {
		for _, failure := range []string{"preflight", "append"} {
			t.Run(string(kind)+"/"+failure, func(t *testing.T) {
				app, _, manager, stderr := gatedApp(
					t,
					caller.Detail{Kind: kind},
					&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
				)
				if failure == "preflight" {
					manager.preflightErr = errors.New(
						"file:///private/audit.git TOPSECRET",
					)
				} else {
					manager.appendErr = errors.New(
						"file:///private/audit.git TOPSECRET",
					)
				}
				entry, err := app.Get(context.Background(), "jasp/one")
				if err != nil || entry == nil || entry.Password != "TOPSECRET" {
					t.Fatalf("entry=%+v error=%v", entry, err)
				}
				warning := stderr.String()
				if warning != teamAuditWarning {
					t.Fatalf("warning = %q", warning)
				}
				if strings.Contains(warning, "TOPSECRET") ||
					strings.Contains(warning, "file://") {
					t.Fatalf("internal data leaked in warning: %q", warning)
				}
			})
		}
	}
}

func TestSharedReadGate_ConfigUnavailableFailsClosedForAllActors(t *testing.T) {
	actors := []caller.Detail{
		aiActor(),
		{Kind: caller.KindHuman},
		{Kind: caller.KindScript},
	}
	configFailures := []struct {
		name string
		load func() (*syncpkg.Config, error)
	}{
		{
			name: "load error",
			load: func() (*syncpkg.Config, error) {
				return nil, errors.New("file:///private/audit.git TOPSECRET")
			},
		},
		{
			name: "missing config",
			load: func() (*syncpkg.Config, error) {
				return nil, nil
			},
		},
		{
			name: "validation error",
			load: func() (*syncpkg.Config, error) {
				return &syncpkg.Config{
					Version: 1,
					Layout:  syncpkg.LayoutPerOrg,
					Remotes: []syncpkg.StoreRemote{
						sharedRemote("jasp"),
						sharedRemote("jasp"),
					},
				}, nil
			},
		},
	}

	for _, actor := range actors {
		for _, configFailure := range configFailures {
			t.Run(string(actor.Kind)+"/"+configFailure.name, func(t *testing.T) {
				app, fakeStore, _, stderr := gatedApp(
					t,
					actor,
					&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
				)
				releaseCalls := 0
				app.teamReads.acquireAnchor = func(
					ctx context.Context,
				) (context.Context, func() error, error) {
					return ctx, func() error {
						releaseCalls++
						return nil
					}, nil
				}
				openCalls := 0
				app.teamReads.openStore = func(
					context.Context,
					[]string,
				) (*accessStoreSession, error) {
					openCalls++
					return nil, errors.New("store opener must not run")
				}
				app.teamReads.loadSyncConfig = configFailure.load

				entry, err := app.Get(context.Background(), "jasp/one")

				want := ErrPolicyUnavailable
				if actor.Kind == caller.KindAI {
					want = ErrTeamAuditUnavailable
				}
				if !errors.Is(err, want) || entry != nil {
					t.Fatalf("entry=%+v error=%v, want %v without plaintext", entry, err, want)
				}
				if fakeStore.GetCallCount() != 0 || openCalls != 0 {
					t.Fatalf(
						"store access = get:%d open:%d, want 0/0",
						fakeStore.GetCallCount(),
						openCalls,
					)
				}
				if releaseCalls != 1 {
					t.Fatalf("outer anchor releases = %d, want 1", releaseCalls)
				}
				if stderr.Len() != 0 {
					t.Fatalf("config failure emitted advisory warning: %q", stderr.String())
				}
				if strings.Contains(err.Error(), "TOPSECRET") ||
					strings.Contains(err.Error(), "private") {
					t.Fatalf("config error leaked internal detail: %v", err)
				}
			})
		}
	}
}

func TestSharedReadGate_MissingConfigLoaderFailsClosed(t *testing.T) {
	app, fakeStore, _, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
	)
	app.teamReads.loadSyncConfig = nil
	storeOpens := 0
	app.teamReads.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		storeOpens++
		return nil, errors.New("store opener must not run")
	}

	entry, err := app.Get(context.Background(), "jasp/one")

	if !errors.Is(err, ErrTeamAuditUnavailable) || entry != nil {
		t.Fatalf("entry=%+v error=%v, want generic failure without plaintext", entry, err)
	}
	if fakeStore.GetCallCount() != 0 || storeOpens != 0 {
		t.Fatalf(
			"store access = get:%d open:%d, want 0/0",
			fakeStore.GetCallCount(),
			storeOpens,
		)
	}
}

func TestSharedReadGate_AuditBackendErrorsFollowActorMode(t *testing.T) {
	cases := []struct {
		name      string
		actor     caller.Detail
		configure func(*App)
		wantError bool
	}{
		{
			name:  "AI mount error",
			actor: aiActor(),
			configure: func(app *App) {
				app.teamReads.resolveMountPath = func(
					context.Context,
					string,
				) (string, error) {
					return "", errors.New(
						"/private/store TOPSECRET",
					)
				}
			},
			wantError: true,
		},
		{
			name:  "script mount error",
			actor: caller.Detail{Kind: caller.KindScript},
			configure: func(app *App) {
				app.teamReads.resolveMountPath = func(
					context.Context,
					string,
				) (string, error) {
					return "", errors.New(
						"/private/store TOPSECRET",
					)
				}
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, fakeStore, _, stderr := gatedApp(
				t,
				testCase.actor,
				&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
			)
			testCase.configure(app)
			entry, err := app.Get(context.Background(), "jasp/one")
			if testCase.wantError {
				if !errors.Is(err, ErrTeamAuditUnavailable) || entry != nil {
					t.Fatalf("entry=%+v error=%v", entry, err)
				}
				if fakeStore.GetCallCount() != 0 {
					t.Fatalf(
						"fail-closed error decrypted %d entries",
						fakeStore.GetCallCount(),
					)
				}
				if strings.Contains(err.Error(), "TOPSECRET") ||
					strings.Contains(err.Error(), "private") {
					t.Fatalf("internal data leaked in error: %v", err)
				}
				return
			}
			if err != nil || entry == nil || entry.Password != "TOPSECRET" {
				t.Fatalf("entry=%+v error=%v", entry, err)
			}
			if stderr.String() != teamAuditWarning {
				t.Fatalf("warning = %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "TOPSECRET") ||
				strings.Contains(stderr.String(), "private") {
				t.Fatalf("internal data leaked in warning: %q", stderr.String())
			}
		})
	}
}

func TestSharedReadGate_PolicyDeniesBeforeDecrypt(t *testing.T) {
	app, fakeStore, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "secret"},
	)
	app.teamReads.loadSharedPolicy = func(
		string,
	) (*policy.Policy, string, error) {
		return denyPolicy(), testSnapshot.PolicyHash, nil
	}
	entry, err := app.Get(context.Background(), "jasp/one")
	var denied *ErrDenied
	if !errors.As(err, &denied) || entry != nil {
		t.Fatalf("entry=%+v error=%v", entry, err)
	}
	if fakeStore.GetCallCount() != 0 {
		t.Fatalf("policy denial decrypted %d entries", fakeStore.GetCallCount())
	}
	preflightCalls, appendCalls := manager.calls()
	if preflightCalls != 0 || len(appendCalls) != 0 {
		t.Fatalf("audit ran after policy denial: %d %+v", preflightCalls, appendCalls)
	}
}

func TestSharedReadGate_MissingSharedPolicyFailsClosedAcrossOperations(
	t *testing.T,
) {
	cases := []struct {
		name string
		run  func(*App) error
	}{
		{
			name: "list",
			run: func(app *App) error {
				_, err := app.List(context.Background(), "jasp")
				return err
			},
		},
		{
			name: "history",
			run: func(app *App) error {
				_, err := app.History(context.Background(), "jasp/one", 1)
				return err
			},
		},
		{
			name: "add",
			run: func(app *App) error {
				return app.Add(
					context.Background(),
					&store.Entry{Path: "jasp/new", Password: "new"},
				)
			},
		},
		{
			name: "rotate",
			run: func(app *App) error {
				return app.Rotate(context.Background(), "jasp/one", "new")
			},
		},
		{
			name: "remove",
			run: func(app *App) error {
				return app.Remove(context.Background(), "jasp/one")
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, fakeStore, _, _ := gatedApp(
				t,
				aiActor(),
				&store.Entry{Path: "jasp/one", Password: "secret"},
			)
			app.teamReads.loadSharedPolicy = func(
				string,
			) (*policy.Policy, string, error) {
				return nil, "", errors.New("missing")
			}
			if err := testCase.run(app); !errors.Is(err, ErrPolicyUnavailable) {
				t.Fatalf("error = %v", err)
			}
			if fakeStore.GetCallCount() != 0 {
				t.Fatalf("operation decrypted %d entries", fakeStore.GetCallCount())
			}
			if fakeStore.Len() != 1 {
				t.Fatalf("operation mutated store, len=%d", fakeStore.Len())
			}
		})
	}
}

func TestSharedReadGate_BatchesExactlyOncePerMount(t *testing.T) {
	jaspManager := &fakeTeamAuditManager{snapshot: testSnapshot}
	teamManager := &fakeTeamAuditManager{snapshot: testSnapshot}
	config := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{
			sharedRemote("jasp"),
			sharedRemote("team"),
		},
	}
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appStore := fake.NewWithEntries(
		&store.Entry{Path: "jasp/one", Password: "one"},
		&store.Entry{Path: "jasp/two", Password: "two"},
		&store.Entry{Path: "team/three", Password: "three"},
	)
	runtime := gatedRuntime(
		aiActor(),
		config,
		map[string]*fakeTeamAuditManager{
			"jasp": jaspManager,
			"team": teamManager,
		},
	)
	app := &App{
		Store:     appStore,
		Audit:     log,
		Policy:    allowPolicy("**"),
		teamReads: runtimeWithInjectedStore(runtime, appStore),
	}
	entries, err := app.BrowseDetailed(context.Background(), "")
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries=%d error=%v", len(entries), err)
	}
	_, jaspCalls := jaspManager.calls()
	_, teamCalls := teamManager.calls()
	if len(jaspCalls) != 1 || len(jaspCalls[0]) != 2 {
		t.Fatalf("jasp calls = %+v", jaspCalls)
	}
	if len(teamCalls) != 1 || len(teamCalls[0]) != 1 {
		t.Fatalf("team calls = %+v", teamCalls)
	}
}

func TestSharedReadGate_AIFinalizesEveryMountAfterAppendFailures(
	t *testing.T,
) {
	mounts := []string{"alpha", "beta", "gamma"}
	managers := map[string]*fakeTeamAuditManager{
		"alpha": {snapshot: testSnapshot, appendErr: errors.New("alpha private")},
		"beta":  {snapshot: testSnapshot},
		"gamma": {snapshot: testSnapshot, appendErr: errors.New("gamma private")},
	}
	config := &syncpkg.Config{Version: 1, Layout: syncpkg.LayoutPerOrg}
	entries := make([]*store.Entry, 0, len(mounts))
	for _, mount := range mounts {
		config.Remotes = append(config.Remotes, sharedRemote(mount))
		entries = append(entries, &store.Entry{
			Path:     mount + "/one",
			Password: mount + "-secret",
		})
	}
	appStore := fake.NewWithEntries(entries...)
	runtime := gatedRuntime(aiActor(), config, managers)
	app := &App{
		Store:     appStore,
		Policy:    allowPolicy("**"),
		teamReads: runtimeWithInjectedStore(runtime, appStore),
	}

	got, err := app.BrowseDetailed(context.Background(), "")

	if got != nil || !errors.Is(err, ErrTeamAuditUnavailable) {
		t.Fatalf("entries/error = %+v/%v", got, err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatalf("AI error leaked append detail: %v", err)
	}
	for _, mount := range mounts {
		_, appendCalls := managers[mount].calls()
		if len(appendCalls) != 1 {
			t.Fatalf("%s append calls = %d, want 1", mount, len(appendCalls))
		}
	}
}

func TestSharedReadGate_HumanFinalizesAfterMiddleTimeout(t *testing.T) {
	mounts := []string{"alpha", "beta", "gamma"}
	managers := map[string]*fakeTeamAuditManager{
		"alpha": {snapshot: testSnapshot},
		"beta":  {snapshot: testSnapshot, waitForDeadline: true},
		"gamma": {snapshot: testSnapshot},
	}
	config := &syncpkg.Config{Version: 1, Layout: syncpkg.LayoutPerOrg}
	entries := make([]*store.Entry, 0, len(mounts))
	for _, mount := range mounts {
		config.Remotes = append(config.Remotes, sharedRemote(mount))
		entries = append(entries, &store.Entry{
			Path:     mount + "/one",
			Password: mount + "-secret",
		})
	}
	appStore := fake.NewWithEntries(entries...)
	stderr := &bytes.Buffer{}
	runtime := gatedRuntime(
		caller.Detail{Kind: caller.KindHuman},
		config,
		managers,
	)
	runtime.finalizeTimeout = 20 * time.Millisecond
	app := &App{
		Store:     appStore,
		Policy:    allowPolicy("**"),
		Stderr:    stderr,
		teamReads: runtimeWithInjectedStore(runtime, appStore),
	}

	got, err := app.BrowseDetailed(context.Background(), "")

	if err != nil || len(got) != len(mounts) {
		t.Fatalf("entries/error = %+v/%v", got, err)
	}
	for _, mount := range mounts {
		_, appendCalls := managers[mount].calls()
		if len(appendCalls) != 1 {
			t.Fatalf("%s append calls = %d, want 1", mount, len(appendCalls))
		}
	}
	if gotWarnings := stderr.String(); gotWarnings != teamAuditWarning {
		t.Fatalf("warnings = %q, want one generic warning", gotWarnings)
	}
}

func TestOpenBoundAccessStoreUsesStoreSessionBindingAcrossABA(t *testing.T) {
	observedPath := t.TempDir()
	loadedPath := t.TempDir()
	probe := &closeRecordingStore{Store: fake.New()}
	livePath := observedPath
	resolverCalls := 0
	resolveLive := func() string {
		resolverCalls++
		return livePath
	}

	session, err := openBoundAccessStore(
		context.Background(),
		[]string{"jasp"},
		boundStoreDependencies{
			openSession: func(
				context.Context,
				[]string,
			) (*accessStoreSession, error) {
				before := resolveLive()
				livePath = loadedPath
				frozenPath := livePath
				livePath = observedPath
				after := resolveLive()
				if before != observedPath || after != observedPath {
					return nil, errors.New("test did not model A-to-B-to-A")
				}
				return &accessStoreSession{
					store: probe,
					resolveMountPath: func(
						context.Context,
						string,
					) (string, error) {
						return frozenPath, nil
					},
				}, nil
			},
			resolveMountPath: func(context.Context, string) (string, error) {
				return resolveLive(), nil
			},
		},
	)
	if err != nil {
		t.Fatalf("open bound store: %v", err)
	}
	got, err := session.resolveMountPath(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("resolve session mount: %v", err)
	}
	want := loadedPath
	if got != want {
		t.Fatalf(
			"session path = %q, want atomic store binding %q (live resolver calls %d)",
			got,
			want,
			resolverCalls,
		)
	}
	if resolverCalls != 2 {
		t.Fatalf("live resolver calls = %d, want only modeled A/A observations", resolverCalls)
	}
}

func TestOpenBoundAccessStoreClosesIncompleteSessionWithDetachedContext(
	t *testing.T,
) {
	closeErr := errors.New("close failed")
	probe := &closeRecordingStore{
		Store:    fake.New(),
		closeErr: closeErr,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session, err := openBoundAccessStore(
		ctx,
		[]string{"jasp"},
		boundStoreDependencies{
			openSession: func(
				context.Context,
				[]string,
			) (*accessStoreSession, error) {
				return &accessStoreSession{store: probe}, nil
			},
		},
	)
	if session != nil || err == nil || !errors.Is(err, closeErr) {
		t.Fatalf("session/error = %+v/%v, want incomplete and close errors", session, err)
	}
	closeCalls, closeCtxErr, hasDeadline := probe.closeState()
	if closeCalls != 1 || closeCtxErr != nil || !hasDeadline {
		t.Fatalf(
			"incomplete close = calls:%d err:%v deadline:%t",
			closeCalls,
			closeCtxErr,
			hasDeadline,
		)
	}
}

func TestOpenBoundAccessStoreAcceptsNilContext(t *testing.T) {
	mountPath := t.TempDir()
	probe := &closeRecordingStore{Store: fake.New()}

	session, err := openBoundAccessStore(
		nil,
		[]string{"jasp"},
		boundStoreDependencies{
			openSession: func(
				context.Context,
				[]string,
			) (*accessStoreSession, error) {
				return &accessStoreSession{
					store: probe,
					resolveMountPath: func(
						context.Context,
						string,
					) (string, error) {
						return mountPath, nil
					},
				}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("open bound store: %v", err)
	}
	got, err := session.resolveMountPath(context.Background(), "jasp")
	if err != nil {
		t.Fatalf("resolve session mount: %v", err)
	}
	want := mountPath
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestAccessOperationTeamAuditedMountsAreSortedAndScoped(t *testing.T) {
	operation := &accessOperation{config: &syncpkg.Config{
		Remotes: []syncpkg.StoreRemote{
			sharedRemote("zulu"),
			{Mount: "personal", Shared: false},
			{
				Mount:  "legacy",
				Shared: true,
			},
			sharedRemote("alpha"),
		},
	}}

	got := operation.teamAuditedMounts()

	if want := []string{"alpha", "zulu"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("team-audited mounts = %v, want %v", got, want)
	}
}

func TestSharedReadGate_ReloadsConfigAndPoliciesEveryOperation(t *testing.T) {
	app, _, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "secret"},
	)
	var mu sync.Mutex
	globalLoads := 0
	configLoads := 0
	sharedLoads := 0
	app.teamReads.loadGlobalPolicy = func() (*policy.Policy, error) {
		mu.Lock()
		defer mu.Unlock()
		globalLoads++
		return allowPolicy("**"), nil
	}
	app.teamReads.loadSyncConfig = func() (*syncpkg.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		configLoads++
		return &syncpkg.Config{
			Version: 1,
			Layout:  syncpkg.LayoutPerOrg,
			Remotes: []syncpkg.StoreRemote{sharedRemote("jasp")},
		}, nil
	}
	app.teamReads.loadSharedPolicy = func(
		string,
	) (*policy.Policy, string, error) {
		mu.Lock()
		defer mu.Unlock()
		sharedLoads++
		if sharedLoads == 1 {
			return allowPolicy("jasp/**"), testSnapshot.PolicyHash, nil
		}
		return denyPolicy(), testSnapshot.PolicyHash, nil
	}
	if _, err := app.Get(context.Background(), "jasp/one"); err != nil {
		t.Fatal(err)
	}
	if entry, err := app.Get(context.Background(), "jasp/one"); err == nil ||
		entry != nil {
		t.Fatalf("stale shared policy allowed second read: %+v %v", entry, err)
	}
	if globalLoads != 2 || configLoads != 2 || sharedLoads != 2 {
		t.Fatalf(
			"loads global/config/shared = %d/%d/%d",
			globalLoads,
			configLoads,
			sharedLoads,
		)
	}
	preflightCalls, appendCalls := manager.calls()
	if preflightCalls != 1 || len(appendCalls) != 1 {
		t.Fatalf("audit calls = %d/%d", preflightCalls, len(appendCalls))
	}
}

func TestSharedReadGate_HoldsOuterAnchorAcrossConfigSnapshotAndBoundOpen(
	t *testing.T,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	personal := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{{
			Mount: "jasp",
			URL:   "file:///tmp/jasp-store.git",
		}},
	}
	shared := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{sharedRemote("jasp")},
	}
	var configMu sync.Mutex
	currentConfig := personal
	configReached := make(chan struct{})
	var configOnce sync.Once
	acquireAttempted := make(chan struct{})
	var acquireOnce sync.Once
	acquireGate := make(chan struct{})
	storeOpened := make(chan struct{})
	var storeOnce sync.Once
	manager := &fakeTeamAuditManager{
		snapshot:     testSnapshot,
		preflightErr: errors.New("audit preflight failed"),
	}
	runtime := gatedRuntime(
		aiActor(),
		personal,
		map[string]*fakeTeamAuditManager{"jasp": manager},
	)
	runtime.acquireAnchor = func(
		operationCtx context.Context,
	) (context.Context, func() error, error) {
		acquireOnce.Do(func() { close(acquireAttempted) })
		select {
		case <-acquireGate:
			return operationCtx, func() error { return nil }, nil
		case <-operationCtx.Done():
			return nil, nil, operationCtx.Err()
		}
	}
	runtime.loadSyncConfig = func() (*syncpkg.Config, error) {
		configMu.Lock()
		defer configMu.Unlock()
		configOnce.Do(func() { close(configReached) })
		snapshot := *currentConfig
		snapshot.Remotes = append([]syncpkg.StoreRemote(nil), currentConfig.Remotes...)
		return &snapshot, nil
	}
	backing := fake.NewWithEntries(&store.Entry{
		Path:     "jasp/one",
		Password: "must-not-be-returned",
	})
	runtime.openStore = func(
		_ context.Context,
		_ []string,
	) (*accessStoreSession, error) {
		storeOnce.Do(func() { close(storeOpened) })
		return &accessStoreSession{
			store:            backing,
			resolveMountPath: runtime.resolveMountPath,
		}, nil
	}
	app := &App{
		Store:     backing,
		Policy:    allowPolicy("**"),
		teamReads: runtime,
	}

	type result struct {
		entry *store.Entry
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		entry, getErr := app.Get(ctx, "jasp/one")
		resultCh <- result{entry: entry, err: getErr}
	}()

	select {
	case <-acquireAttempted:
	case <-ctx.Done():
		t.Fatalf("read did not attempt anchor acquisition: %v", ctx.Err())
	}

	configMu.Lock()
	currentConfig = shared
	configMu.Unlock()
	close(acquireGate)
	select {
	case got := <-resultCh:
		if !errors.Is(got.err, ErrTeamAuditUnavailable) || got.entry != nil {
			t.Fatalf(
				"read after personal-to-shared handoff = %+v/%v, want audit failure without plaintext",
				got.entry,
				got.err,
			)
		}
	case <-ctx.Done():
		t.Fatalf(
			"read did not finish after the anchor gate opened: %v",
			ctx.Err(),
		)
	}
	select {
	case <-configReached:
	case <-ctx.Done():
		t.Fatalf("config did not load after writer release: %v", ctx.Err())
	}
	select {
	case <-storeOpened:
	case <-ctx.Done():
		t.Fatalf("store did not open after writer release: %v", ctx.Err())
	}
	preflightCalls, appendCalls := manager.calls()
	if preflightCalls != 1 || len(appendCalls) != 0 {
		t.Fatalf(
			"shared handoff audit calls = %d/%d, want failed preflight only",
			preflightCalls,
			len(appendCalls),
		)
	}
}

func TestHistory_HoldsOuterAnchorAcrossConfigSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	personal := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{{
			Mount: "jasp",
			URL:   "file:///tmp/jasp-store.git",
		}},
	}
	shared := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{sharedRemote("jasp")},
	}
	var configMu sync.Mutex
	currentConfig := personal
	configReached := make(chan struct{})
	var configOnce sync.Once
	acquireAttempted := make(chan struct{})
	var acquireOnce sync.Once
	acquireGate := make(chan struct{})
	runtime := gatedRuntime(
		aiActor(),
		personal,
		map[string]*fakeTeamAuditManager{},
	)
	runtime.acquireAnchor = func(
		operationCtx context.Context,
	) (context.Context, func() error, error) {
		acquireOnce.Do(func() { close(acquireAttempted) })
		select {
		case <-acquireGate:
			return operationCtx, func() error { return nil }, nil
		case <-operationCtx.Done():
			return nil, nil, operationCtx.Err()
		}
	}
	runtime.loadSyncConfig = func() (*syncpkg.Config, error) {
		configMu.Lock()
		defer configMu.Unlock()
		configOnce.Do(func() { close(configReached) })
		snapshot := *currentConfig
		snapshot.Remotes = append([]syncpkg.StoreRemote(nil), currentConfig.Remotes...)
		return &snapshot, nil
	}
	runtime.loadSharedPolicy = func(
		string,
	) (*policy.Policy, string, error) {
		return denyPolicy(), testSnapshot.PolicyHash, nil
	}
	app := &App{teamReads: runtime}

	type result struct {
		revisions int
		err       error
	}
	resultCh := make(chan result, 1)
	go func() {
		revisions, historyErr := app.History(ctx, "jasp/one", 1)
		resultCh <- result{revisions: len(revisions), err: historyErr}
	}()

	select {
	case <-acquireAttempted:
	case <-ctx.Done():
		t.Fatalf("history did not attempt anchor acquisition: %v", ctx.Err())
	}

	configMu.Lock()
	currentConfig = shared
	configMu.Unlock()
	close(acquireGate)
	select {
	case got := <-resultCh:
		var denied *ErrDenied
		if !errors.As(got.err, &denied) || got.revisions != 0 {
			t.Fatalf(
				"history after personal-to-shared handoff = %d/%v, want denied without metadata",
				got.revisions,
				got.err,
			)
		}
	case <-ctx.Done():
		t.Fatalf("history did not finish after the anchor gate opened: %v", ctx.Err())
	}
	select {
	case <-configReached:
	case <-ctx.Done():
		t.Fatalf("history config did not load after the anchor gate opened: %v", ctx.Err())
	}
}

func TestSharedReadGate_AnchorGateCancellationStopsBeforeConfigAndStore(
	t *testing.T,
) {
	deadlineCtx, cancelDeadline := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelDeadline()
	operationCtx, cancelOperation := context.WithCancel(deadlineCtx)
	defer cancelOperation()

	app, fakeStore, _, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "must-not-be-returned"},
	)
	attempted := make(chan struct{})
	gate := make(chan struct{})
	var attemptOnce sync.Once
	configLoads := 0
	storeOpens := 0
	app.teamReads.acquireAnchor = func(
		ctx context.Context,
	) (context.Context, func() error, error) {
		attemptOnce.Do(func() { close(attempted) })
		select {
		case <-gate:
			return ctx, func() error { return nil }, nil
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	app.teamReads.loadSyncConfig = func() (*syncpkg.Config, error) {
		configLoads++
		return nil, errors.New("config loader must not run")
	}
	app.teamReads.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		storeOpens++
		return nil, errors.New("store opener must not run")
	}

	type result struct {
		entry *store.Entry
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		entry, err := app.Get(operationCtx, "jasp/one")
		resultCh <- result{entry: entry, err: err}
	}()

	select {
	case <-attempted:
	case <-deadlineCtx.Done():
		t.Fatalf("read did not attempt anchor acquisition: %v", deadlineCtx.Err())
	}
	cancelOperation()
	select {
	case got := <-resultCh:
		if !errors.Is(got.err, ErrTeamAuditUnavailable) || got.entry != nil {
			t.Fatalf(
				"cancelled read = %+v/%v, want generic failure without plaintext",
				got.entry,
				got.err,
			)
		}
	case <-deadlineCtx.Done():
		t.Fatalf("cancelled read did not return: %v", deadlineCtx.Err())
	}
	if configLoads != 0 || storeOpens != 0 || fakeStore.GetCallCount() != 0 {
		t.Fatalf(
			"cancelled read access = config:%d store-open:%d decrypt:%d, want 0/0/0",
			configLoads,
			storeOpens,
			fakeStore.GetCallCount(),
		)
	}
}

func TestBeginAccessOperation_ReleasesOuterAnchorOnEarlyFailure(t *testing.T) {
	policyErr := errors.New("global policy load failed")
	config := &syncpkg.Config{Version: 1, Layout: syncpkg.LayoutPerOrg}
	runtime := gatedRuntime(
		aiActor(),
		config,
		map[string]*fakeTeamAuditManager{},
	)
	releaseCalls := 0
	runtime.acquireAnchor = func(
		ctx context.Context,
	) (context.Context, func() error, error) {
		return ctx, func() error {
			releaseCalls++
			return nil
		}, nil
	}
	runtime.loadGlobalPolicy = func() (*policy.Policy, error) {
		return nil, policyErr
	}
	runtime.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		t.Fatal("store opener ran after policy failure")
		return nil, nil
	}
	app := &App{teamReads: runtime}

	operation, err := app.beginAccessOperation(
		context.Background(),
		aiActor(),
		true,
		true,
	)

	if operation != nil || !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("operation/error = %+v/%v, want policy failure", operation, err)
	}
	if releaseCalls != 1 {
		t.Fatalf("early failure released outer anchor %d times, want 1", releaseCalls)
	}
}

func TestAccessOperation_CloseReleasesOuterAnchorAfterStoreCloseFailure(
	t *testing.T,
) {
	storeCloseErr := errors.New("store close failed")
	anchorReleaseErr := errors.New("anchor release failed")
	probe := &closeRecordingStore{
		Store:    fake.New(),
		closeErr: storeCloseErr,
	}
	config := &syncpkg.Config{Version: 1, Layout: syncpkg.LayoutPerOrg}
	runtime := gatedRuntime(
		caller.Detail{Kind: caller.KindHuman},
		config,
		map[string]*fakeTeamAuditManager{},
	)
	releaseCalls := 0
	runtime.acquireAnchor = func(
		ctx context.Context,
	) (context.Context, func() error, error) {
		return ctx, func() error {
			releaseCalls++
			closeCalls, _, _ := probe.closeState()
			if closeCalls != 1 {
				t.Fatalf("outer anchor released before store close: %d calls", closeCalls)
			}
			return anchorReleaseErr
		}, nil
	}
	runtime.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		return &accessStoreSession{
			store:            probe,
			resolveMountPath: runtime.resolveMountPath,
		}, nil
	}
	app := &App{teamReads: runtime}

	operation, err := app.beginAccessOperation(
		context.Background(),
		caller.Detail{Kind: caller.KindHuman},
		true,
		true,
	)
	if err != nil {
		t.Fatalf("begin access operation: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for attempt := 1; attempt <= 2; attempt++ {
		err = operation.close(ctx)
		if !errors.Is(err, storeCloseErr) || !errors.Is(err, anchorReleaseErr) {
			t.Fatalf("close attempt %d error = %v", attempt, err)
		}
	}
	closeCalls, closeCtxErr, hasDeadline := probe.closeState()
	if closeCalls != 1 || closeCtxErr != nil || !hasDeadline || releaseCalls != 1 {
		t.Fatalf(
			"close/release = %d/%d, context:%v deadline:%t",
			closeCalls,
			releaseCalls,
			closeCtxErr,
			hasDeadline,
		)
	}
}

func TestSharedReadGate_UsesFreshBoundStoreSessionPerOperation(t *testing.T) {
	app, injected, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "stale"},
	)
	var mu sync.Mutex
	sessions := make([]*closeRecordingStore, 0, 2)
	resolvedPaths := make([]string, 0, 2)
	app.teamReads.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		mu.Lock()
		sessionID := len(sessions) + 1
		session := &closeRecordingStore{
			Store: fake.NewWithEntries(&store.Entry{
				Path:     "jasp/one",
				Password: fmt.Sprintf("session-%d", sessionID),
			}),
		}
		sessions = append(sessions, session)
		mu.Unlock()
		return &accessStoreSession{
			store: session,
			resolveMountPath: func(
				context.Context,
				string,
			) (string, error) {
				return filepath.Join(
					"/tmp",
					fmt.Sprintf("session-%d-store", sessionID),
				), nil
			},
		}, nil
	}
	app.teamReads.newAuditManager = func(
		_ string,
		_ syncpkg.TeamAuditConfig,
		storePath string,
	) (teamAuditManager, error) {
		mu.Lock()
		resolvedPaths = append(resolvedPaths, storePath)
		mu.Unlock()
		return manager, nil
	}

	first, err := app.Get(context.Background(), "jasp/one")
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	second, err := app.Get(context.Background(), "jasp/one")
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if first.Password != "session-1" || second.Password != "session-2" {
		t.Fatalf(
			"session passwords = %q/%q",
			first.Password,
			second.Password,
		)
	}
	if injected.GetCallCount() != 0 {
		t.Fatalf(
			"cached injected store decrypted %d entries",
			injected.GetCallCount(),
		)
	}

	mu.Lock()
	gotSessions := append([]*closeRecordingStore(nil), sessions...)
	gotPaths := append([]string(nil), resolvedPaths...)
	mu.Unlock()
	if len(gotSessions) != 2 {
		t.Fatalf("opened sessions = %d, want 2", len(gotSessions))
	}
	for index, session := range gotSessions {
		calls, closeCtxErr, hasDeadline := session.closeState()
		if calls != 1 || closeCtxErr != nil || !hasDeadline {
			t.Fatalf(
				"session %d close = calls:%d err:%v deadline:%t",
				index+1,
				calls,
				closeCtxErr,
				hasDeadline,
			)
		}
	}
	wantPaths := []string{
		filepath.Join("/tmp", "session-1-store"),
		filepath.Join("/tmp", "session-2-store"),
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("audit mount paths = %v, want %v", gotPaths, wantPaths)
	}
}

func TestSharedReadGate_RejectsUnavailableOrIncompleteStoreSession(
	t *testing.T,
) {
	cases := []struct {
		name       string
		actor      caller.Detail
		open       func(context.Context, []string) (*accessStoreSession, error)
		want       error
		wantDetail string
		probe      *closeRecordingStore
	}{
		{
			name:  "AI open error is generic",
			actor: aiActor(),
			open: func(context.Context, []string) (*accessStoreSession, error) {
				return nil, errors.New("/private/store TOPSECRET")
			},
			want: ErrTeamAuditUnavailable,
		},
		{
			name:  "AI nil session is generic",
			actor: aiActor(),
			open: func(context.Context, []string) (*accessStoreSession, error) {
				return nil, nil
			},
			want: ErrTeamAuditUnavailable,
		},
		{
			name:  "AI missing opener is generic",
			actor: aiActor(),
			open:  nil,
			want:  ErrTeamAuditUnavailable,
		},
		{
			name:  "human open error is preserved",
			actor: caller.Detail{Kind: caller.KindHuman},
			open: func(context.Context, []string) (*accessStoreSession, error) {
				return nil, errors.New("gpg unavailable")
			},
			wantDetail: "gpg unavailable",
		},
		{
			name:  "incomplete session is closed",
			actor: aiActor(),
			probe: &closeRecordingStore{
				Store: fake.NewWithEntries(&store.Entry{
					Path:     "jasp/one",
					Password: "never-read",
				}),
			},
			want: ErrTeamAuditUnavailable,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			app, injected, _, _ := gatedApp(
				t,
				testCase.actor,
				&store.Entry{Path: "jasp/one", Password: "cached"},
			)
			open := testCase.open
			if testCase.probe != nil {
				open = func(
					context.Context,
					[]string,
				) (*accessStoreSession, error) {
					return &accessStoreSession{
						store: testCase.probe,
					}, nil
				}
			}
			app.teamReads.openStore = open

			entry, err := app.Get(context.Background(), "jasp/one")

			if entry != nil {
				t.Fatalf("entry returned: %+v", entry)
			}
			if testCase.want != nil && !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v", err, testCase.want)
			}
			if testCase.wantDetail != "" &&
				(err == nil || !strings.Contains(err.Error(), testCase.wantDetail)) {
				t.Fatalf("error = %v, want %q", err, testCase.wantDetail)
			}
			if testCase.actor.Kind == caller.KindAI && err != nil &&
				(strings.Contains(err.Error(), "TOPSECRET") ||
					strings.Contains(err.Error(), "/private")) {
				t.Fatalf("AI error leaked store detail: %v", err)
			}
			if injected.GetCallCount() != 0 {
				t.Fatalf(
					"cached store decrypted %d entries",
					injected.GetCallCount(),
				)
			}
			if testCase.probe != nil {
				calls, closeCtxErr, hasDeadline := testCase.probe.closeState()
				if calls != 1 || closeCtxErr != nil || !hasDeadline {
					t.Fatalf(
						"incomplete close = calls:%d err:%v deadline:%t",
						calls,
						closeCtxErr,
						hasDeadline,
					)
				}
			}
		})
	}
}

type cancelAfterSuccessfulGetStore struct {
	*closeRecordingStore
	cancel context.CancelFunc
	once   sync.Once
}

func (s *cancelAfterSuccessfulGetStore) Get(
	ctx context.Context,
	path string,
) (*store.Entry, error) {
	entry, err := s.Store.Get(ctx, path)
	if err == nil {
		s.once.Do(s.cancel)
	}
	return entry, err
}

func TestSharedReadGate_MidLoopCancelFinalizesObservedRead(t *testing.T) {
	app, _, manager, _ := gatedApp(t, aiActor())
	ctx, cancel := context.WithCancel(context.Background())
	session := &cancelAfterSuccessfulGetStore{
		closeRecordingStore: &closeRecordingStore{
			Store: fake.NewWithEntries(
				&store.Entry{Path: "jasp/a", Password: "first"},
				&store.Entry{Path: "jasp/b", Password: "second"},
			),
		},
		cancel: cancel,
	}
	app.teamReads.openStore = func(
		context.Context,
		[]string,
	) (*accessStoreSession, error) {
		return &accessStoreSession{
			store: session,
			resolveMountPath: func(
				context.Context,
				string,
			) (string, error) {
				return filepath.Join("/tmp", "cancel-store"), nil
			},
		}, nil
	}

	entries, err := app.BrowseDetailed(ctx, "jasp")

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if entries != nil {
		t.Fatalf("partial plaintext returned: %+v", entries)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 1 ||
		len(appendCalls[0]) != 1 ||
		appendCalls[0][0].Path != "jasp/a" {
		t.Fatalf("append calls = %+v, want exactly first successful read", appendCalls)
	}
	ctxErrors, deadlines := manager.appendContexts()
	if !reflect.DeepEqual(ctxErrors, []error{nil}) ||
		!reflect.DeepEqual(deadlines, []bool{true}) {
		t.Fatalf(
			"append contexts = errors:%v deadlines:%v",
			ctxErrors,
			deadlines,
		)
	}
	closeCalls, closeCtxErr, closeDeadline := session.closeState()
	if closeCalls != 1 || closeCtxErr != nil || !closeDeadline {
		t.Fatalf(
			"session close = calls:%d err:%v deadline:%t",
			closeCalls,
			closeCtxErr,
			closeDeadline,
		)
	}
}

func TestSharedReadGate_DecryptErrorFinalizesPriorRead(t *testing.T) {
	app, fakeStore, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/a", Password: "first"},
		&store.Entry{Path: "jasp/b", Password: "second"},
	)
	decryptErr := errors.New("target decrypt failed")
	fakeStore.GetErrors = map[string]error{"jasp/b": decryptErr}

	entries, err := app.BrowseDetailed(context.Background(), "jasp")

	if !errors.Is(err, decryptErr) {
		t.Fatalf("error = %v, want targeted decrypt error", err)
	}
	if entries != nil {
		t.Fatalf("partial plaintext returned: %+v", entries)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 1 ||
		len(appendCalls[0]) != 1 ||
		appendCalls[0][0].Path != "jasp/a" {
		t.Fatalf("append calls = %+v, want prior successful read", appendCalls)
	}
}

func TestSharedReadGate_SearchDecryptErrorFinalizesPriorRead(t *testing.T) {
	app, fakeStore, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/a", Username: "first"},
		&store.Entry{Path: "jasp/b", Username: "second"},
	)
	decryptErr := errors.New("metadata decrypt failed")
	fakeStore.GetErrors = map[string]error{"jasp/b": decryptErr}

	paths, err := app.Search(context.Background(), "no-path-match")

	if !errors.Is(err, decryptErr) {
		t.Fatalf("error = %v, want metadata decrypt error", err)
	}
	if paths != nil {
		t.Fatalf("partial search results returned: %v", paths)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 1 ||
		len(appendCalls[0]) != 1 ||
		appendCalls[0][0].Path != "jasp/a" {
		t.Fatalf("append calls = %+v, want prior metadata decrypt", appendCalls)
	}
}

func TestSharedReadGate_AppendTimeoutFailsClosedWithoutPlaintext(t *testing.T) {
	app, _, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "TOPSECRET"},
	)
	manager.waitForDeadline = true
	app.teamReads.finalizeTimeout = 20 * time.Millisecond

	started := time.Now()
	entries, err := app.BrowseDetailed(context.Background(), "jasp")
	elapsed := time.Since(started)

	if !errors.Is(err, ErrTeamAuditUnavailable) {
		t.Fatalf("error = %v, want generic audit failure", err)
	}
	if entries != nil {
		t.Fatalf("plaintext returned after append timeout: %+v", entries)
	}
	if elapsed > time.Second {
		t.Fatalf("bounded append took %s", elapsed)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 1 || len(appendCalls[0]) != 1 {
		t.Fatalf("append calls = %+v, want one batch", appendCalls)
	}
}

func TestSharedReadGate_SearchAuditsMetadataDecryptNotPathHit(t *testing.T) {
	app, _, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/needle", Username: "none"},
		&store.Entry{Path: "jasp/metadata", Username: "needle"},
	)
	paths, err := app.Search(context.Background(), "needle")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{"jasp/metadata", "jasp/needle"}) {
		t.Fatalf("paths = %v", paths)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 1 || len(appendCalls[0]) != 1 ||
		appendCalls[0][0].Path != "jasp/metadata" {
		t.Fatalf("append calls = %+v", appendCalls)
	}
}

func TestSearchAuditDoesNotPersistRawQuery(t *testing.T) {
	app, _, _, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Username: "user"},
	)
	query := "https://user:TOPSECRET@example.com"
	if _, err := app.Search(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	rows, err := app.Audit.Tail(
		context.Background(),
		audit.Filter{Action: audit.ActionSearch, Limit: 10},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.Contains(row.Reason, "TOPSECRET") ||
			strings.Contains(row.Reason, "https://") {
			t.Fatalf("raw query persisted in audit row: %q", row.Reason)
		}
	}
	if len(rows) == 0 ||
		!strings.Contains(rows[0].Reason, "query_len=") {
		t.Fatalf("safe query metadata missing: %+v", rows)
	}
}

type latePathSearchStore struct {
	*fake.Store
	lateAllowed bool
}

func (searchStore *latePathSearchStore) SearchObserved(
	_ context.Context,
	_ string,
	allow func(string) bool,
	observer store.SearchObserver,
) ([]string, []string, error) {
	searchStore.lateAllowed = allow("jasp/late")
	if searchStore.lateAllowed {
		observer("jasp/late")
		return []string{"jasp/late"}, nil, nil
	}
	return nil, []string{"jasp/late"}, nil
}

func TestSharedReadGate_SearchDeniesPathAddedAfterAuthorization(t *testing.T) {
	manager := &fakeTeamAuditManager{snapshot: testSnapshot}
	config := &syncpkg.Config{
		Version: 1,
		Layout:  syncpkg.LayoutPerOrg,
		Remotes: []syncpkg.StoreRemote{sharedRemote("jasp")},
	}
	backing := fake.NewWithEntries(
		&store.Entry{Path: "jasp/known", Username: "known"},
	)
	searchStore := &latePathSearchStore{Store: backing}
	runtime := gatedRuntime(
		aiActor(),
		config,
		map[string]*fakeTeamAuditManager{"jasp": manager},
	)
	app := &App{
		Store:     searchStore,
		Policy:    allowPolicy("**"),
		teamReads: runtimeWithInjectedStore(runtime, searchStore),
	}
	paths, err := app.Search(context.Background(), "late")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 || searchStore.lateAllowed {
		t.Fatalf(
			"late path escaped authorization: paths=%v allowed=%t",
			paths,
			searchStore.lateAllowed,
		)
	}
	_, appendCalls := manager.calls()
	if len(appendCalls) != 0 {
		t.Fatalf("late denied path was audited as decrypted: %+v", appendCalls)
	}
}

func TestSharedReadGate_NoSyncDoesNotBypassAudit(t *testing.T) {
	previous := NoSyncFlag
	NoSyncFlag = true
	t.Cleanup(func() { NoSyncFlag = previous })
	app, _, manager, _ := gatedApp(
		t,
		aiActor(),
		&store.Entry{Path: "jasp/one", Password: "secret"},
	)
	if _, err := app.Get(context.Background(), "jasp/one"); err != nil {
		t.Fatal(err)
	}
	preflightCalls, appendCalls := manager.calls()
	if preflightCalls != 1 || len(appendCalls) != 1 {
		t.Fatalf("audit bypassed: %d/%d", preflightCalls, len(appendCalls))
	}
}

func TestGenerateTOTPDetailsUsesOneDecryption(t *testing.T) {
	entry := &store.Entry{
		Path:          "jasp/totp",
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:    "GitHub",
		TOTPLabel:     "sascha",
		TOTPAlgorithm: "SHA1",
		TOTPDigits:    6,
		TOTPPeriod:    30,
	}
	app, fakeStore, _, _ := gatedApp(t, aiActor(), entry)
	details, err := app.GenerateTOTPDetails(
		context.Background(),
		entry.Path,
		time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if details.Issuer != "GitHub" || details.Label != "sascha" ||
		details.Code == "" || details.SecondsLeft == 0 {
		t.Fatalf("details = %+v", details)
	}
	if fakeStore.GetCallCount() != 1 {
		t.Fatalf("decryptions = %d, want 1", fakeStore.GetCallCount())
	}
}

func TestSharedReadGate_ConcurrentWarningsAreSerialized(t *testing.T) {
	app, _, manager, stderr := gatedApp(
		t,
		caller.Detail{Kind: caller.KindHuman},
		&store.Entry{Path: "jasp/one", Password: "secret"},
	)
	manager.preflightErr = errors.New("offline")
	const requests = 16
	var wait sync.WaitGroup
	wait.Add(requests)
	for range requests {
		go func() {
			defer wait.Done()
			if _, err := app.Get(context.Background(), "jasp/one"); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wait.Wait()
	if count := strings.Count(stderr.String(), teamAuditWarning); count != requests {
		t.Fatalf("warning count = %d, want %d", count, requests)
	}
}

func TestProductionTeamReadRuntimeIsComplete(t *testing.T) {
	runtime := productionTeamReadRuntime()
	if runtime == nil ||
		runtime.loadGlobalPolicy == nil ||
		runtime.loadSyncConfig == nil ||
		runtime.loadSharedPolicy == nil ||
		runtime.openStore == nil ||
		runtime.resolveMountPath == nil ||
		runtime.newAuditManager == nil ||
		runtime.identifyCaller == nil {
		t.Fatal("production team-read runtime is incomplete")
	}
}
