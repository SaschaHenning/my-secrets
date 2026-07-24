package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
)

type runtimeCoverageStore struct {
	*fake.Store
	mu               sync.Mutex
	closeCalls       int
	closeErr         error
	closeCtxErr      error
	closeHasDeadline bool
	order            *[]string
}

func (store *runtimeCoverageStore) Close(ctx context.Context) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closeCalls++
	store.closeCtxErr = ctx.Err()
	_, store.closeHasDeadline = ctx.Deadline()
	if store.order != nil {
		*store.order = append(*store.order, "store")
	}
	return store.closeErr
}

func (store *runtimeCoverageStore) closeState() (int, error, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.closeCalls, store.closeCtxErr, store.closeHasDeadline
}

func TestRuntimeContractProductionDependenciesWireOnlyLocalFactories(t *testing.T) {
	dependencies := productionAppOpenDependencies()
	if dependencies.openStore == nil || dependencies.openAudit == nil ||
		dependencies.loadPolicy == nil || dependencies.closeAudit == nil ||
		dependencies.teamReads == nil {
		t.Fatal("production dependencies are incomplete")
	}

	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open temporary audit log: %v", err)
	}
	if err := dependencies.closeAudit(context.Background(), log); err != nil {
		t.Fatalf("production audit closer: %v", err)
	}

	runtime := dependencies.teamReads()
	if runtime == nil || runtime.openStore == nil ||
		runtime.resolveMountPath == nil || runtime.newAuditManager == nil {
		t.Fatal("production team-read runtime is incomplete")
	}
}

func TestRuntimeContractBoundRuntimeUsesInjectedBoundStore(t *testing.T) {
	backing := fake.New()
	wantMounts := []string{"alpha", "zulu"}
	var gotMounts []string
	resolverCalls := 0
	runtime := productionTeamReadRuntimeWithBoundStore(boundStoreDependencies{
		openSession: func(
			_ context.Context,
			mounts []string,
		) (*accessStoreSession, error) {
			gotMounts = append([]string(nil), mounts...)
			return &accessStoreSession{
				store: backing,
				resolveMountPath: func(context.Context, string) (string, error) {
					return "/bound/store", nil
				},
			}, nil
		},
		resolveMountPath: func(context.Context, string) (string, error) {
			resolverCalls++
			return "/live/store", nil
		},
	})

	session, err := runtime.openStore(context.Background(), wantMounts)
	if err != nil {
		t.Fatalf("open bound runtime store: %v", err)
	}
	if session == nil || session.store != backing {
		t.Fatalf("session = %#v, want injected bound store", session)
	}
	if !reflect.DeepEqual(gotMounts, wantMounts) {
		t.Fatalf("bound store mounts = %v, want %v", gotMounts, wantMounts)
	}
	if path, err := runtime.resolveMountPath(context.Background(), "alpha"); err != nil || path != "/live/store" || resolverCalls != 1 {
		t.Fatalf("runtime resolver = %q/%v calls=%d", path, err, resolverCalls)
	}

	_, err = runtime.newAuditManager(
		"",
		syncpkg.TeamAuditConfig{},
		"/bound/store",
	)
	if err == nil {
		t.Fatal("invalid team audit configuration was accepted")
	}
}

func TestRuntimeContractOpenFailsClosedForNilPolicy(t *testing.T) {
	storeCloseErr := errors.New("store close failed")
	auditCloseErr := errors.New("audit close failed")
	probe := &runtimeCoverageStore{
		Store:    fake.New(),
		closeErr: storeCloseErr,
	}
	auditLog := &audit.Log{}
	auditCloseCalls := 0

	application, err := openApp(context.Background(), "test", appOpenDependencies{
		openStore: func(context.Context) (store.Interface, error) {
			return probe, nil
		},
		openAudit:  func() (*audit.Log, error) { return auditLog, nil },
		loadPolicy: func() (*policy.Policy, error) { return nil, nil },
		closeAudit: func(context.Context, *audit.Log) error {
			auditCloseCalls++
			return auditCloseErr
		},
	})

	if application != nil {
		t.Fatalf("application returned despite unavailable policy: %#v", application)
	}
	for _, want := range []error{ErrPolicyUnavailable, storeCloseErr, auditCloseErr} {
		if !errors.Is(err, want) {
			t.Fatalf("open error = %v, want joined %v", err, want)
		}
	}
	if calls, ctxErr, deadline := probe.closeState(); calls != 1 || ctxErr != nil || !deadline {
		t.Fatalf("store cleanup = calls:%d context:%v deadline:%t", calls, ctxErr, deadline)
	}
	if auditCloseCalls != 1 {
		t.Fatalf("audit cleanup calls = %d, want 1", auditCloseCalls)
	}
}

func TestRuntimeContractOpenBoundAccessStoreRejectsBrokenOpeners(t *testing.T) {
	t.Run("missing opener", func(t *testing.T) {
		session, err := openBoundAccessStore(context.Background(), nil, boundStoreDependencies{})
		if session != nil || err == nil ||
			!strings.Contains(err.Error(), "opener is required") {
			t.Fatalf("session/error = %#v/%v", session, err)
		}
	})

	t.Run("partial session returned with error", func(t *testing.T) {
		openErr := errors.New("bound store open failed")
		closeErr := errors.New("partial store close failed")
		probe := &runtimeCoverageStore{Store: fake.New(), closeErr: closeErr}
		session, err := openBoundAccessStore(
			context.Background(),
			[]string{"jasp"},
			boundStoreDependencies{openSession: func(
				context.Context,
				[]string,
			) (*accessStoreSession, error) {
				return &accessStoreSession{store: probe}, openErr
			}},
		)
		if session != nil || !errors.Is(err, openErr) || !errors.Is(err, closeErr) {
			t.Fatalf("session/error = %#v/%v, want joined open and close errors", session, err)
		}
		if calls, ctxErr, deadline := probe.closeState(); calls != 1 || ctxErr != nil || !deadline {
			t.Fatalf("partial cleanup = calls:%d context:%v deadline:%t", calls, ctxErr, deadline)
		}
	})

	t.Run("nil session", func(t *testing.T) {
		session, err := openBoundAccessStore(
			context.Background(),
			nil,
			boundStoreDependencies{openSession: func(
				context.Context,
				[]string,
			) (*accessStoreSession, error) {
				return nil, nil
			}},
		)
		if session != nil || err == nil ||
			!strings.Contains(err.Error(), "returned nil") {
			t.Fatalf("session/error = %#v/%v", session, err)
		}
	})
}

func TestRuntimeContractBeginAccessOperationRejectsMalformedLease(t *testing.T) {
	releaseErr := errors.New("anchor release failed")
	newRuntime := func(acquire acquireAnchorContextFunc) *teamReadRuntime {
		return &teamReadRuntime{
			loadGlobalPolicy: func() (*policy.Policy, error) {
				return policy.Default(), nil
			},
			loadSyncConfig: func() (*syncpkg.Config, error) {
				return &syncpkg.Config{Version: 1}, nil
			},
			loadSharedPolicy: func(string) (*policy.Policy, string, error) {
				return policy.Default(), "", nil
			},
			acquireAnchor: acquire,
			resolveMountPath: func(context.Context, string) (string, error) {
				return "/bound/store", nil
			},
			newAuditManager: func(string, syncpkg.TeamAuditConfig, string) (teamAuditManager, error) {
				return nil, errors.New("unused")
			},
		}
	}

	t.Run("human retains malformed lease details", func(t *testing.T) {
		releaseCalls := 0
		app := &App{teamReads: newRuntime(func(context.Context) (context.Context, func() error, error) {
			return nil, func() error {
				releaseCalls++
				return releaseErr
			}, nil
		})}
		operation, err := app.beginAccessOperation(
			context.Background(), caller.Detail{Kind: caller.KindHuman}, true, false,
		)
		if operation != nil || err == nil ||
			!strings.Contains(err.Error(), "incomplete lease") || !errors.Is(err, releaseErr) {
			t.Fatalf("operation/error = %#v/%v", operation, err)
		}
		if releaseCalls != 1 {
			t.Fatalf("lease release calls = %d, want 1", releaseCalls)
		}
	})

	t.Run("AI hides anchor failure details", func(t *testing.T) {
		anchorErr := errors.New("private lock location")
		app := &App{teamReads: newRuntime(func(context.Context) (context.Context, func() error, error) {
			return context.Background(), func() error { return releaseErr }, anchorErr
		})}
		operation, err := app.beginAccessOperation(
			context.Background(), caller.Detail{Kind: caller.KindAI}, true, false,
		)
		if operation != nil || !errors.Is(err, ErrTeamAuditUnavailable) {
			t.Fatalf("operation/error = %#v/%v", operation, err)
		}
		if strings.Contains(err.Error(), anchorErr.Error()) || strings.Contains(err.Error(), releaseErr.Error()) {
			t.Fatalf("AI-visible error leaked anchor details: %v", err)
		}
	})
}

func TestRuntimeContractValidateAuditEventsRejectsEveryIntegrityClass(t *testing.T) {
	snapshot := teamaudit.Snapshot{
		StoreCommit:      "commit",
		PolicyHash:       "policy",
		TeamKeysHash:     "keys",
		RecipientSetHash: "recipients",
	}
	input := teamaudit.Input{
		EventID: "event-1", Path: "jasp/one", Action: "get",
		ActorKind: "ai", AgentLabel: "claude-code",
	}
	validEvent := func(eventID string) teamaudit.Event {
		return teamaudit.Event{
			EventID: eventID, Mount: "jasp", Path: input.Path, Action: input.Action,
			Actor:  teamaudit.Actor{Kind: input.ActorKind, AgentLabel: input.AgentLabel},
			Result: "success", StoreCommit: snapshot.StoreCommit,
			PolicyHash: snapshot.PolicyHash, TeamKeysHash: snapshot.TeamKeysHash,
			RecipientSetHash: snapshot.RecipientSetHash,
		}
	}
	cases := []struct {
		name   string
		inputs []teamaudit.Input
		events []teamaudit.Event
		want   string
	}{
		{"incomplete batch", []teamaudit.Input{input}, nil, "incomplete batch"},
		{"missing input ID", []teamaudit.Input{{}}, []teamaudit.Event{{}}, "omitted its event ID"},
		{
			"duplicate input ID",
			[]teamaudit.Input{input, input},
			[]teamaudit.Event{validEvent(input.EventID), validEvent(input.EventID)},
			"reused an event ID",
		},
		{"unexpected event", []teamaudit.Input{input}, []teamaudit.Event{validEvent("other")}, "unexpected event"},
		func() struct {
			name   string
			inputs []teamaudit.Input
			events []teamaudit.Event
			want   string
		} {
			event := validEvent(input.EventID)
			event.Actor.AgentLabel = "other-agent"
			return struct {
				name   string
				inputs []teamaudit.Input
				events []teamaudit.Event
				want   string
			}{"event field mismatch", []teamaudit.Input{input}, []teamaudit.Event{event}, "snapshot changed"}
		}(),
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateAuditEvents("jasp", testCase.inputs, testCase.events, snapshot)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("validate error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestRuntimeContractCloseOrdersResourcesAndSharesJoinedError(t *testing.T) {
	storeCloseErr := errors.New("store close failed")
	auditCloseErr := errors.New("audit close failed")
	var order []string
	probe := &runtimeCoverageStore{
		Store:    fake.New(),
		closeErr: storeCloseErr,
		order:    &order,
	}
	var orderMu sync.Mutex
	app := &App{
		Store: probe,
		auditClose: func(context.Context) error {
			orderMu.Lock()
			defer orderMu.Unlock()
			order = append(order, "audit")
			return auditCloseErr
		},
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	const callers = 12
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			errorsSeen <- app.Close(cancelled)
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, storeCloseErr) || !errors.Is(err, auditCloseErr) {
			t.Fatalf("close error = %v, want both close errors", err)
		}
	}
	if calls, ctxErr, deadline := probe.closeState(); calls != 1 || ctxErr != nil || !deadline {
		t.Fatalf("store close = calls:%d context:%v deadline:%t", calls, ctxErr, deadline)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if !reflect.DeepEqual(order, []string{"store", "audit"}) {
		t.Fatalf("close order = %v, want store then audit", order)
	}
}

func TestRuntimeContractBulkAuditWrappersPreserveAuditContract(t *testing.T) {
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open temporary audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	application := &App{Audit: log, Override: "claude-code"}
	cases := []struct {
		action string
		result string
		reason string
		write  func()
	}{
		{
			action: audit.ActionExport, result: audit.ResultDenied, reason: "destination refused",
			write: func() {
				application.AuditExport(context.Background(), "jasp", audit.ResultDenied, "destination refused")
			},
		},
		{
			action: audit.ActionBWPush, result: audit.ResultOK, reason: "uploaded=2",
			write: func() { application.AuditBWPush(context.Background(), "jasp", audit.ResultOK, "uploaded=2") },
		},
		{
			action: audit.ActionBWImport, result: audit.ResultError, reason: "diff rejected",
			write: func() { application.AuditBWImport(context.Background(), "jasp", audit.ResultError, "diff rejected") },
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.action, func(t *testing.T) {
			testCase.write()
			rows, tailErr := log.Tail(context.Background(), audit.Filter{Action: testCase.action, Limit: 2})
			if tailErr != nil {
				t.Fatalf("tail %s audit: %v", testCase.action, tailErr)
			}
			if len(rows) != 1 || rows[0].SecretPath != "org=jasp" ||
				rows[0].Org != "jasp" || rows[0].Result != testCase.result ||
				rows[0].Reason != testCase.reason {
				t.Fatalf("audit row = %+v", rows)
			}
		})
	}
}
