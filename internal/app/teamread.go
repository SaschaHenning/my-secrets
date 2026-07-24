package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/lockanchor"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamaudit"
	"github.com/google/uuid"
)

var (
	// ErrPolicyUnavailable deliberately omits filesystem details so callers
	// cannot learn local policy locations from an authorization failure.
	ErrPolicyUnavailable = errors.New("access policy unavailable")
	// ErrTeamAuditUnavailable is the generic AI-facing failure for every
	// config, mount-resolution, preflight, append, and snapshot error.
	ErrTeamAuditUnavailable = errors.New("shared read audit unavailable")
)

const teamAuditWarning = "warning: shared read audit unavailable; access continued because the audit is advisory\n"

type teamAuditManager interface {
	Preflight(context.Context) (teamaudit.Snapshot, error)
	AppendBatch(
		context.Context,
		teamaudit.Snapshot,
		[]teamaudit.Input,
	) ([]teamaudit.Event, error)
}

type teamReadRuntime struct {
	loadGlobalPolicy func() (*policy.Policy, error)
	loadSyncConfig   func() (*syncpkg.Config, error)
	loadSharedPolicy func(string) (*policy.Policy, string, error)
	acquireAnchor    acquireAnchorContextFunc
	openStore        func(context.Context, []string) (*accessStoreSession, error)
	resolveMountPath func(context.Context, string) (string, error)
	newAuditManager  func(
		string,
		syncpkg.TeamAuditConfig,
		string,
	) (teamAuditManager, error)
	identifyCaller  func(string) caller.Detail
	finalizeTimeout time.Duration
}

type acquireAnchorContextFunc func(
	context.Context,
) (context.Context, func() error, error)

type accessStoreSession struct {
	store            store.Interface
	resolveMountPath func(context.Context, string) (string, error)
}

type boundStoreDependencies struct {
	openSession      func(context.Context, []string) (*accessStoreSession, error)
	resolveMountPath store.MountPathResolver
}

func openBoundAccessStore(
	ctx context.Context,
	mounts []string,
	dependencies boundStoreDependencies,
) (*accessStoreSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if dependencies.openSession == nil {
		return nil, errors.New("bound store session opener is required")
	}
	opened, openErr := dependencies.openSession(ctx, mounts)
	if openErr != nil || opened == nil {
		if opened != nil && opened.store != nil {
			closeCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			openErr = errors.Join(openErr, opened.store.Close(closeCtx))
			cancel()
		}
		if openErr == nil {
			openErr = errors.New("bound store session opener returned nil")
		}
		return nil, openErr
	}
	if opened.store == nil || opened.resolveMountPath == nil {
		sessionErr := errors.New("bound store session opener returned incomplete session")
		if opened.store == nil {
			return nil, sessionErr
		}
		closeCtx, cancel := detachedCleanupContext(
			ctx,
			storeCleanupTimeout,
		)
		closeErr := opened.store.Close(closeCtx)
		cancel()
		return nil, errors.Join(sessionErr, closeErr)
	}
	return opened, nil
}

func productionTeamReadRuntime() *teamReadRuntime {
	resolveMountPath := func(
		ctx context.Context,
		mount string,
	) (string, error) {
		return syncpkg.GopassMountPath(ctx, nil, mount)
	}
	return productionTeamReadRuntimeWithBoundStore(boundStoreDependencies{
		openSession: func(
			ctx context.Context,
			mounts []string,
		) (*accessStoreSession, error) {
			session, err := store.OpenBound(ctx, mounts, resolveMountPath)
			if err != nil {
				return nil, err
			}
			return &accessStoreSession{
				store:            session.SecretStore(),
				resolveMountPath: session.ResolveMountPath,
			}, nil
		},
		resolveMountPath: resolveMountPath,
	})
}

func productionTeamReadRuntimeWithBoundStore(
	storeDependencies boundStoreDependencies,
) *teamReadRuntime {
	runtime := &teamReadRuntime{
		loadGlobalPolicy: func() (*policy.Policy, error) {
			return policy.Load("")
		},
		loadSyncConfig: func() (*syncpkg.Config, error) {
			return syncpkg.Load("")
		},
		loadSharedPolicy: func(mount string) (*policy.Policy, string, error) {
			shared, _, hash, err := policy.LoadShared(mount)
			return shared, hash, err
		},
		acquireAnchor:    lockanchor.AcquireContext,
		resolveMountPath: storeDependencies.resolveMountPath,
		newAuditManager: func(
			mount string,
			auditConfig syncpkg.TeamAuditConfig,
			storePath string,
		) (teamAuditManager, error) {
			config, err := teamaudit.DefaultConfig(
				mount,
				auditConfig.URL,
				auditConfig.SigningFingerprint,
				storePath,
			)
			if err != nil {
				return nil, err
			}
			return teamaudit.NewManager(config, nil)
		},
		identifyCaller: caller.Identify,
	}
	runtime.openStore = func(
		ctx context.Context,
		mounts []string,
	) (*accessStoreSession, error) {
		return openBoundAccessStore(
			ctx,
			mounts,
			storeDependencies,
		)
	}
	return runtime
}

type sharedPolicyState struct {
	policy *policy.Policy
	hash   string
	err    error
}

type accessOperation struct {
	app              *App
	runtime          *teamReadRuntime
	actor            caller.Detail
	global           *policy.Policy
	config           *syncpkg.Config
	shared           map[string]sharedPolicyState
	store            store.Interface
	resolveMountPath func(context.Context, string) (string, error)

	anchorRelease func() error
	ownsStore     bool
	closeOnce     sync.Once
	closeErr      error
}

func (a *App) callerDetail() caller.Detail {
	if a.teamReads != nil && a.teamReads.identifyCaller != nil {
		return a.teamReads.identifyCaller(a.Override)
	}
	return caller.Identify(a.Override)
}

func (a *App) beginAccessOperation(
	ctx context.Context,
	actor caller.Detail,
	readOnly bool,
	needsStore bool,
) (*accessOperation, error) {
	operation := &accessOperation{
		app:     a,
		runtime: a.teamReads,
		actor:   actor,
		shared:  make(map[string]sharedPolicyState),
	}
	if a.teamReads == nil {
		if a.Policy == nil {
			return nil, ErrPolicyUnavailable
		}
		operation.global = a.Policy
		operation.store = a.Store
		return operation, nil
	}
	if a.teamReads.loadGlobalPolicy == nil ||
		a.teamReads.loadSyncConfig == nil ||
		a.teamReads.loadSharedPolicy == nil ||
		a.teamReads.acquireAnchor == nil ||
		a.teamReads.resolveMountPath == nil ||
		a.teamReads.newAuditManager == nil {
		return nil, ErrTeamAuditUnavailable
	}
	if needsStore && a.teamReads.openStore == nil {
		return nil, ErrTeamAuditUnavailable
	}

	operationCtx, release, anchorErr := a.teamReads.acquireAnchor(ctx)
	if anchorErr != nil {
		if release != nil {
			anchorErr = errors.Join(anchorErr, release())
		}
		if actor.Kind == caller.KindAI {
			return nil, ErrTeamAuditUnavailable
		}
		return nil, fmt.Errorf("acquire access lock anchor: %w", anchorErr)
	}
	if operationCtx == nil || release == nil {
		anchorErr = errors.New("access lock anchor returned incomplete lease")
		if release != nil {
			anchorErr = errors.Join(anchorErr, release())
		}
		if actor.Kind == caller.KindAI {
			return nil, ErrTeamAuditUnavailable
		}
		return nil, anchorErr
	}
	operation.anchorRelease = release

	global, err := a.teamReads.loadGlobalPolicy()
	if err != nil || global == nil {
		return nil, errors.Join(ErrPolicyUnavailable, operation.close(ctx))
	}
	operation.global = global

	config, err := a.teamReads.loadSyncConfig()
	if err == nil && config != nil {
		err = config.Validate()
	}
	if err != nil || config == nil {
		if readOnly && actor.Kind != caller.KindAI {
			a.warnTeamAudit()
			operation.config = &syncpkg.Config{Version: 1}
		} else {
			if !readOnly {
				return nil, errors.Join(
					ErrPolicyUnavailable,
					operation.close(ctx),
				)
			}
			return nil, errors.Join(
				ErrTeamAuditUnavailable,
				operation.close(ctx),
			)
		}
	} else {
		operation.config = config
	}

	if !needsStore {
		operation.store = a.Store
		operation.resolveMountPath = a.teamReads.resolveMountPath
		return operation, nil
	}
	opened, openErr := a.teamReads.openStore(
		operationCtx,
		operation.teamAuditedMounts(),
	)
	if openErr != nil || opened == nil {
		if opened != nil && opened.store != nil {
			closeCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			openErr = errors.Join(openErr, opened.store.Close(closeCtx))
			cancel()
		}
		if actor.Kind == caller.KindAI {
			_ = operation.close(ctx)
			return nil, ErrTeamAuditUnavailable
		}
		if openErr == nil {
			openErr = errors.New("store opener returned nil")
		}
		return nil, errors.Join(
			fmt.Errorf("open store session: %w", openErr),
			operation.close(ctx),
		)
	}
	if opened.store == nil || opened.resolveMountPath == nil {
		invalidErr := errors.New("store opener returned an incomplete session")
		if opened.store != nil {
			closeCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			invalidErr = errors.Join(invalidErr, opened.store.Close(closeCtx))
			cancel()
		}
		if actor.Kind == caller.KindAI {
			_ = operation.close(ctx)
			return nil, ErrTeamAuditUnavailable
		}
		return nil, errors.Join(invalidErr, operation.close(ctx))
	}
	operation.store = opened.store
	operation.resolveMountPath = opened.resolveMountPath
	operation.ownsStore = true
	if operation.store == nil {
		return nil, errors.New("secret store unavailable")
	}
	return operation, nil
}

func (operation *accessOperation) teamAuditedMounts() []string {
	if operation == nil || operation.config == nil {
		return nil
	}
	mounts := make([]string, 0, len(operation.config.Remotes))
	for _, remote := range operation.config.Remotes {
		if remote.Shared && remote.TeamAudit != nil {
			mounts = append(mounts, remote.Mount)
		}
	}
	sort.Strings(mounts)
	return mounts
}

func (operation *accessOperation) close(ctx context.Context) error {
	if operation == nil {
		return nil
	}
	operation.closeOnce.Do(func() {
		var closeErr error
		if operation.ownsStore && operation.store != nil {
			closeCtx, cancel := detachedCleanupContext(ctx, storeCleanupTimeout)
			closeErr = operation.store.Close(closeCtx)
			cancel()
		}
		var releaseErr error
		if operation.anchorRelease != nil {
			releaseErr = operation.anchorRelease()
		}
		operation.closeErr = errors.Join(closeErr, releaseErr)
	})
	return operation.closeErr
}

func (operation *accessOperation) authorize(path string) (policy.Decision, error) {
	globalDecision := operation.global.Evaluate(
		string(operation.actor.Kind),
		operation.actor.AgentLabel,
		path,
	)
	if !globalDecision.Allowed || operation.runtime == nil {
		return globalDecision, nil
	}

	mount := store.OrgOf(path)
	remote, shared := operation.sharedRemote(mount)
	if !shared {
		return globalDecision, nil
	}
	_ = remote
	state, loaded := operation.shared[mount]
	if !loaded {
		sharedPolicy, hash, err := operation.runtime.loadSharedPolicy(mount)
		if err == nil && sharedPolicy == nil {
			err = ErrPolicyUnavailable
		}
		state = sharedPolicyState{policy: sharedPolicy, hash: hash, err: err}
		operation.shared[mount] = state
	}
	if state.err != nil {
		return policy.Decision{}, ErrPolicyUnavailable
	}
	return policy.EvaluateCombined(
		operation.global,
		state.policy,
		string(operation.actor.Kind),
		operation.actor.AgentLabel,
		path,
	), nil
}

func (operation *accessOperation) sharedRemote(
	mount string,
) (syncpkg.StoreRemote, bool) {
	if operation.runtime == nil || operation.config == nil || mount == "" {
		return syncpkg.StoreRemote{}, false
	}
	remote, ok := operation.config.Remote(mount)
	return remote, ok && remote.Shared
}

type preparedAudit struct {
	manager  teamAuditManager
	snapshot teamaudit.Snapshot
}

type readPreparation struct {
	operation    *accessOperation
	byMount      map[string]preparedAudit
	failedMounts map[string]struct{}
}

func (operation *accessOperation) prepareReads(
	ctx context.Context,
	paths []string,
) (*readPreparation, error) {
	preparation := &readPreparation{
		operation:    operation,
		byMount:      make(map[string]preparedAudit),
		failedMounts: make(map[string]struct{}),
	}
	if operation.runtime == nil {
		return preparation, nil
	}

	mounts := make(map[string]struct{})
	for _, path := range paths {
		mount := store.OrgOf(path)
		if _, shared := operation.sharedRemote(mount); shared {
			mounts[mount] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(mounts))
	for mount := range mounts {
		ordered = append(ordered, mount)
	}
	sort.Strings(ordered)
	failMount := func(mount string) error {
		preparation.failedMounts[mount] = struct{}{}
		return operation.auditFailure()
	}

	for _, mount := range ordered {
		remote, _ := operation.sharedRemote(mount)
		if remote.TeamAudit == nil {
			if err := failMount(mount); err != nil {
				return nil, err
			}
			continue
		}
		storePath, err := operation.resolveMountPath(ctx, mount)
		if err != nil {
			if err := failMount(mount); err != nil {
				return nil, err
			}
			continue
		}
		manager, err := operation.runtime.newAuditManager(
			mount,
			*remote.TeamAudit,
			storePath,
		)
		if err != nil {
			if err := failMount(mount); err != nil {
				return nil, err
			}
			continue
		}
		snapshot, err := manager.Preflight(ctx)
		if err != nil {
			if err := failMount(mount); err != nil {
				return nil, err
			}
			continue
		}
		policyState := operation.shared[mount]
		if policyState.hash == "" ||
			snapshot.PolicyHash != policyState.hash {
			if err := failMount(mount); err != nil {
				return nil, err
			}
			continue
		}
		preparation.byMount[mount] = preparedAudit{
			manager:  manager,
			snapshot: snapshot,
		}
	}
	return preparation, nil
}

type observedRead struct {
	path   string
	action string
}

func (operation *accessOperation) authorizedPaths(
	paths []string,
) ([]string, map[string]policy.Decision, error) {
	allowed := make([]string, 0, len(paths))
	decisions := make(map[string]policy.Decision, len(paths))
	for _, path := range paths {
		if cleanSecretPath(path) != nil {
			continue
		}
		decision, err := operation.authorize(path)
		if err != nil {
			return nil, nil, err
		}
		decisions[path] = decision
		if decision.Allowed {
			allowed = append(allowed, path)
		}
	}
	return allowed, decisions, nil
}

func (operation *accessOperation) decryptBatch(
	ctx context.Context,
	paths []string,
	action string,
) (entries []*store.Entry, resultErr error) {
	allowed, _, err := operation.authorizedPaths(paths)
	if err != nil {
		return nil, err
	}
	preparation, err := operation.prepareReads(ctx, allowed)
	if err != nil {
		return nil, err
	}
	entries = make([]*store.Entry, 0, len(allowed))
	observed := make([]observedRead, 0, len(allowed))
	defer func() {
		finalizeErr := preparation.finalize(ctx, observed)
		resultErr = errors.Join(resultErr, finalizeErr)
		if resultErr != nil {
			entries = nil
		}
	}()
	for _, path := range allowed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := operation.store.Get(ctx, path)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		entries = append(entries, entry)
		observed = append(observed, observedRead{path: path, action: action})
	}
	return entries, nil
}

func (preparation *readPreparation) finalize(
	ctx context.Context,
	observed []observedRead,
) error {
	if preparation == nil || len(observed) == 0 {
		return nil
	}
	timeout := teamAuditFinalizeTimeout
	if preparation.operation != nil &&
		preparation.operation.runtime != nil &&
		preparation.operation.runtime.finalizeTimeout > 0 {
		timeout = preparation.operation.runtime.finalizeTimeout
	}
	return preparation.complete(ctx, observed, timeout)
}

func (preparation *readPreparation) complete(
	ctx context.Context,
	observed []observedRead,
	timeout time.Duration,
) error {
	if preparation == nil ||
		preparation.operation == nil ||
		preparation.operation.runtime == nil {
		return nil
	}
	grouped := make(map[string][]observedRead)
	for _, read := range observed {
		mount := store.OrgOf(read.path)
		if _, shared := preparation.operation.sharedRemote(mount); !shared {
			continue
		}
		grouped[mount] = append(grouped[mount], read)
	}

	mounts := make([]string, 0, len(grouped))
	for mount := range grouped {
		mounts = append(mounts, mount)
	}
	sort.Strings(mounts)
	var failures []error
	for _, mount := range mounts {
		prepared, ok := preparation.byMount[mount]
		if !ok {
			if _, alreadyReported := preparation.failedMounts[mount]; !alreadyReported {
				if err := preparation.operation.auditFailure(); err != nil {
					failures = append(failures, err)
				}
			}
			continue
		}
		reads := grouped[mount]
		inputs := make([]teamaudit.Input, 0, len(reads))
		for _, read := range reads {
			inputs = append(inputs, teamaudit.Input{
				EventID:    uuid.NewString(),
				Path:       read.path,
				Action:     read.action,
				ActorKind:  string(preparation.operation.actor.Kind),
				AgentLabel: preparation.operation.actor.AgentLabel,
			})
		}
		appendCtx, cancel := detachedCleanupContext(ctx, timeout)
		events, err := prepared.manager.AppendBatch(
			appendCtx,
			prepared.snapshot,
			inputs,
		)
		cancel()
		if err == nil {
			err = validateAuditEvents(
				mount,
				inputs,
				events,
				prepared.snapshot,
			)
		}
		if err != nil {
			if err := preparation.operation.auditFailure(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func validateAuditEvents(
	mount string,
	inputs []teamaudit.Input,
	events []teamaudit.Event,
	snapshot teamaudit.Snapshot,
) error {
	if len(events) != len(inputs) {
		return errors.New("team audit returned an incomplete batch")
	}
	expected := make(map[string]teamaudit.Input, len(inputs))
	for _, input := range inputs {
		if input.EventID == "" {
			return errors.New("team audit input omitted its event ID")
		}
		if _, duplicate := expected[input.EventID]; duplicate {
			return errors.New("team audit input reused an event ID")
		}
		expected[input.EventID] = input
	}
	for _, event := range events {
		input, found := expected[event.EventID]
		if !found {
			return errors.New("team audit returned an unexpected event")
		}
		if event.Mount != mount ||
			event.Result != "success" ||
			event.StoreCommit != snapshot.StoreCommit ||
			event.PolicyHash != snapshot.PolicyHash ||
			event.TeamKeysHash != snapshot.TeamKeysHash ||
			event.RecipientSetHash != snapshot.RecipientSetHash ||
			event.Path != input.Path ||
			event.Action != input.Action ||
			event.Actor.Kind != input.ActorKind ||
			event.Actor.AgentLabel != input.AgentLabel {
			return errors.New("team audit snapshot changed during read")
		}
		delete(expected, event.EventID)
	}
	if len(expected) != 0 {
		return errors.New("team audit omitted an event")
	}
	return nil
}

func (operation *accessOperation) auditFailure() error {
	if operation.actor.Kind == caller.KindAI {
		return ErrTeamAuditUnavailable
	}
	operation.app.warnTeamAudit()
	return nil
}

func (a *App) warnTeamAudit() {
	a.warningMu.Lock()
	defer a.warningMu.Unlock()
	_, _ = fmt.Fprint(a.stderr(), teamAuditWarning)
}
