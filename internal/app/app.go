// Package app orchestrates the store, audit, caller, and policy components
// into a single Facade. Every operation on the CLI, Web UI, or MCP server
// MUST go through the App — that is how we guarantee that every access is
// audited and policy-checked.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/history"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	totppkg "github.com/SaschaHenning/my-secrets/internal/totp"
)

// NoSyncFlag is set by the CLI when `--no-sync` is passed. It is a
// package-level variable so that the cobra layer can flip it without
// having to thread an option through every App.Open call site. The App
// reads it once per AutoSync invocation.
var NoSyncFlag bool

// autoSyncTimeout is the hard budget for one auto-sync attempt. Chosen
// so a write operation never blocks the user for more than a few
// seconds even on a flaky network. Exposed as a package variable so
// tests can tighten or extend it.
var autoSyncTimeout = 5 * time.Second

// autoSyncRunner is the sync.Runner used by (*App).AutoSync. Tests
// override it to inject a fake runner; production code leaves it nil
// which falls back to the exec runner.
var autoSyncRunner syncpkg.Runner

const (
	storeCleanupTimeout      = 5 * time.Second
	teamAuditFinalizeTimeout = 5 * time.Second
)

// App wires everything together.
type App struct {
	Store    store.Interface
	Audit    *audit.Log
	Policy   *policy.Policy
	Override string // explicit --requester value for this invocation
	// SuppressAutoSync disables the normal best-effort personal-store
	// auto-sync for this App instance. Administrative batch flows use it
	// when they hold their own mount lock and perform one explicit sync
	// after all writes.
	SuppressAutoSync bool
	// Stderr is where user-visible warnings (auto-sync failure, etc.)
	// are written. Nil falls back to os.Stderr. Tests inject a
	// *bytes.Buffer here to assert on the output.
	Stderr io.Writer
	// teamReads is enabled by Open. Nil preserves the historical static-policy
	// behavior for explicitly constructed test Apps.
	teamReads *teamReadRuntime
	// warningMu keeps writes to a shared bytes.Buffer or response stream
	// coherent when long-lived Web/MCP Apps serve concurrent requests.
	warningMu  sync.Mutex
	closeOnce  sync.Once
	closeErr   error
	auditClose func(context.Context) error
}

type appOpenDependencies struct {
	openStore  func(context.Context) (store.Interface, error)
	openAudit  func() (*audit.Log, error)
	loadPolicy func() (*policy.Policy, error)
	closeAudit func(context.Context, *audit.Log) error
	teamReads  func() *teamReadRuntime
}

func productionAppOpenDependencies() appOpenDependencies {
	return appOpenDependencies{
		openStore: func(ctx context.Context) (store.Interface, error) {
			return store.Open(ctx)
		},
		openAudit: func() (*audit.Log, error) {
			return audit.Open("")
		},
		loadPolicy: func() (*policy.Policy, error) {
			return policy.Load("")
		},
		closeAudit: func(_ context.Context, log *audit.Log) error {
			return log.Close()
		},
		teamReads: productionTeamReadRuntime,
	}
}

// Open opens the store + audit DB + policy in one call. Callers are
// responsible for calling Close when done.
func Open(ctx context.Context, override string) (*App, error) {
	return openApp(ctx, override, productionAppOpenDependencies())
}

func openApp(
	ctx context.Context,
	override string,
	dependencies appOpenDependencies,
) (*App, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	closeAudit := dependencies.closeAudit
	if closeAudit == nil {
		closeAudit = func(_ context.Context, log *audit.Log) error {
			return log.Close()
		}
	}
	if dependencies.openStore == nil {
		return nil, errors.New("store opener is required")
	}
	st, err := dependencies.openStore(ctx)
	if err != nil {
		return nil, errors.Join(
			err,
			closeOpenResources(ctx, st, nil, closeAudit),
		)
	}
	if st == nil {
		return nil, errors.New("store opener returned nil")
	}
	if dependencies.openAudit == nil {
		return nil, errors.Join(
			errors.New("audit opener is required"),
			closeOpenResources(ctx, st, nil, closeAudit),
		)
	}
	al, err := dependencies.openAudit()
	if err != nil {
		return nil, errors.Join(
			err,
			closeOpenResources(ctx, st, al, closeAudit),
		)
	}
	if al == nil {
		return nil, errors.Join(
			errors.New("audit opener returned nil"),
			closeOpenResources(ctx, st, nil, closeAudit),
		)
	}
	if dependencies.loadPolicy == nil {
		return nil, errors.Join(
			errors.New("policy loader is required"),
			closeOpenResources(ctx, st, al, closeAudit),
		)
	}
	pol, err := dependencies.loadPolicy()
	if err == nil && pol == nil {
		err = ErrPolicyUnavailable
	}
	if err != nil {
		return nil, errors.Join(
			err,
			closeOpenResources(ctx, st, al, closeAudit),
		)
	}
	var teamReads *teamReadRuntime
	if dependencies.teamReads != nil {
		teamReads = dependencies.teamReads()
	}
	return &App{
		Store:     st,
		Audit:     al,
		Policy:    pol,
		Override:  override,
		teamReads: teamReads,
		auditClose: func(closeCtx context.Context) error {
			return closeAudit(closeCtx, al)
		},
	}, nil
}

// OpenAuditOnly is used by commands (`audit tail`, `web`) that do not need
// to decrypt secrets. It skips the gopass store to avoid unlocking GPG.
func OpenAuditOnly() (*App, error) {
	return openAuditOnlyWithDependencies(
		context.Background(),
		productionAppOpenDependencies(),
	)
}

func openAuditOnlyWithDependencies(
	ctx context.Context,
	dependencies appOpenDependencies,
) (*App, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	closeAudit := dependencies.closeAudit
	if closeAudit == nil {
		closeAudit = func(_ context.Context, log *audit.Log) error {
			return log.Close()
		}
	}
	if dependencies.openAudit == nil {
		return nil, errors.New("audit opener is required")
	}
	al, err := dependencies.openAudit()
	if err != nil {
		return nil, errors.Join(
			err,
			closeOpenResources(ctx, nil, al, closeAudit),
		)
	}
	if al == nil {
		return nil, errors.New("audit opener returned nil")
	}
	if dependencies.loadPolicy == nil {
		return nil, errors.Join(
			errors.New("policy loader is required"),
			closeOpenResources(ctx, nil, al, closeAudit),
		)
	}
	pol, err := dependencies.loadPolicy()
	if err == nil && pol == nil {
		err = ErrPolicyUnavailable
	}
	if err != nil {
		return nil, errors.Join(
			err,
			closeOpenResources(ctx, nil, al, closeAudit),
		)
	}
	return &App{
		Audit:  al,
		Policy: pol,
		auditClose: func(closeCtx context.Context) error {
			return closeAudit(closeCtx, al)
		},
	}, nil
}

func closeOpenResources(
	ctx context.Context,
	st store.Interface,
	log *audit.Log,
	closeAudit func(context.Context, *audit.Log) error,
) error {
	var errs []error
	if st != nil {
		storeCloseCtx, cancel := detachedCleanupContext(
			ctx,
			storeCleanupTimeout,
		)
		errs = append(errs, st.Close(storeCloseCtx))
		cancel()
	}
	if log != nil {
		if closeAudit == nil {
			errs = append(errs, errors.New("audit closer is required"))
		} else {
			auditCloseCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			errs = append(errs, closeAudit(auditCloseCtx, log))
			cancel()
		}
	}
	return errors.Join(errs...)
}

func (a *App) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		var errs []error
		if a.Store != nil {
			closeCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			if err := a.Store.Close(closeCtx); err != nil {
				errs = append(errs, err)
			}
			cancel()
		}
		if a.auditClose != nil {
			closeCtx, cancel := detachedCleanupContext(
				ctx,
				storeCleanupTimeout,
			)
			if err := a.auditClose(closeCtx); err != nil {
				errs = append(errs, err)
			}
			cancel()
		} else if a.Audit != nil {
			if err := a.Audit.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}

func detachedCleanupContext(
	ctx context.Context,
	timeout time.Duration,
) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

// ErrDenied is returned when the scope policy rejects a request.
type ErrDenied struct {
	Path   string
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("denied: %s (%s)", e.Path, e.Reason)
}

// errInvalidPath is returned by cleanSecretPath for any path App refuses
// to evaluate at all.
var errInvalidPath = errors.New("invalid secret path")

// cleanSecretPath rejects any path containing a ".", "..", or empty
// segment, or a leading slash. Policy.Evaluate and the store's own path
// resolution (gopass cleans the path with filepath.Join/filepath.Clean
// before touching disk) MUST agree on the exact same bytes — otherwise a
// caller can craft a path like "jasp/../private/bank" that a prefix-based
// policy rule ("allow jasp/**") judges as allowed while the store
// resolves and returns "private/bank". This is checked before every
// Policy.Evaluate call in this file that is followed by a Store
// operation on the same path, so policy always judges exactly the bytes
// the store will act on.
//
// Rejecting outright (rather than cleaning the path and continuing) is
// deliberate: silently rewriting a caller's input could itself surprise a
// caller expecting their literal path to be evaluated, and every
// legitimate path this tool ever writes (mys add/rotate) is already
// canonical, so a non-canonical path is never a legitimate access.
func cleanSecretPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") {
		return errInvalidPath
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errInvalidPath
		}
	}
	return nil
}

// Get fetches a decrypted entry, respecting policy + writing audit.
func (a *App) Get(
	ctx context.Context,
	path string,
) (entry *store.Entry, resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			entry = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultDenied, decision.Reason)
		return nil, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	preparation, err := operation.prepareReads(ctx, []string{path})
	if err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	e, err := operation.store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	if err := preparation.finalize(ctx, []observedRead{{
		path: path, action: "get",
	}}); err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultOK, decision.MatchedRule)
	return e, nil
}

// GenerateTOTP computes the current TOTP code for a stored entry. Policy
// is enforced the same way as for Get — AI callers hit the same allow/deny
// gate. Every invocation writes a totp_generate audit row including the
// time-window index so repeated calls within the same window are
// identifiable. Non-TOTP entries produce a descriptive error plus an
// error-result audit row.
func (a *App) GenerateTOTP(ctx context.Context, path string, now time.Time) (string, int, error) {
	details, err := a.GenerateTOTPDetails(ctx, path, now)
	return details.Code, details.SecondsLeft, err
}

// TOTPDetails contains the generated code and non-secret display metadata
// obtained from the same single decryption.
type TOTPDetails struct {
	Code        string
	SecondsLeft int
	Issuer      string
	Label       string
}

// GenerateTOTPDetails is the single-read TOTP API used by callers that also
// need issuer and label. It avoids a second direct Store.Get bypass.
func (a *App) GenerateTOTPDetails(
	ctx context.Context,
	path string,
	now time.Time,
) (details TOTPDetails, resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultDenied, err.Error())
		return TOTPDetails{}, &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			details = TOTPDetails{}
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultDenied, decision.Reason)
		return TOTPDetails{}, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	preparation, err := operation.prepareReads(ctx, []string{path})
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	e, err := operation.store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	if err := preparation.finalize(ctx, []observedRead{{
		path: path, action: "totp_generate",
	}}); err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	if e.Kind != store.KindTOTP {
		msg := fmt.Sprintf("path %q is not a totp entry", path)
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, msg)
		return TOTPDetails{}, errors.New(msg)
	}
	alg, algErr := totppkg.ParseAlgorithm(e.TOTPAlgorithm)
	if algErr != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, algErr.Error())
		return TOTPDetails{}, algErr
	}
	digits, digErr := totppkg.ParseDigits(fmt.Sprintf("%d", e.TOTPDigits))
	if digErr != nil {
		// Treat zero as default here instead of an error.
		if e.TOTPDigits == 0 {
			digits, _ = totppkg.ParseDigits("")
		} else {
			a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, digErr.Error())
			return TOTPDetails{}, digErr
		}
	}
	period := uint(e.TOTPPeriod)
	if period == 0 {
		period = 30
	}
	reason := fmt.Sprintf("window=%d", totppkg.WindowIndex(now, period))
	code, secondsLeft, err := totppkg.GenerateCode(e.Password, totppkg.Options{
		Algorithm: alg,
		Digits:    digits,
		Period:    period,
	}, now)
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return TOTPDetails{}, err
	}
	a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultOK, reason)
	return TOTPDetails{
		Code:        code,
		SecondsLeft: secondsLeft,
		Issuer:      e.TOTPIssuer,
		Label:       e.TOTPLabel,
	}, nil
}

// List returns paths filtered by the caller's policy. Paths that would be
// denied are silently filtered out of the result; a single audit entry is
// written for the list action itself.
func (a *App) List(
	ctx context.Context,
	org string,
) (pathsResult []string, resultErr error) {
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionList, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			pathsResult = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	paths, err := operation.store.List(ctx, org)
	if err != nil {
		a.writeAudit(ctx, audit.ActionList, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if cleanSecretPath(p) != nil {
			continue
		}
		decision, decisionErr := operation.authorize(p)
		if decisionErr != nil {
			a.writeAudit(
				ctx, audit.ActionList, orgPath(org), d,
				audit.ResultError, decisionErr.Error(),
			)
			return nil, decisionErr
		}
		if decision.Allowed {
			filtered = append(filtered, p)
		}
	}
	a.writeAudit(ctx, audit.ActionList, orgPath(org), d, audit.ResultOK,
		fmt.Sprintf("%d of %d entries visible", len(filtered), len(paths)))
	return filtered, nil
}

// Orgs returns the distinct top-level orgs visible to the caller, derived
// from the already policy-filtered List() output. Deliberately does not
// call a.Store.Orgs() directly — that would bypass policy filtering and
// could leak org names for orgs the caller has zero access to. Piggybacks
// on List()'s existing audit row rather than writing a second one for what
// is, from the caller's point of view, a single logical browse.
func (a *App) Orgs(ctx context.Context) ([]string, error) {
	paths, err := a.List(ctx, "")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	orgs := make([]string, 0)
	for _, p := range paths {
		o := store.OrgOf(p)
		if o == "" {
			continue
		}
		if _, ok := seen[o]; !ok {
			seen[o] = struct{}{}
			orgs = append(orgs, o)
		}
	}
	sort.Strings(orgs)
	return orgs, nil
}

// BrowseDetailed decrypts every entry visible to the caller within org
// (all orgs if org is "") and returns the full metadata — everything on
// store.Entry except the caller is expected to render Password/TOTP seed
// material. Unlike Get, this writes exactly ONE aggregated audit row per
// call under ActionListDetail, not one ActionGet row per path: browsing a
// list of entries in the web UI must not look, in the audit log, like the
// caller read every single one of them. That distinction is what keeps
// "last read" (audit.LastAccessByPath, filtered to ActionGet) meaningful.
// This mirrors the existing SearchByDomain, which has the same
// one-row-per-call shape for the same reason.
func (a *App) BrowseDetailed(
	ctx context.Context,
	org string,
) (resultEntries []*store.Entry, resultErr error) {
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			resultEntries = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	paths, err := operation.store.List(ctx, org)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	entries, err := operation.decryptBatch(ctx, paths, "list_detail")
	if err != nil {
		auditContext := ctx
		if ctx.Err() != nil {
			auditContext = context.Background()
		}
		a.writeAudit(
			auditContext, audit.ActionListDetail, orgPath(org), d,
			audit.ResultError, err.Error(),
		)
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionListDetail, orgPath(org), d, audit.ResultOK,
		fmt.Sprintf("%d entries", len(entries)))
	return entries, nil
}

// BrowseDetailedPaths decrypts exactly the given paths and returns the
// same full metadata BrowseDetailed does, for callers that already know
// which entries changed (the web UI's store watcher) and must not pay a
// whole-store re-decrypt to pick them up.
//
// Audit shape is deliberately identical to BrowseDetailed: ONE aggregated
// ActionListDetail row per call, never one ActionGet row per path — a
// background refresh must not make "last read" (audit.LastAccessByPath,
// filtered to ActionGet) claim the user read those entries. Paths that
// policy hides, or that are malformed, are dropped silently by
// decryptBatch, so a missing path means "not visible", not "unchanged".
func (a *App) BrowseDetailedPaths(
	ctx context.Context,
	paths []string,
) (resultEntries []*store.Entry, resultErr error) {
	if len(paths) == 0 {
		return nil, nil
	}
	target := orgPath(sharedOrg(paths))
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, target, d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			resultEntries = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	entries, err := operation.decryptBatch(ctx, paths, "list_detail")
	if err != nil {
		auditContext := ctx
		if ctx.Err() != nil {
			auditContext = context.Background()
		}
		a.writeAudit(
			auditContext, audit.ActionListDetail, target, d,
			audit.ResultError, err.Error(),
		)
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionListDetail, target, d, audit.ResultOK,
		fmt.Sprintf("%d of %d changed entries", len(entries), len(paths)))
	return entries, nil
}

// sharedOrg returns the org every path belongs to, or "" when they span
// more than one — the audit row then covers the whole store, like
// BrowseDetailed(ctx, "").
func sharedOrg(paths []string) string {
	shared := ""
	for i, p := range paths {
		org := store.OrgOf(p)
		if i == 0 {
			shared = org
			continue
		}
		if org != shared {
			return ""
		}
	}
	return shared
}

// Inspect decrypts a single entry for metadata display — Kind, Tags,
// Domain, etc. Like BrowseDetailed, this writes an ActionListDetail row,
// NOT ActionGet: the web UI's masked entry-detail page uses Inspect, so
// simply viewing an entry's metadata does not count as reading it. Only
// the explicit reveal action (App.Get) does.
func (a *App) Inspect(
	ctx context.Context,
	path string,
) (entry *store.Entry, resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			entry = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultDenied, decision.Reason)
		return nil, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	preparation, err := operation.prepareReads(ctx, []string{path})
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	e, err := operation.store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	if err := preparation.finalize(ctx, []observedRead{{
		path: path, action: "inspect",
	}}); err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultOK, decision.MatchedRule)
	return e, nil
}

// History returns recent git-log revisions for path — commit
// hash/timestamp/message only, never decrypted content. Policy-gated the
// same way as every other path-taking method: a denied path shouldn't
// leak how many times it was ever changed, any more than it should leak
// its metadata (App.Inspect) or its value (App.Get).
func (a *App) History(
	ctx context.Context,
	path string,
	limit int,
) (revisions []history.Revision, resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, true, false)
	if err != nil {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			revisions = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultDenied, decision.Reason)
		return nil, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	revs, err := history.Log(ctx, path, limit)
	if err != nil {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultOK, fmt.Sprintf("%d revisions", len(revs)))
	return revs, nil
}

// storeSearcher is the minimal interface App.Search needs from the store.
// Extracted so tests can exercise the audit + policy wiring without
// requiring a real gopass store.
type storeSearcher interface {
	Search(ctx context.Context, query string, allow func(path string) bool) (allowed []string, denied []string, err error)
}

// Search filters by caller policy. Paths denied by policy are filtered out
// BEFORE the store decrypts them — denied entries never enter process
// memory. In addition to the aggregate audit row, one denied audit row is
// written per rejected path so operators can see exactly which secrets a
// caller attempted to reach.
func (a *App) Search(ctx context.Context, query string) ([]string, error) {
	if a.teamReads != nil {
		return a.searchObserved(ctx, query)
	}
	return a.searchWith(ctx, query, a.Store)
}

func (a *App) searchWith(
	ctx context.Context,
	query string,
	ss storeSearcher,
) (pathsResult []string, resultErr error) {
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStagePrepare),
		)
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			pathsResult = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	// Cache reasons for denied paths so we do not have to call Evaluate
	// twice per path. The closure collects them as a side effect while
	// the store walks the list.
	denyReasons := make(map[string]string)
	allow := func(p string) bool {
		if cleanSecretPath(p) != nil {
			denyReasons[p] = errInvalidPath.Error()
			return false
		}
		dec, err := operation.authorize(p)
		if err != nil {
			denyReasons[p] = err.Error()
			return false
		}
		if !dec.Allowed {
			denyReasons[p] = dec.Reason
			return false
		}
		return true
	}
	allowed, denied, err := ss.Search(ctx, query, allow)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStageExecute),
		)
		return nil, err
	}
	// Per-path denied audit rows.
	for _, p := range denied {
		reason := denyReasons[p]
		if reason == "" {
			decision, decisionErr := operation.authorize(p)
			if decisionErr != nil {
				reason = decisionErr.Error()
			} else {
				reason = decision.Reason
			}
		}
		a.writeAudit(ctx, audit.ActionSearch, p, d, audit.ResultDenied, reason)
	}
	total := len(allowed) + len(denied)
	a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultOK,
		fmt.Sprintf("%s %d of %d visible", searchAuditMetadata(query), len(allowed), total))
	return allowed, nil
}

func (a *App) searchObserved(
	ctx context.Context,
	query string,
) (pathsResult []string, resultErr error) {
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStagePrepare),
		)
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			pathsResult = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	paths, err := operation.store.List(ctx, "")
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStageList),
		)
		return nil, err
	}
	authorized, decisions, err := operation.authorizedPaths(paths)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStageAuthorize),
		)
		return nil, err
	}
	authorizedSet := make(map[string]struct{}, len(authorized))
	for _, path := range authorized {
		authorizedSet[path] = struct{}{}
	}
	preparation, err := operation.prepareReads(ctx, authorized)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStagePreflight),
		)
		return nil, err
	}

	denyReasons := make(map[string]string)
	allow := func(path string) bool {
		if _, ok := authorizedSet[path]; ok {
			return true
		}
		if decision, ok := decisions[path]; ok {
			denyReasons[path] = decision.Reason
		} else {
			denyReasons[path] = "path was not authorized before search"
		}
		return false
	}
	observed := make([]observedRead, 0, len(authorized))
	observe := func(path string) {
		observed = append(observed, observedRead{
			path: path, action: "search",
		})
	}
	allowed, denied, searchErr := operation.store.SearchObserved(
		ctx,
		query,
		allow,
		observe,
	)
	recordErr := preparation.finalize(ctx, observed)
	combinedErr := errors.Join(searchErr, recordErr)
	if combinedErr != nil {
		stage := searchAuditStageExecute
		if recordErr != nil {
			stage = searchAuditStageRecord
		}
		auditCtx := ctx
		if ctx.Err() != nil {
			auditCtx = context.Background()
		}
		a.writeAudit(
			auditCtx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, stage),
		)
		return nil, combinedErr
	}
	for _, path := range allowed {
		if _, ok := authorizedSet[path]; !ok {
			a.writeAudit(
				ctx, audit.ActionSearch, "", d,
				audit.ResultError, searchAuditFailure(query, searchAuditStageAuthorize),
			)
			return nil, ErrPolicyUnavailable
		}
	}
	for _, path := range denied {
		reason := denyReasons[path]
		if reason == "" {
			reason = "path denied before search"
		}
		a.writeAudit(
			ctx, audit.ActionSearch, path, d,
			audit.ResultDenied, reason,
		)
	}
	total := len(allowed) + len(denied)
	a.writeAudit(
		ctx, audit.ActionSearch, "", d, audit.ResultOK,
		fmt.Sprintf("%s %d of %d visible", searchAuditMetadata(query), len(allowed), total),
	)
	return allowed, nil
}

type searchAuditStage string

const (
	searchAuditStagePrepare   searchAuditStage = "prepare"
	searchAuditStageList      searchAuditStage = "list"
	searchAuditStageAuthorize searchAuditStage = "authorize"
	searchAuditStagePreflight searchAuditStage = "preflight"
	searchAuditStageExecute   searchAuditStage = "execute"
	searchAuditStageRecord    searchAuditStage = "record"
	searchAuditStageDecrypt   searchAuditStage = "decrypt"
)

// searchAuditMetadata records only non-sensitive query metadata. Search input
// may be a pasted password, token, or credential-bearing URL, so neither raw
// nor normalized query content is safe for a persistent audit log.
func searchAuditMetadata(query string) string {
	trimmed := strings.TrimSpace(query)
	return fmt.Sprintf(
		"query=redacted query_len=%d query_runes=%d",
		len(trimmed),
		utf8.RuneCountInString(trimmed),
	)
}

func searchAuditFailure(query string, stage searchAuditStage) string {
	return fmt.Sprintf("%s stage=%s failed", searchAuditMetadata(query), stage)
}

// Add writes a new entry after policy check. Add is defined as a rotation
// event for the purposes of the rotation-reminder feature: it always
// stamps RotatedAt to the current UTC time. Callers that explicitly set
// a non-zero RotatedAt before calling Add have that value overwritten —
// the timestamp is a book-keeping field maintained by the app layer, not
// user input.
func (a *App) Add(ctx context.Context, e *store.Entry) (resultErr error) {
	d := a.callerDetail()
	if e == nil {
		err := errors.New("entry is required")
		a.writeAudit(ctx, audit.ActionAdd, "", d, audit.ResultDenied, err.Error())
		return err
	}
	if err := cleanSecretPath(e.Path); err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: e.Path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, false, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultError, err.Error())
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, operation.close(ctx))
	}()
	decision, err := operation.authorize(e.Path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultError, err.Error())
		return err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: e.Path, Reason: decision.Reason}
	}
	e.RotatedAt = time.Now().UTC()
	// Auto-derive Domain from URL if the caller did not set it explicitly.
	// Keeps the happy-path "echo pw | mys add --url https://…" flow working
	// without forcing every caller to pass --domain.
	if e.Domain == "" && e.URL != "" {
		e.Domain = store.DeriveDomain(e.URL)
	}
	if err := operation.store.Set(ctx, e); err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultError, err.Error())
		return err
	}
	if err := operation.close(ctx); err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultError, err.Error())
		return err
	}
	a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultOK, decision.MatchedRule)
	a.AutoSync(ctx, "add "+e.Path)
	return nil
}

// Rotate writes a new password for an existing entry. It preserves all
// metadata (including RotateAfter) and stamps RotatedAt to the current
// UTC time so that --stale filters and doctor checks reset.
func (a *App) Rotate(
	ctx context.Context,
	path string,
	newPassword string,
) (resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, false, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, operation.close(ctx))
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: path, Reason: decision.Reason}
	}
	// Load the existing entry so the rotated_at stamp can be carried in
	// the Set() call alongside the existing metadata. We bypass
	// App.Get's audit row because the rotate audit row already captures
	// this operation; emitting a separate get row would double-count.
	preparation, err := operation.prepareReads(ctx, []string{path})
	if err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	existing, err := operation.store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	if err := preparation.finalize(ctx, []observedRead{{
		path: path, action: "rotate_read",
	}}); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	existing.Password = newPassword
	existing.RotatedAt = time.Now().UTC()
	if err := operation.store.Set(ctx, existing); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	if err := operation.close(ctx); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultOK, decision.MatchedRule)
	a.AutoSync(ctx, "rotate "+path)
	return nil
}

// Remove deletes an entry after policy check.
func (a *App) Remove(ctx context.Context, path string) (resultErr error) {
	d := a.callerDetail()
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: path, Reason: err.Error()}
	}
	operation, err := a.beginAccessOperation(ctx, d, false, true)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultError, err.Error())
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, operation.close(ctx))
	}()
	decision, err := operation.authorize(path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultError, err.Error())
		return err
	}
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: path, Reason: decision.Reason}
	}
	if err := operation.store.Remove(ctx, path); err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultError, err.Error())
		return err
	}
	if err := operation.close(ctx); err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultError, err.Error())
		return err
	}
	a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultOK, decision.MatchedRule)
	a.AutoSync(ctx, "remove "+path)
	return nil
}

// AutoSync fires a `gopass sync` for every configured remote after a
// successful write. It is best-effort: a failure does NOT propagate to
// the caller — Add/Rotate/Remove return nil even if the push fails, on
// the grounds that the local write already succeeded and the user
// should not have to redo the write just because the network was down.
//
// Failure modes are surfaced in two ways:
//   - A warning line is written to a.Stderr (defaults to os.Stderr).
//   - An audit row with action=sync_push, result=error is appended so
//     operators can correlate „CLI exited 0 but the remote is stale".
//
// The skip path (no sync config, no remotes, or MYS_AUTO_SYNC=0/--no-sync)
// produces no audit row and no stderr output.
//
// A 5-second timeout is imposed on top of the caller's context so a
// hanging `git push` cannot block the CLI indefinitely.
func (a *App) AutoSync(ctx context.Context, trigger string) {
	if a.SuppressAutoSync || NoSyncFlag {
		return
	}
	ctx2, cancel := context.WithTimeout(ctx, autoSyncTimeout)
	defer cancel()
	skipped, err := syncpkg.AutoSync(ctx2, autoSyncRunner, trigger)
	if skipped {
		return
	}
	d := caller.Identify(a.Override)
	if err != nil {
		reason := fmt.Sprintf("auto-sync after %s: %s", trigger, err.Error())
		a.writeAudit(ctx, audit.ActionSyncPush, "", d, audit.ResultError, reason)
		w := a.stderr()
		a.warningMu.Lock()
		defer a.warningMu.Unlock()
		fmt.Fprintf(w, "warning: auto-sync failed (%s) — run \"mys sync push\" manually when online\n", err.Error())
		return
	}
	a.writeAudit(ctx, audit.ActionSyncPush, "", d, audit.ResultOK,
		fmt.Sprintf("auto-sync after %s", trigger))
}

// stderr returns a.Stderr or os.Stderr as a fallback. Extracted so
// tests can pin it to a buffer without having to protect against nil.
func (a *App) stderr() io.Writer {
	if a.Stderr != nil {
		return a.Stderr
	}
	return os.Stderr
}

// DomainMatch is the app-layer view of a domain search hit. It reuses
// store.DomainMatch so CLI and MCP callers do not have to juggle two
// parallel types, but keeps a small adapter for clarity at the call site.
type DomainMatch = store.DomainMatch

// SearchByDomain walks every entry visible to the caller, classifies it
// against the query with store.MatchDomain, and returns two ordered
// slices:
//
//   - matches  — tier exact or subdomain. These are what the user "almost
//     certainly" wanted.
//   - similar  — tier substring or fuzzy. These are candidates the caller
//     can suggest to the user or to an AI, with tier + hint so
//     the consumer can render an explanation.
//
// When includeSimilar is false the similar slice is nil to save work on
// large stores. Policy filtering happens at the List() step — denied
// paths never enter either slice. A single audit row records the search
// with a tier breakdown in the reason; no per-path rows are written for
// this read-only metadata walk (each Get() inside would produce its own
// row, which would spam the log on big stores).
func (a *App) SearchByDomain(
	ctx context.Context,
	query string,
	includeSimilar bool,
) (matches []DomainMatch, similar []DomainMatch, resultErr error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil, nil
	}
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStagePrepare),
		)
		return nil, nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			matches = nil
			similar = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	paths, err := operation.store.List(ctx, "")
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStageList),
		)
		return nil, nil, err
	}
	entries, err := operation.decryptBatch(ctx, paths, "search_domain")
	if err != nil {
		a.writeAudit(
			ctx, audit.ActionSearch, "", d,
			audit.ResultError, searchAuditFailure(query, searchAuditStageDecrypt),
		)
		return nil, nil, err
	}
	matches = make([]DomainMatch, 0)
	similar = make([]DomainMatch, 0)
	var exact, subdomain, substring, fuzzy int
	for _, e := range entries {
		tier, hint, ok := store.MatchDomain(query, e.Domain)
		if !ok {
			continue
		}
		m := DomainMatch{Entry: e, Tier: tier, Hint: hint}
		switch tier {
		case store.TierExact:
			exact++
			matches = append(matches, m)
		case store.TierSubdomain:
			subdomain++
			matches = append(matches, m)
		case store.TierSubstring:
			substring++
			if includeSimilar {
				similar = append(similar, m)
			}
		case store.TierFuzzy:
			fuzzy++
			if includeSimilar {
				similar = append(similar, m)
			}
		}
	}
	reason := fmt.Sprintf(
		"%s exact=%d subdomain=%d substring=%d fuzzy=%d similar=%t",
		searchAuditMetadata(query),
		exact,
		subdomain,
		substring,
		fuzzy,
		includeSimilar,
	)
	a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultOK, reason)
	return matches, similar, nil
}

// DoctorRotationEntries returns every policy-visible entry needed by the
// rotation-overdue doctor check. It is intentionally separate from
// BrowseDetailed so the signed team audit records the purpose-specific
// doctor_rotation action while still batching once per shared mount.
func (a *App) DoctorRotationEntries(
	ctx context.Context,
) (entries []*store.Entry, resultErr error) {
	d := a.callerDetail()
	operation, err := a.beginAccessOperation(ctx, d, true, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := operation.close(ctx); closeErr != nil {
			entries = nil
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	paths, err := operation.store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	return operation.decryptBatch(ctx, paths, "doctor_rotation")
}

// AuditInit records a one-time init event.
func (a *App) AuditInit(ctx context.Context, note string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionInit, "", d, audit.ResultOK, note)
}

// AuditExport records a bulk plaintext export attempt (bw-export) — one
// summary row per invocation, so an export of N entries is
// distinguishable in the audit log from N unrelated gets. The org filter
// is carried in the path column (org=<org> encoding); reason carries
// destination and entry count on success, or the refusal cause.
func (a *App) AuditExport(ctx context.Context, org, result, reason string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionExport, orgPath(org), d, result, reason)
}

// AuditBWPush records one bw-push mirror run — same one-row-per-run
// shape as AuditExport, with the target server and change counts in the
// reason. Refusals and failures land here too (result denied/error).
func (a *App) AuditBWPush(ctx context.Context, org, result, reason string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionBWPush, orgPath(org), d, result, reason)
}

// AuditBWImport records one bw-import run — same one-row-per-run shape
// as AuditBWPush, with the diff class counts (and, on --apply, the
// applied/skipped/failed outcome) in the reason.
func (a *App) AuditBWImport(ctx context.Context, org, result, reason string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionBWImport, orgPath(org), d, result, reason)
}

// AuditWebOpen records that the web UI was started.
func (a *App) AuditWebOpen(ctx context.Context, addr string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionWebOpen, "", d, audit.ResultOK, "listen="+addr)
}

// AuditMCPStart records that the MCP server was started.
func (a *App) AuditMCPStart(ctx context.Context) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionMCPStart, "", d, audit.ResultOK, "stdio")
}

func (a *App) writeAudit(ctx context.Context, action, path string, d caller.Detail, result, reason string) {
	if a.Audit == nil {
		return
	}
	detail, _ := json.Marshal(d)
	org := ""
	if path != "" && !strings.HasPrefix(path, "org=") {
		org = store.OrgOf(path)
	} else if strings.HasPrefix(path, "org=") {
		org = strings.TrimPrefix(path, "org=")
	}
	_, _ = a.Audit.Write(ctx, audit.Entry{
		Action:      action,
		SecretPath:  path,
		Org:         org,
		ActorKind:   string(d.Kind),
		ActorDetail: detail,
		Result:      result,
		Reason:      reason,
	})
}

// orgPath encodes an org-only audit target.
func orgPath(org string) string {
	if org == "" {
		return ""
	}
	return "org=" + org
}
