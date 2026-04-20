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
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
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

// App wires everything together.
type App struct {
	Store    store.Interface
	Audit    *audit.Log
	Policy   *policy.Policy
	Override string // explicit --requester value for this invocation
	// Stderr is where user-visible warnings (auto-sync failure, etc.)
	// are written. Nil falls back to os.Stderr. Tests inject a
	// *bytes.Buffer here to assert on the output.
	Stderr io.Writer
}

// Open opens the store + audit DB + policy in one call. Callers are
// responsible for calling Close when done.
func Open(ctx context.Context, override string) (*App, error) {
	st, err := store.Open(ctx)
	if err != nil {
		return nil, err
	}
	al, err := audit.Open("")
	if err != nil {
		_ = st.Close(ctx)
		return nil, err
	}
	pol, err := policy.Load("")
	if err != nil {
		_ = st.Close(ctx)
		_ = al.Close()
		return nil, err
	}
	return &App{Store: st, Audit: al, Policy: pol, Override: override}, nil
}

// OpenAuditOnly is used by commands (`audit tail`, `web`) that do not need
// to decrypt secrets. It skips the gopass store to avoid unlocking GPG.
func OpenAuditOnly() (*App, error) {
	al, err := audit.Open("")
	if err != nil {
		return nil, err
	}
	pol, err := policy.Load("")
	if err != nil {
		_ = al.Close()
		return nil, err
	}
	return &App{Audit: al, Policy: pol}, nil
}

func (a *App) Close(ctx context.Context) error {
	var errs []error
	if a.Store != nil {
		if err := a.Store.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if a.Audit != nil {
		if err := a.Audit.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ErrDenied is returned when the scope policy rejects a request.
type ErrDenied struct {
	Path   string
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("denied: %s (%s)", e.Path, e.Reason)
}

// Get fetches a decrypted entry, respecting policy + writing audit.
func (a *App) Get(ctx context.Context, path string) (*store.Entry, error) {
	d := caller.Identify(a.Override)
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultDenied, decision.Reason)
		return nil, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	e, err := a.Store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultError, err.Error())
		return nil, err
	}
	a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultOK, decision.MatchedRule)
	return e, nil
}

// List returns paths filtered by the caller's policy. Paths that would be
// denied are silently filtered out of the result; a single audit entry is
// written for the list action itself.
func (a *App) List(ctx context.Context, org string) ([]string, error) {
	d := caller.Identify(a.Override)
	paths, err := a.Store.List(ctx, org)
	if err != nil {
		a.writeAudit(ctx, audit.ActionList, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if a.Policy.Evaluate(string(d.Kind), d.AgentLabel, p).Allowed {
			filtered = append(filtered, p)
		}
	}
	a.writeAudit(ctx, audit.ActionList, orgPath(org), d, audit.ResultOK,
		fmt.Sprintf("%d of %d entries visible", len(filtered), len(paths)))
	return filtered, nil
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
	return a.searchWith(ctx, query, a.Store)
}

func (a *App) searchWith(ctx context.Context, query string, ss storeSearcher) ([]string, error) {
	d := caller.Identify(a.Override)
	// Cache reasons for denied paths so we do not have to call Evaluate
	// twice per path. The closure collects them as a side effect while
	// the store walks the list.
	denyReasons := make(map[string]string)
	allow := func(p string) bool {
		dec := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, p)
		if !dec.Allowed {
			denyReasons[p] = dec.Reason
			return false
		}
		return true
	}
	allowed, denied, err := ss.Search(ctx, query, allow)
	if err != nil {
		a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultError, err.Error())
		return nil, err
	}
	// Per-path denied audit rows.
	for _, p := range denied {
		reason := denyReasons[p]
		if reason == "" {
			reason = a.Policy.Evaluate(string(d.Kind), d.AgentLabel, p).Reason
		}
		a.writeAudit(ctx, audit.ActionSearch, p, d, audit.ResultDenied, reason)
	}
	total := len(allowed) + len(denied)
	a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultOK,
		fmt.Sprintf("query=%q %d of %d visible", query, len(allowed), total))
	return allowed, nil
}

// Add writes a new entry after policy check.
func (a *App) Add(ctx context.Context, e *store.Entry) error {
	d := caller.Identify(a.Override)
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, e.Path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: e.Path, Reason: decision.Reason}
	}
	if err := a.Store.Set(ctx, e); err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultError, err.Error())
		return err
	}
	a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultOK, decision.MatchedRule)
	a.AutoSync(ctx, "add "+e.Path)
	return nil
}

// Rotate writes a new password for an existing entry.
func (a *App) Rotate(ctx context.Context, path, newPassword string) error {
	d := caller.Identify(a.Override)
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: path, Reason: decision.Reason}
	}
	if err := a.Store.Rotate(ctx, path, newPassword); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultOK, decision.MatchedRule)
	a.AutoSync(ctx, "rotate "+path)
	return nil
}

// Remove deletes an entry after policy check.
func (a *App) Remove(ctx context.Context, path string) error {
	d := caller.Identify(a.Override)
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: path, Reason: decision.Reason}
	}
	if err := a.Store.Remove(ctx, path); err != nil {
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
	if NoSyncFlag {
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

// AuditInit records a one-time init event.
func (a *App) AuditInit(ctx context.Context, note string) {
	d := caller.Identify(a.Override)
	a.writeAudit(ctx, audit.ActionInit, "", d, audit.ResultOK, note)
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
