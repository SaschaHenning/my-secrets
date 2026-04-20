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
	"strings"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

// App wires everything together.
type App struct {
	Store    *store.Store
	Audit    *audit.Log
	Policy   *policy.Policy
	Override string // explicit --requester value for this invocation
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
	return nil
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
