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
	"time"

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
func (a *App) Get(ctx context.Context, path string) (*store.Entry, error) {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionGet, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
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

// GenerateTOTP computes the current TOTP code for a stored entry. Policy
// is enforced the same way as for Get — AI callers hit the same allow/deny
// gate. Every invocation writes a totp_generate audit row including the
// time-window index so repeated calls within the same window are
// identifiable. Non-TOTP entries produce a descriptive error plus an
// error-result audit row.
func (a *App) GenerateTOTP(ctx context.Context, path string, now time.Time) (string, int, error) {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultDenied, err.Error())
		return "", 0, &ErrDenied{Path: path, Reason: err.Error()}
	}
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultDenied, decision.Reason)
		return "", 0, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	e, err := a.Store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, err.Error())
		return "", 0, err
	}
	if e.Kind != store.KindTOTP {
		msg := fmt.Sprintf("path %q is not a totp entry", path)
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, msg)
		return "", 0, errors.New(msg)
	}
	alg, algErr := totppkg.ParseAlgorithm(e.TOTPAlgorithm)
	if algErr != nil {
		a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, algErr.Error())
		return "", 0, algErr
	}
	digits, digErr := totppkg.ParseDigits(fmt.Sprintf("%d", e.TOTPDigits))
	if digErr != nil {
		// Treat zero as default here instead of an error.
		if e.TOTPDigits == 0 {
			digits, _ = totppkg.ParseDigits("")
		} else {
			a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultError, digErr.Error())
			return "", 0, digErr
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
		return "", 0, err
	}
	a.writeAudit(ctx, audit.ActionTOTPGenerate, path, d, audit.ResultOK, reason)
	return code, secondsLeft, nil
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
func (a *App) BrowseDetailed(ctx context.Context, org string) ([]*store.Entry, error) {
	d := caller.Identify(a.Override)
	paths, err := a.Store.List(ctx, org)
	if err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, orgPath(org), d, audit.ResultError, err.Error())
		return nil, err
	}
	entries := make([]*store.Entry, 0, len(paths))
	for _, p := range paths {
		// Request cancelled mid-decrypt — e.g. the browser aborted the
		// /entries load because the user navigated away before the
		// whole store finished decrypting. Returning the entries
		// decrypted so far as if the list were complete is exactly the
		// "entries silently vanish on a quick back-click" bug: the web
		// entriesCache would store that truncated result and serve it as
		// good. Fail instead, so nothing partial is ever cached. The
		// error audit row uses a detached context because ctx itself is
		// already cancelled and would drop the write.
		if ctx.Err() != nil {
			a.writeAudit(context.Background(), audit.ActionListDetail, orgPath(org), d, audit.ResultError, ctx.Err().Error())
			return nil, ctx.Err()
		}
		if !a.Policy.Evaluate(string(d.Kind), d.AgentLabel, p).Allowed {
			continue
		}
		e, gerr := a.Store.Get(ctx, p)
		if gerr != nil {
			// Distinguish "this one entry is genuinely undecryptable"
			// (tolerate, skip it) from "the whole request was cancelled"
			// (fatal — never a partial-as-success). ctx.Err() is the
			// reliable signal: the store may wrap the cancellation error
			// as a plain string that errors.Is won't match, but a
			// cancelled request always makes ctx.Err() non-nil.
			if ctx.Err() != nil {
				a.writeAudit(context.Background(), audit.ActionListDetail, orgPath(org), d, audit.ResultError, ctx.Err().Error())
				return nil, ctx.Err()
			}
			continue
		}
		entries = append(entries, e)
	}
	a.writeAudit(ctx, audit.ActionListDetail, orgPath(org), d, audit.ResultOK,
		fmt.Sprintf("%d entries", len(entries)))
	return entries, nil
}

// Inspect decrypts a single entry for metadata display — Kind, Tags,
// Domain, etc. Like BrowseDetailed, this writes an ActionListDetail row,
// NOT ActionGet: the web UI's masked entry-detail page uses Inspect, so
// simply viewing an entry's metadata does not count as reading it. Only
// the explicit reveal action (App.Get) does.
func (a *App) Inspect(ctx context.Context, path string) (*store.Entry, error) {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionListDetail, path, d, audit.ResultDenied, decision.Reason)
		return nil, &ErrDenied{Path: path, Reason: decision.Reason}
	}
	e, err := a.Store.Get(ctx, path)
	if err != nil {
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
func (a *App) History(ctx context.Context, path string, limit int) ([]history.Revision, error) {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionHistory, path, d, audit.ResultDenied, err.Error())
		return nil, &ErrDenied{Path: path, Reason: err.Error()}
	}
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
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

// Add writes a new entry after policy check. Add is defined as a rotation
// event for the purposes of the rotation-reminder feature: it always
// stamps RotatedAt to the current UTC time. Callers that explicitly set
// a non-zero RotatedAt before calling Add have that value overwritten —
// the timestamp is a book-keeping field maintained by the app layer, not
// user input.
func (a *App) Add(ctx context.Context, e *store.Entry) error {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(e.Path); err != nil {
		a.writeAudit(ctx, audit.ActionAdd, e.Path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: e.Path, Reason: err.Error()}
	}
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, e.Path)
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
	if err := a.Store.Set(ctx, e); err != nil {
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
func (a *App) Rotate(ctx context.Context, path, newPassword string) error {
	d := caller.Identify(a.Override)
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: path, Reason: err.Error()}
	}
	decision := a.Policy.Evaluate(string(d.Kind), d.AgentLabel, path)
	if !decision.Allowed {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultDenied, decision.Reason)
		return &ErrDenied{Path: path, Reason: decision.Reason}
	}
	// Load the existing entry so the rotated_at stamp can be carried in
	// the Set() call alongside the existing metadata. We bypass
	// App.Get's audit row because the rotate audit row already captures
	// this operation; emitting a separate get row would double-count.
	existing, err := a.Store.Get(ctx, path)
	if err != nil {
		a.writeAudit(ctx, audit.ActionRotate, path, d, audit.ResultError, err.Error())
		return err
	}
	existing.Password = newPassword
	existing.RotatedAt = time.Now().UTC()
	if err := a.Store.Set(ctx, existing); err != nil {
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
	if err := cleanSecretPath(path); err != nil {
		a.writeAudit(ctx, audit.ActionRemove, path, d, audit.ResultDenied, err.Error())
		return &ErrDenied{Path: path, Reason: err.Error()}
	}
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
func (a *App) SearchByDomain(ctx context.Context, query string, includeSimilar bool) (matches []DomainMatch, similar []DomainMatch, err error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil, nil
	}
	d := caller.Identify(a.Override)
	paths, err := a.Store.List(ctx, "")
	if err != nil {
		a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultError, err.Error())
		return nil, nil, err
	}
	matches = make([]DomainMatch, 0)
	similar = make([]DomainMatch, 0)
	var exact, subdomain, substring, fuzzy int
	for _, p := range paths {
		// Policy pre-filter. Denied paths are silently skipped — the
		// aggregate audit row at the end still records the search, and
		// a denied caller never sees which paths exist.
		if !a.Policy.Evaluate(string(d.Kind), d.AgentLabel, p).Allowed {
			continue
		}
		e, gerr := a.Store.Get(ctx, p)
		if gerr != nil {
			continue
		}
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
	// Log the canonicalised form of the query rather than the raw user
	// input. If the user typed a full URL with credentials in it, or a
	// password by mistake, the plain-string form would otherwise end up
	// in the append-only audit DB (review finding I7). The normalised
	// value carries enough information for audit review.
	logged := store.NormalizeDomain(query)
	if logged == "" {
		logged = fmt.Sprintf("len=%d", len(strings.TrimSpace(query)))
	}
	reason := fmt.Sprintf("domain=%q exact=%d subdomain=%d substring=%d fuzzy=%d similar=%t",
		logged, exact, subdomain, substring, fuzzy, includeSimilar)
	a.writeAudit(ctx, audit.ActionSearch, "", d, audit.ResultOK, reason)
	return matches, similar, nil
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
