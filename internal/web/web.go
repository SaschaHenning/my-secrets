// Package web serves a read-only-except-reveal localhost UI: browsing
// the audit log, browsing/searching secrets metadata (never decrypts a
// value just to render a list — see App.BrowseDetailed/App.Inspect), and
// an explicit, re-authenticated reveal action for a single value (see
// handleReveal) that mirrors `mys get --reveal` in the audit log.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/gopassinit"
	"github.com/SaschaHenning/my-secrets/internal/store"
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
)

//go:embed templates/*.html static/*
var assets embed.FS

var templates *template.Template

// sessionCookieName is the cookie that carries a successful Touch-ID
// session ID between requests.
const sessionCookieName = "mys_session"

// defaultSessionTTL is how long a session stays valid without activity.
// After this window of silence the idle watcher tears the server down.
const defaultSessionTTL = 30 * time.Minute

// idleTickInterval is how often the idle watcher polls sessionStore.
// Kept short enough to respond promptly once ttl is exceeded but long
// enough not to waste cycles.
const idleTickInterval = 30 * time.Second

// touchIDWriteBudget is how long a Touch-ID-gated handler (login, reveal)
// gets to write its response, overriding the server's normal 10s
// WriteTimeout for just that request. defaultRequireTouchID itself waits
// up to 30s (auth_darwin.go) and explicitly supports falling back to a
// typed password, which routinely takes longer than the server's default
// write budget — without this override, a slow-but-successful Touch-ID
// challenge would still get its response cut off, even though App.Get
// already ran and wrote a `get` audit row for a value the browser never
// actually received.
const touchIDWriteBudget = 45 * time.Second

// entriesWriteBudget is how long /entries gets to decrypt and render.
// handleEntries calls App.BrowseDetailed(ctx, ""), which decrypts EVERY
// policy-visible entry one at a time — for a real store (as opposed to
// the handful of fixture entries in tests), this routinely exceeds the
// server's normal 10s WriteTimeout. Without this override the request's
// context is cancelled mid-decrypt (surfacing as a wall of "context
// canceled" errors from the remaining Store.Get calls) and the
// connection is torn down before any response reaches the browser — the
// page silently "loads nothing". 2 minutes is a generous ceiling for a
// personal store; if this genuinely isn't enough, the fix is caching
// decrypted metadata between loads, not raising this further.
const entriesWriteBudget = 2 * time.Minute

func init() {
	funcs := template.FuncMap{
		"actorBadge":  actorBadge,
		"resultBadge": resultBadge,
		"shortTime": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"relativeTime": relativeTime,
		"mask":         store.MaskedPassword,
		// maskField masks a custom Fields value the same way Password is
		// always masked, when its key looks secret-like (contains
		// "password" or "secret" — same rule the store's own search uses
		// to keep such values out of free-text matches). Custom fields are
		// user-defined and can legally be named "api_secret", "db_password",
		// etc., so this page must not render them raw just because they
		// aren't the well-known Password field.
		"maskField": func(key, value string) string {
			if store.IsSecretLikeFieldKey(key) {
				return store.MaskedPassword(value)
			}
			return value
		},
		"searchBlob": searchableText,
	}
	templates = template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html"))
}

// Version is the running binary's version string, injected by cmd/mys
// before Serve (ldflags-set main.Version). Package-level like
// app.NoSyncFlag so the Serve signature stays stable. Shown in the
// login and start page footers so a PWA user can verify an update
// landed without a shell.
var Version = "dev"

// Serve starts the HTTP server on 127.0.0.1:port and blocks until the
// context is cancelled, the process receives an idle-timeout signal, or
// the server itself fails. The audit-open app passed in must have its
// Audit field set.
func Serve(ctx context.Context, a *app.App, port int, stdout io.Writer) error {
	return serveWith(ctx, a, port, stdout, defaultSessionTTL, idleTickInterval)
}

// serveWith is the testable core of Serve. ttl and tick are parameterised
// so tests can run the full HTTP stack with sub-second timings.
func serveWith(ctx context.Context, a *app.App, port int, stdout io.Writer, ttl, tick time.Duration) error {
	// background tracks the cache's goroutines (warm, stale refresh, store
	// watcher). The defers run LIFO — cancel() stops them, Wait() blocks
	// until they are out of the store and audit DB, so serveWith cannot
	// return into App.Close mid-decrypt.
	var background sync.WaitGroup
	cancelCtx, cancel := context.WithCancel(ctx)
	defer background.Wait()
	defer cancel()

	a.AuditWebOpen(cancelCtx, fmt.Sprintf("127.0.0.1:%d", port))

	store := newSessionStore(ttl)

	mux := http.NewServeMux()
	// Public routes. /login deliberately lives outside the auth gate
	// so the user can reach it; /healthz stays open so systemd-style
	// supervisors can probe without a session.
	mux.HandleFunc("/login", handleLogin(store, ttl))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	// Static assets stay public too — they carry no data.
	mux.Handle("/static/", http.FileServerFS(assets))

	// Gated routes. Every handler here goes through authGate, which
	// redirects to /login on a missing / stale cookie.
	entries := newEntriesCache()
	entries.bindLifetime(cancelCtx, &background)
	// Pre-warm the full-store decrypt so the first /entries load is
	// instant, and watch the store so an out-of-band write shows up in
	// seconds. Only when the app has a store (audit-only openings lack one).
	var watcher *storeWatcher
	if a.Store != nil {
		entries.goBackground(func(ctx context.Context) { entries.warm(ctx, a) })
		if watcher = newStoreWatcher(cancelCtx, a, entries); watcher != nil {
			entries.goBackground(watcher.run)
		}
	}
	mux.Handle("/", authGate(store, handleIndex(a)))
	mux.Handle("/audit", authGate(store, handleAudit(a)))
	mux.Handle("/entries", authGate(store, handleEntries(a, entries)))
	// Go's mux prefers the literal, so this never shadows a real entry: a
	// secret path "refresh" would have to sit outside any org.
	mux.Handle("/entries/refresh", authGate(store, handleEntriesRefresh(entries, watcher)))
	mux.Handle("/entries/{path...}", authGate(store, handleEntryDetail(a)))

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      localhostOnly(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Fprintf(stdout, "my-secrets web UI → http://127.0.0.1:%d\n", port)
	fmt.Fprintln(stdout, "press Ctrl-C to stop")

	// Idle watcher: closes store.idleCh after ttl of silence, which
	// then triggers a graceful shutdown below.
	watcherStop := make(chan struct{})
	go store.runWatcher(watcherStop, tick)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		close(watcherStop)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-cancelCtx.Done():
		close(watcherStop)
		return gracefulShutdown(srv, errCh)
	case <-store.IdleC():
		fmt.Fprintln(stdout, "idle shutdown after 30 min inactivity")
		close(watcherStop)
		cancel()
		return gracefulShutdown(srv, errCh)
	}
}

// gracefulShutdown stops the server with a short grace period and reaps
// the serve goroutine.
func gracefulShutdown(srv *http.Server, errCh <-chan error) error {
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := srv.Shutdown(shutdown)
	<-errCh
	return err
}

// localhostOnly rejects any request whose RemoteAddr is not loopback.
// Parses RemoteAddr properly (host:port) rather than prefix-matching.
func localhostOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// authGate wraps a handler so it only fires for callers with a valid
// session cookie. Missing/stale cookies get a 303 See Other back to
// /login?next=<original request>, so a deep link (e.g. the PWA's
// start_url, or a bookmarked /entries/{path}) survives a re-login
// instead of always dumping the user back on the stats overview. Every
// gated response also gets Cache-Control: no-store — set here once
// rather than per-handler, since it must cover everything behind the
// gate (entry metadata, and since the reveal endpoint below, actual
// secret values), not just the one route that first needed it.
func authGate(store *sessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || !store.Validate(c.Value) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// defaultLandingPath is where a successful login goes when there's no
// (valid) next= target — the start page (search box + recently-used),
// which renders instantly because it decrypts nothing. Deliberately NOT
// /entries: that decrypts the entire store (tens of seconds on a large
// store), which right after login looked like the app hanging.
const defaultLandingPath = "/"

// safeNextPath validates a caller-supplied redirect target, returning
// defaultPath unless next is unambiguously a same-origin path. Guards
// against open-redirect tricks: a bare "//host" or "http://host" would
// send the post-login redirect off this server entirely. A leading
// backslash is rejected too — some browsers resolve it the same as a
// forward slash when following a Location header, which url.Parse alone
// would not flag as absolute.
func safeNextPath(next, defaultPath string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsRune(next, '\\') {
		return defaultPath
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return defaultPath
	}
	return next
}

// extendWriteDeadline pushes the current request's write deadline out to
// budget, overriding the server-wide WriteTimeout for a handler that's
// about to do something slower than the default 10s allows (a Touch-ID
// challenge, or decrypting an entire store). Best-effort: SetWriteDeadline
// returns http.ErrNotSupported for a ResponseWriter that doesn't
// implement the deadline-setting interface (e.g. httptest.ResponseRecorder
// in unit tests) — that's fine, tests use fixtures/stubs fast enough that
// the real timeout window never matters there, and production always
// runs behind the real net/http server, which does support it.
func extendWriteDeadline(w http.ResponseWriter, budget time.Duration) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(budget))
}

// --- login handler ---------------------------------------------------------

// handleLogin renders the login page on GET and runs the Touch-ID
// challenge on POST. Successful POSTs set the session cookie and
// redirect to /.
func handleLogin(store *sessionStore, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			renderLogin(w, "", r.URL.Query().Get("next"))
		case http.MethodPost:
			next := safeNextPath(r.FormValue("next"), defaultLandingPath)
			extendWriteDeadline(w, touchIDWriteBudget)
			if err := requireTouchID(r.Context()); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				renderLogin(w, err.Error(), next)
				return
			}
			id := store.Issue()
			if id == "" {
				http.Error(w, "failed to issue session", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    id,
				Path:     "/",
				HttpOnly: true,
				// Localhost HTTP, so Secure is off. SameSite=Lax is
				// enough to block cross-site POSTs from leaking the
				// cookie; the login form itself is same-origin.
				Secure:   false,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(ttl.Seconds()),
			})
			http.Redirect(w, r, next, http.StatusSeeOther)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// renderLogin writes the tiny inline login page. We do not route this
// through html/template because the page is static aside from an
// optional error message and the next= redirect target, both of which
// we escape manually. next is echoed back as a hidden form field (not
// re-validated here — handleLogin's POST branch is what enforces
// safeNextPath before ever issuing a redirect) so a retry after a failed
// Touch-ID challenge doesn't lose the original destination.
func renderLogin(w http.ResponseWriter, errMsg, next string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errBlock := ""
	if errMsg != "" {
		errBlock = fmt.Sprintf(`<p class="empty" style="color:#f87171">%s</p>`, template.HTMLEscapeString(errMsg))
	}
	nextField := ""
	if next != "" {
		nextField = fmt.Sprintf(`<input type="hidden" name="next" value="%s">`, template.HTMLEscapeString(next))
	}
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>my-secrets — Anmelden</title>
<link rel="stylesheet" href="/static/styles.css">
<link rel="manifest" href="/static/manifest.webmanifest">
<link rel="apple-touch-icon" href="/static/icons/icon-192.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="my-secrets">
<meta name="theme-color" content="#0f1117">
</head>
<body>
<header><h1>my-secrets</h1></header>
<main>
<section class="stats" style="grid-template-columns: 1fr; max-width: 420px; margin: 3rem auto;">
  <div class="stat">
    <div class="label">Anmeldung erforderlich</div>
    <p style="margin-top:0.8rem;color:var(--muted);font-size:0.9rem;">
      Mit Touch&nbsp;ID entsperren (oder deinem macOS-Passwort). Danach
      bleibt die Sitzung offen — Aufdecken und Kopieren ohne weitere
      Abfrage. Sie läuft nach 30&nbsp;Minuten Inaktivität automatisch ab.
    </p>
    <form method="post" action="/login" style="margin-top:1rem;">
      %s
      <button type="submit" class="btn-link" style="background:var(--accent);color:white;padding:0.5rem 1rem;border:none;border-radius:4px;cursor:pointer;font-weight:600;">
        Mit Touch ID anmelden
      </button>
    </form>
    %s
  </div>
</section>
</main>
<footer>local read-only UI · bound to 127.0.0.1 · no secret values are rendered here · mys %s</footer>
<script>
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/static/sw.js');
</script>
</body>
</html>`, nextField, errBlock, template.HTMLEscapeString(Version))
}

// --- handlers --------------------------------------------------------------

func handleIndex(a *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Summary numbers: total rows, rows per actor, recent denied count.
		total, _ := a.Audit.Count(ctx)
		last, err := a.Audit.Tail(ctx, audit.Filter{Limit: 10})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		aiCount := countActor(a, ctx, audit.ActorAI)
		humanCount := countActor(a, ctx, audit.ActorHuman)
		deniedCount := countResult(a, ctx, audit.ResultDenied)

		// Sync status: read the local config file directly, no network
		// call. A page load must never block on reachability — that
		// probe (`git ls-remote`) stays CLI-only, in `mys sync status`.
		// Load() returns an empty Config (not an error) when sync isn't
		// configured, which renders as a natural empty state.
		var syncRemotes []syncpkg.StoreRemote
		if cfg, err := syncpkg.Load(""); err == nil {
			syncRemotes = cfg.Remotes
		}

		// Recently-used quick-access: the most recently *revealed* entries
		// (audit.LastAccessByPath is get/ok-only, so this is "actually
		// used", not merely browsed). Rendered as path + relative time +
		// a one-click copy-password button — no decrypt at render time,
		// so the start page stays instant and can't be slow/cancelled.
		recents := recentlyUsed(a, ctx, 10)

		data := map[string]any{
			"Total":       total,
			"AI":          aiCount,
			"Human":       humanCount,
			"Denied":      deniedCount,
			"Recent":      last,
			"Recents":     recents,
			"Page":        "index",
			"SyncRemotes": syncRemotes,
			"Version":     Version,
		}
		if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// recentEntry is one row of the start page's "zuletzt benutzt" list.
type recentEntry struct {
	Path string
	When time.Time
}

// recentlyUsed returns up to limit entries, most-recently-revealed
// first, from the audit log's per-path last-access (get/ok) timestamps.
// Metadata-free by design: it only needs the path (to link/copy) and the
// timestamp, so it never decrypts — cheap and cancellation-proof.
func recentlyUsed(a *app.App, ctx context.Context, limit int) []recentEntry {
	byPath, err := a.Audit.LastAccessByPath(ctx)
	if err != nil {
		return nil
	}
	out := make([]recentEntry, 0, len(byPath))
	for p, t := range byPath {
		out = append(out, recentEntry{Path: p, When: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func countActor(a *app.App, ctx context.Context, actor string) int64 {
	// Cheap count — we reuse the existing Tail filter to fetch then count.
	// For MVP this is fine; entries are bounded in practice.
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Actor: actor, Limit: 10000})
	return int64(len(rows))
}

func countResult(a *app.App, ctx context.Context, result string) int64 {
	rows, _ := a.Audit.Tail(ctx, audit.Filter{Limit: 10000})
	var n int64
	for _, r := range rows {
		if r.Result == result {
			n++
		}
	}
	return n
}

func handleAudit(a *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		filter := audit.Filter{
			Actor:  q.Get("actor"),
			Action: q.Get("action"),
			Org:    q.Get("org"),
			Path:   q.Get("path"),
			Limit:  limit,
		}
		if s := q.Get("since"); s != "" {
			if t, err := time.Parse("2006-01-02", s); err == nil {
				filter.Since = t
			}
		}
		entries, err := a.Audit.Tail(r.Context(), filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data := map[string]any{
			"Entries": entries,
			"Filter":  filter,
			"Page":    "audit",
		}
		if err := templates.ExecuteTemplate(w, "audit.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// orgGroup is one org's worth of entries, pre-sorted, for the always-show-
// everything entries page.
type orgGroup struct {
	Org     string
	Entries []*store.Entry
}

// groupByOrg buckets entries by their Org field (already populated by the
// store) and returns groups sorted by org name, with entries sorted by
// path within each group.
func groupByOrg(entries []*store.Entry) []orgGroup {
	byOrg := make(map[string][]*store.Entry)
	var orgs []string
	for _, e := range entries {
		if _, ok := byOrg[e.Org]; !ok {
			orgs = append(orgs, e.Org)
		}
		byOrg[e.Org] = append(byOrg[e.Org], e)
	}
	sort.Strings(orgs)
	groups := make([]orgGroup, 0, len(orgs))
	for _, o := range orgs {
		es := byOrg[o]
		sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
		groups = append(groups, orgGroup{Org: o, Entries: es})
	}
	return groups
}

// searchableText returns the lowercase blob of an entry's non-secret
// metadata used for filtering — path, username, url, domain, notes,
// kind, tags. Password and custom Fields values are never included,
// matching the store's own search semantics (never match on secret
// values). Rendered into each entry card's data-search attribute so the
// entries.html filter box can match client-side with zero server round
// trips.
func searchableText(e *store.Entry) string {
	parts := []string{e.Path, e.Username, e.URL, e.Domain, e.Notes, e.Kind}
	parts = append(parts, e.Tags...)
	return strings.ToLower(strings.Join(parts, " "))
}

// handleEntries serves the secrets browser at /entries. Shows every
// policy-visible entry (served via entriesCache; a decrypt only happens
// on a cold or stale cache), grouped by org, in one page —
// filtering then happens entirely client-side (see entries.html's inline
// script) against each card's data-search attribute, so typing narrows
// the view instantly with no server round trip. This trades the previous
// three-tier cheap/scoped/expensive design for a simpler, always-decrypt
// one, at the user's explicit request: for a personal store this size,
// one App.BrowseDetailed(ctx, "") call (one aggregated audit row,
// regardless of entry count) is fast enough that hiding entries behind an
// extra click just adds friction.
//
// "q" only pre-fills the search box's initial value — the inline script
// applies the same client-side filter to it on load, so a bookmarked/
// shared link (e.g. entry.html's "back to org") still narrows the view.
// entriesCacheTTL is when a cached decrypt is considered stale. With
// stale-while-revalidate (see entriesCache.get) a stale result is still
// served instantly and refreshed in the background, so this only controls
// how often that background refresh fires on access — not how long a user
// ever waits. Kept generous because the store only changes out-of-band
// (a `mys` CLI write or `mys sync pull`; the web UI has no write
// endpoints), and each refresh re-decrypts the whole store.
const entriesCacheTTL = 2 * time.Minute

// entriesCache memoises App.BrowseDetailed(ctx, "") — decrypting a real
// store's every entry takes tens of seconds (0.19s × 156 entries in the
// wild), far too slow to repeat on every /entries load or search.
//
// Serving strategy is stale-while-revalidate:
//   - cache present (fresh or stale) → returned immediately; a stale
//     result additionally kicks off one background refresh.
//   - cache absent (cold) → the caller blocks once on a synchronous
//     decrypt (bounded by entriesWriteBudget).
//
// warm() pre-populates it at server startup so even that first cold load
// is usually already done by the time the user navigates.
//
// Background refresh/warm run on the server's lifetime context, never a
// request's. Only successful decrypts are cached; an error leaves the
// previous good result in place (a transient failure never wedges
// /entries).
type entriesCache struct {
	mu      sync.Mutex
	at      time.Time
	entries []*store.Entry
	// fresh is what „Stand" shows: last full load OR last applied change.
	// Apart from at (the TTL anchor), which an incremental merge must not
	// push out.
	fresh      time.Time
	refreshing bool
	// lifetime cancels background work at shutdown, tracker lets serveWith
	// wait for it before App.Close pulls the store and audit DB out from
	// under a running decrypt. Both nil in tests (plain goroutines then).
	lifetime context.Context
	tracker  *sync.WaitGroup
}

func newEntriesCache() *entriesCache {
	return &entriesCache{}
}

// bindLifetime ties everything this cache starts to the server. Called
// once, before the first get/warm.
func (c *entriesCache) bindLifetime(ctx context.Context, tracker *sync.WaitGroup) {
	c.lifetime, c.tracker = ctx, tracker
}

// goBackground runs fn in a goroutine shutdown can cancel and wait for.
func (c *entriesCache) goBackground(fn func(context.Context)) {
	ctx := c.lifetime
	if ctx == nil {
		ctx = context.Background()
	}
	if c.tracker == nil {
		go fn(ctx)
		return
	}
	c.tracker.Add(1)
	go func() {
		defer c.tracker.Done()
		fn(ctx)
	}()
}

func (c *entriesCache) get(ctx context.Context, a *app.App) ([]*store.Entry, error) {
	c.mu.Lock()
	cached := c.entries
	stale := cached == nil || time.Since(c.at) >= entriesCacheTTL
	if cached != nil && stale && !c.refreshing {
		c.refreshing = true
		c.goBackground(func(ctx context.Context) { c.refresh(ctx, a) })
	}
	c.mu.Unlock()

	if cached != nil {
		return cached, nil // fresh or stale — served immediately
	}
	// Cold cache: block this one request on a full decrypt. (A concurrent
	// startup warm may briefly race this into a second decrypt — correct,
	// just transiently wasteful, and only in the ~30s before the first
	// load completes.)
	return c.load(ctx, a)
}

// load decrypts the whole store and, on success, replaces the cache.
func (c *entriesCache) load(ctx context.Context, a *app.App) ([]*store.Entry, error) {
	entries, err := a.BrowseDetailed(ctx, "")
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries, c.at = entries, time.Now()
	c.fresh = c.at
	c.mu.Unlock()
	return entries, nil
}

// freshness is when the cached set last matched the store. Zero if cold.
func (c *entriesCache) freshness() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fresh
}

// waitIdle blocks until no full refresh is in flight, or ctx expires: a
// running refresh re-reads the whole store anyway, so the button waits
// for it instead of queueing a second decrypt behind it.
func (c *entriesCache) waitIdle(ctx context.Context) {
	for {
		c.mu.Lock()
		busy := c.refreshing
		c.mu.Unlock()
		if !busy {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshPollInterval):
		}
	}
}

// refresh re-decrypts in the background (stale-while-revalidate), keeping
// the existing result on error. Its refreshing flag is cleared even if
// load panics/errs so a failed refresh never blocks future ones.
func (c *entriesCache) refresh(ctx context.Context, a *app.App) {
	defer func() {
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
	}()
	_, _ = c.load(ctx, a)
}

// warm pre-populates the cache at server startup so the first /entries
// load or search doesn't pay the full-store decrypt. No-op if already
// populated or a load is in flight.
func (c *entriesCache) warm(ctx context.Context, a *app.App) {
	c.mu.Lock()
	skip := c.entries != nil || c.refreshing
	if !skip {
		c.refreshing = true
	}
	c.mu.Unlock()
	if skip {
		return
	}
	c.refresh(ctx, a) // reuses refresh's refreshing-flag cleanup
}

// applyChange folds an out-of-band store change into the cached set:
// removed paths are dropped and new or rewritten paths are decrypted in
// ONE batch (App.BrowseDetailedPaths — one aggregated audit row, never a
// per-path read). Reports false when the change was not taken and the
// caller should retry; the previous good set stays served.
func (c *entriesCache) applyChange(ctx context.Context, a *app.App, change storeChange) bool {
	c.mu.Lock()
	if c.refreshing {
		c.mu.Unlock()
		return false
	}
	// Cold and idle: no load is in flight, so whichever load comes next
	// reads the store as it is now. Nothing to merge into, nothing lost.
	if c.entries == nil {
		c.mu.Unlock()
		return true
	}
	c.refreshing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
	}()

	updated, err := a.BrowseDetailedPaths(ctx, change.Changed)
	if err != nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = mergeEntries(c.entries, updated, change)
	c.fresh = time.Now()
	// c.at is deliberately left alone: an incremental merge only covers
	// what the watcher can see (the watched store's *.gpg files), so the
	// full-refresh TTL has to keep running on its own schedule as the
	// safety net for everything it cannot.
	return true
}

// mergeEntries rebuilds the cached set from the previous one plus the
// freshly decrypted entries, sorted by path so the page renders exactly
// as after a full load. Every touched path is dropped before the
// decrypted ones go back in: one the decrypt did not return is
// policy-hidden or gone, and a full load would skip it too.
func mergeEntries(current, updated []*store.Entry, change storeChange) []*store.Entry {
	byPath := make(map[string]*store.Entry, len(current)+len(updated))
	for _, e := range current {
		byPath[e.Path] = e
	}
	for _, p := range change.Changed {
		delete(byPath, p)
	}
	for _, p := range change.Removed {
		delete(byPath, p)
	}
	for _, e := range updated {
		byPath[e.Path] = e
	}
	merged := make([]*store.Entry, 0, len(byPath))
	for _, e := range byPath {
		merged = append(merged, e)
	}
	sort.Slice(merged, func(i, j int) bool { return merged[i].Path < merged[j].Path })
	return merged
}

// newStoreWatcher builds the watcher that keeps the entries cache in step
// with out-of-band store writes (`mys add`, `mys sync pull`) in seconds
// rather than at entriesCacheTTL. Nil when the store directory cannot be
// resolved; the TTL refresh then stays the only path in.
func newStoreWatcher(ctx context.Context, a *app.App, cache *entriesCache) *storeWatcher {
	root, err := gopassinit.DefaultStoreDir()
	if err != nil || root == "" {
		return nil
	}
	return &storeWatcher{
		root:     root,
		poll:     storePollInterval,
		debounce: storeDebounce,
		retryCap: storeRetryCap,
		apply: func(change storeChange) bool {
			// The server's context, never a request's: a store change
			// belongs to no request, must still stop at shutdown, and
			// survives the browser navigating away mid-refresh.
			return cache.applyChange(ctx, a, change)
		},
	}
}

// refreshPollInterval is how often waitIdle re-checks.
const refreshPollInterval = 100 * time.Millisecond

// refreshWaitBudget bounds the „Aktualisieren" button: at worst it waits
// out a full-store refresh. A var so tests need not sit through it.
var refreshWaitBudget = 30 * time.Second

// handleEntriesRefresh is the „Aktualisieren" button: check the store now
// instead of at the next poll, then redirect back to the list with the
// search intact (POST-redirect-GET, so a reload does not re-trigger it).
// The check goes through the watcher, whose lock the poll loop shares.
func handleEntriesRefresh(cache *entriesCache, watcher *storeWatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := "/entries"
		if q := strings.TrimSpace(r.FormValue("q")); q != "" {
			target += "?q=" + url.QueryEscape(q)
		}
		if r.Method != http.MethodPost {
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		extendWriteDeadline(w, refreshWaitBudget)
		ctx, cancel := context.WithTimeout(r.Context(), refreshWaitBudget)
		defer cancel()
		cache.waitIdle(ctx)
		if watcher != nil {
			watcher.checkNow()
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}

func handleEntries(a *app.App, cache *entriesCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		initial := strings.TrimSpace(r.URL.Query().Get("q"))

		extendWriteDeadline(w, entriesWriteBudget)
		entries, err := cache.get(ctx, a)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Best-effort: a query error just means "last read" shows as
		// blank for this render, not a failed page.
		lastReads, _ := a.Audit.LastAccessByPath(ctx)

		// Clock only: the date would always be today's.
		stand := ""
		if t := cache.freshness(); !t.IsZero() {
			stand = t.Local().Format("15:04:05")
		}
		data := map[string]any{
			"Page":      "entries",
			"Query":     initial,
			"Groups":    groupByOrg(entries),
			"LastReads": lastReads,
			"Stand":     stand,
		}
		if err := templates.ExecuteTemplate(w, "entries.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// handleEntryDetail serves the entry-detail page at /entries/{path...}.
// GET renders the masked view (App.Inspect — writes a list_detail row,
// does not count as a read). POST is the reveal action (handleReveal),
// gated by the login session, not a per-reveal prompt.
//
// No CSRF token on the reveal form: the session cookie is
// SameSite=Lax (session.go), which browsers do not attach to a
// cross-site POST — so a forged form on another origin can't even reach
// authGate with a valid session, let alone trigger a reveal.
func handleEntryDetail(a *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.PathValue("path")
		if path == "" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			renderMaskedEntry(w, r, a, path, "")
		case http.MethodPost:
			handleReveal(w, r, a, path)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleReveal reveals a secret's actual value. The session cookie
// obtained at login IS the gate: once authenticated, revealing is a
// single action with no per-reveal re-prompt. This deliberately does not
// re-authenticate — it matches the CLI, where `mys get --reveal`
// re-decrypts freely within the GPG agent's cache and is strictly more
// powerful than this loopback UI, so a per-reveal biometric here would
// add friction without adding real security (the owner's explicit call;
// see docs/SECURITY.md). App.Get still re-checks policy and writes the
// `get` audit row, so a denied path is refused (403) and every reveal
// remains logged, exactly like `mys get --reveal`. JSON mode returns
// {"password": "..."} for the entries table's inline copy button;
// otherwise the detail page is re-rendered with the value shown.
func handleReveal(w http.ResponseWriter, r *http.Request, a *app.App, path string) {
	// App.Get performs an in-process gopass/GPG decrypt that, on a cold
	// agent, blocks on a pinentry prompt (with a typed-passphrase
	// fallback) — longer than the server's default 10s WriteTimeout.
	// Without extending the deadline, App.Get would still run to
	// completion and write its `get`/`ok` audit row (WriteTimeout
	// doesn't cancel the request context), but the subsequent response
	// write would be truncated — an audit row for a value the browser
	// never received. The start page's inline copy-password button makes
	// this reachable directly from `/` (which itself decrypts nothing),
	// so the cushion is not merely theoretical. Same budget as login.
	extendWriteDeadline(w, touchIDWriteBudget)
	e, err := a.Get(r.Context(), path)
	if err != nil {
		writeEntryError(w, err)
		return
	}
	if wantsJSON(r) {
		writeRevealJSON(w, e)
		return
	}
	renderEntry(w, r, a, e, true, "")
}

// wantsJSON reports whether the caller asked for a JSON reveal response
// (the entries table's inline "copy password" button) instead of the
// full HTML page. Same App.Get gate either way — only the response
// format branches.
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// writeRevealJSON is the inline-copy response shape: just the password,
// nothing else — the caller already has every other field rendered in
// the table, it only needs the one value it can't otherwise get without
// this reveal.
func writeRevealJSON(w http.ResponseWriter, e *store.Entry) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Password string `json:"password"`
	}{Password: e.Password})
}

// renderMaskedEntry re-fetches metadata via App.Inspect (never a `get`
// row) and renders the masked view, optionally with an error message
// (e.g. a failed Touch-ID challenge from a reveal attempt).
func renderMaskedEntry(w http.ResponseWriter, r *http.Request, a *app.App, path, errMsg string) {
	e, err := a.Inspect(r.Context(), path)
	if err != nil {
		writeEntryError(w, err)
		return
	}
	renderEntry(w, r, a, e, false, errMsg)
}

// renderEntry looks up "last read" for e.Path via audit.Log.LastAccess —
// a best-effort UI enhancement, not a security control, so a query error
// degrades to "never shown" rather than failing the whole page.
// historyLimit caps how many git-log revisions the entry detail page
// requests — this is a UI convenience list, not an audit trail; the full
// history remains available via `git -C <store> log` for anyone who
// needs it.
const historyLimit = 10

func renderEntry(w http.ResponseWriter, r *http.Request, a *app.App, e *store.Entry, revealed bool, errMsg string) {
	var lastRead time.Time
	if a.Audit != nil {
		lastRead, _ = a.Audit.LastAccess(r.Context(), e.Path)
	}
	// Best-effort: a history error (denied/git unavailable/no repo)
	// degrades to an empty list, never a failed page — this mirrors how
	// history.Log itself fails soft for anything below policy denial.
	revisions, _ := a.History(r.Context(), e.Path, historyLimit)
	data := map[string]any{
		"Page":     "entries",
		"Entry":    e,
		"Revealed": revealed,
		"Error":    errMsg,
		"LastRead": lastRead,
		"History":  revisions,
	}
	if err := templates.ExecuteTemplate(w, "entry.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeEntryError(w http.ResponseWriter, err error) {
	var denied *app.ErrDenied
	if errors.As(err, &denied) {
		http.Error(w, denied.Error(), http.StatusForbidden)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// relativeTime renders "wann zuletzt" recency-first rather than forcing
// a mental subtraction from an absolute date every time: "nie" for the
// zero Time (never happened), "gerade eben"/"vor N Minuten" within the
// last hour, "heute, HH:MM"/"gestern, HH:MM" for the last two calendar
// days, and the full absolute date only once it's older than that. Used
// for both "zuletzt gelesen" (entries/entry pages) and "zuletzt gesynct"
// (index page) — same kind of timestamp, same recency-first framing.
func relativeTime(t time.Time) string {
	if t.IsZero() {
		return "nie"
	}
	now := time.Now()
	d := now.Sub(t)
	switch {
	case d < 45*time.Second:
		return "gerade eben"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins < 1 {
			mins = 1
		}
		if mins == 1 {
			return "vor 1 Minute"
		}
		return fmt.Sprintf("vor %d Minuten", mins)
	}
	local, nowLocal := t.Local(), now.Local()
	if isSameDay(local, nowLocal) {
		return "heute, " + local.Format("15:04")
	}
	if isSameDay(local, nowLocal.AddDate(0, 0, -1)) {
		return "gestern, " + local.Format("15:04")
	}
	return local.Format("2006-01-02 15:04:05")
}

func isSameDay(a, b time.Time) bool {
	ya, ma, da := a.Date()
	yb, mb, db := b.Date()
	return ya == yb && ma == mb && da == db
}

func actorBadge(kind string) template.HTML {
	color := "#8b90a0"
	switch kind {
	case audit.ActorAI:
		color = "#a78bfa"
	case audit.ActorHuman:
		color = "#4ade80"
	case audit.ActorScript:
		color = "#f59e42"
	}
	return template.HTML(fmt.Sprintf(
		`<span class="badge" style="background:%s22;color:%s">%s</span>`, color, color, template.HTMLEscapeString(kind)))
}

func resultBadge(result string) template.HTML {
	color := "#8b90a0"
	switch result {
	case audit.ResultOK:
		color = "#4ade80"
	case audit.ResultDenied:
		color = "#f87171"
	case audit.ResultError:
		color = "#f59e42"
	}
	return template.HTML(fmt.Sprintf(
		`<span class="badge" style="background:%s22;color:%s">%s</span>`, color, color, template.HTMLEscapeString(result)))
}
