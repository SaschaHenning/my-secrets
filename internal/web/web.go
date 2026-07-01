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
	cancelCtx, cancel := context.WithCancel(ctx)
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
	mux.Handle("/", authGate(store, handleIndex(a)))
	mux.Handle("/audit", authGate(store, handleAudit(a)))
	mux.Handle("/entries", authGate(store, handleEntries(a, newEntriesCache())))
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
// (valid) next= target — the search-first entries browser, per the PWA's
// start_url, not the stats overview.
const defaultLandingPath = "/entries"

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
      Bestätige per Touch&nbsp;ID, um die Weboberfläche zu öffnen.
      Die Sitzung läuft nach 30&nbsp;Minuten Inaktivität automatisch ab.
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
<footer>local read-only UI · bound to 127.0.0.1 · no secret values are rendered here</footer>
<script>
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/static/sw.js');
</script>
</body>
</html>`, nextField, errBlock)
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

		data := map[string]any{
			"Total":       total,
			"AI":          aiCount,
			"Human":       humanCount,
			"Denied":      deniedCount,
			"Recent":      last,
			"Page":        "index",
			"SyncRemotes": syncRemotes,
		}
		if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
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

// handleEntries serves the secrets browser at /entries. Always decrypts
// and shows every policy-visible entry, grouped by org, in one page —
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
// entriesCacheTTL bounds how stale the cached decrypt can be. Short
// enough that a write from another `mys` CLI invocation (the only way
// the store changes while `mys web` is running — this UI has no write
// endpoints) or a `mys sync pull` shows up quickly on the next load;
// long enough that clicking around the entries page during normal use
// (the "back to org" link, revisiting after glancing at one entry's
// detail page) doesn't pay the full-store decrypt cost every time.
const entriesCacheTTL = 30 * time.Second

// entriesCache holds the last App.BrowseDetailed(ctx, "") result so
// repeated /entries loads within entriesCacheTTL don't repeat the full
// decrypt — found necessary in practice: on a real store, decrypting
// every entry took long enough (tens of seconds) that "click a link,
// wait, nothing happens" was the actual user experience even after
// extendWriteDeadline stopped the request from being cut off outright.
// A cache hit skips App.BrowseDetailed entirely, so it also skips that
// call's ActionListDetail audit row — no decrypt happened on a hit, so
// logging one would misrepresent what actually occurred.
//
// Only successful decrypts are ever cached: an error is returned as-is
// and neither stored nor timestamped, so a transient failure (e.g. a
// denied/unreachable store during a refresh) is retried on the very
// next request instead of wedging /entries into repeat errors — served
// alongside stale-but-otherwise-good cached entries — for the rest of
// the TTL.
type entriesCache struct {
	mu      sync.Mutex
	at      time.Time
	entries []*store.Entry
}

func newEntriesCache() *entriesCache {
	return &entriesCache{}
}

func (c *entriesCache) get(ctx context.Context, a *app.App) ([]*store.Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries != nil && time.Since(c.at) < entriesCacheTTL {
		return c.entries, nil
	}
	entries, err := a.BrowseDetailed(ctx, "")
	if err != nil {
		return nil, err
	}
	c.entries, c.at = entries, time.Now()
	return entries, nil
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

		data := map[string]any{
			"Page":      "entries",
			"Query":     initial,
			"Groups":    groupByOrg(entries),
			"LastReads": lastReads,
		}
		if err := templates.ExecuteTemplate(w, "entries.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// handleEntryDetail serves the entry-detail page at /entries/{path...}.
// GET renders the masked view (App.Inspect — does not count as a read).
// POST is the reveal action: for any path the caller is actually allowed
// to read, it requires a FRESH Touch-ID challenge on every single
// submission, deliberately not relying on the session cookie that
// already gates access to this page. The session cookie answers "is this
// browser allowed to browse metadata"; Touch ID answers "does a human
// want to see this specific value right now" — collapsing the two would
// mean an open browser tab, or anyone who can reach it within the
// 30-minute idle window, could reveal every secret without further
// confirmation. On success it calls the unmodified App.Get, so a web
// reveal produces the exact same `get` audit row shape as `mys get
// --reveal` on the CLI.
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

// handleReveal checks accessibility via App.Inspect FIRST — before ever
// running the Touch-ID challenge. This matters for two reasons: a caller
// who is policy-denied from a path gets a correctly audited denial
// (Inspect writes it) and never sees the biometric prompt at all for
// something they could never read anyway; and it means a bare POST to a
// denied path (no prior page load) can't be used to spam Touch-ID
// prompts. Only once Inspect confirms the path is both real and allowed
// does the fresh Touch-ID challenge run, followed by the unmodified
// App.Get, so a web reveal produces the exact same `get` audit row shape
// as `mys get --reveal` on the CLI.
func handleReveal(w http.ResponseWriter, r *http.Request, a *app.App, path string) {
	jsonMode := wantsJSON(r)
	masked, err := a.Inspect(r.Context(), path)
	if err != nil {
		writeEntryError(w, err)
		return
	}
	extendWriteDeadline(w, touchIDWriteBudget)
	if err := requireTouchID(r.Context()); err != nil {
		if jsonMode {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		renderEntry(w, r, a, masked, false, "Touch ID erforderlich: "+err.Error())
		return
	}
	e, err := a.Get(r.Context(), path)
	if err != nil {
		writeEntryError(w, err)
		return
	}
	if jsonMode {
		writeRevealJSON(w, e)
		return
	}
	renderEntry(w, r, a, e, true, "")
}

// wantsJSON reports whether the caller asked for a JSON reveal response
// (the entries table's inline "copy password" button) instead of the
// full HTML page. Same handler, same Inspect→TouchID→Get gate either
// way — only the response format branches, at the very end.
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
