// Package web serves a minimal read-only localhost UI for browsing the
// audit log and entry list. The UI never decrypts secret values — it talks
// only to the audit DB and to a path-list helper.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/store"
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

func init() {
	funcs := template.FuncMap{
		"actorBadge":  actorBadge,
		"resultBadge": resultBadge,
		"shortTime": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"mask": store.MaskedPassword,
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
	mux.Handle("/entries", authGate(store, handleEntries(a)))
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
// /login.
func authGate(store *sessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookieName)
		if err != nil || !store.Validate(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- login handler ---------------------------------------------------------

// handleLogin renders the login page on GET and runs the Touch-ID
// challenge on POST. Successful POSTs set the session cookie and
// redirect to /.
func handleLogin(store *sessionStore, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			renderLogin(w, "")
		case http.MethodPost:
			if err := requireTouchID(r.Context()); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				renderLogin(w, err.Error())
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
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// renderLogin writes the tiny inline login page. We do not route this
// through html/template because the page is static aside from an
// optional error message, which we escape manually.
func renderLogin(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errBlock := ""
	if errMsg != "" {
		errBlock = fmt.Sprintf(`<p class="empty" style="color:#f87171">%s</p>`, template.HTMLEscapeString(errMsg))
	}
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<title>my-secrets — Anmelden</title>
<link rel="stylesheet" href="/static/styles.css">
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
      <button type="submit" class="btn-link" style="background:var(--accent);color:white;padding:0.5rem 1rem;border:none;border-radius:4px;cursor:pointer;font-weight:600;">
        Mit Touch ID anmelden
      </button>
    </form>
    %s
  </div>
</section>
</main>
<footer>local read-only UI · bound to 127.0.0.1 · no secret values are rendered here</footer>
</body>
</html>`, errBlock)
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

		data := map[string]any{
			"Total":  total,
			"AI":     aiCount,
			"Human":  humanCount,
			"Denied": deniedCount,
			"Recent": last,
			"Page":   "index",
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

// handleEntries serves the secrets browser at /entries.
//
// Three shapes, in increasing cost:
//   - no "org", no "q": the cheap landing view — org names + per-org
//     counts, derived from a single App.List(ctx, "") call, no decrypts.
//   - "org" set: App.BrowseDetailed(ctx, org) — decrypts that org's
//     entries so metadata can be shown, filtered by "q" if present.
//   - "q" set without "org": cross-org search, App.BrowseDetailed(ctx,
//     ""); explicitly the most expensive shape since it decrypts
//     everything visible to the caller, so the UI labels it distinctly.
func handleEntries(a *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()
		org := strings.TrimSpace(q.Get("org"))
		query := strings.TrimSpace(q.Get("q"))

		if org == "" && query == "" {
			renderOrgList(w, r, a, ctx)
			return
		}

		entries, err := a.BrowseDetailed(ctx, org)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if query != "" {
			entries = filterEntries(entries, query)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

		data := map[string]any{
			"Page":           "entries",
			"SelectedOrg":    org,
			"Query":          query,
			"CrossOrgSearch": org == "" && query != "",
			"Entries":        entries,
		}
		if err := templates.ExecuteTemplate(w, "entries.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// renderOrgList renders the cheap landing view of /entries: org names and
// counts only, no entry decrypts. A single App.List(ctx, "") call backs
// both — calling App.Orgs() here too would add N more App.List(ctx, org)
// calls (one per org, for the counts) and multiply the ActionList audit
// rows a single page load produces.
func renderOrgList(w http.ResponseWriter, r *http.Request, a *app.App, ctx context.Context) {
	paths, err := a.List(ctx, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	counts := make(map[string]int)
	var orgs []string
	for _, p := range paths {
		o := store.OrgOf(p)
		if o == "" {
			continue
		}
		if _, ok := counts[o]; !ok {
			orgs = append(orgs, o)
		}
		counts[o]++
	}
	sort.Strings(orgs)
	data := map[string]any{
		"Page":      "entries",
		"Orgs":      orgs,
		"OrgCounts": counts,
	}
	if err := templates.ExecuteTemplate(w, "entries.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// filterEntries keeps entries whose Path, Username, URL, Domain, Notes,
// Kind, or Tags contain query (case-insensitive). Password and TOTP seed
// material are never matched — this mirrors the store's own search
// semantics (internal/store/fake package doc: "matches ... NEVER
// against password values").
func filterEntries(entries []*store.Entry, query string) []*store.Entry {
	q := strings.ToLower(query)
	out := make([]*store.Entry, 0, len(entries))
	for _, e := range entries {
		if entryMatches(e, q) {
			out = append(out, e)
		}
	}
	return out
}

func entryMatches(e *store.Entry, q string) bool {
	fields := []string{e.Path, e.Username, e.URL, e.Domain, e.Notes, e.Kind}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	for _, t := range e.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// handleEntryDetail serves the masked entry-detail page at
// /entries/{path...}. GET only in this iteration — reveal (POST) is a
// separate, security-sensitive change layered on top later.
func handleEntryDetail(a *app.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.PathValue("path")
		if path == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		e, err := a.Inspect(r.Context(), path)
		if err != nil {
			var denied *app.ErrDenied
			if errors.As(err, &denied) {
				http.Error(w, denied.Error(), http.StatusForbidden)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data := map[string]any{
			"Page":  "entries",
			"Entry": e,
		}
		if err := templates.ExecuteTemplate(w, "entry.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
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
