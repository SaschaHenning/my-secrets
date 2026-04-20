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
	"strconv"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
)

//go:embed templates/*.html static/*
var assets embed.FS

var templates *template.Template

func init() {
	funcs := template.FuncMap{
		"actorBadge":  actorBadge,
		"resultBadge": resultBadge,
		"shortTime": func(t time.Time) string {
			return t.Local().Format("2006-01-02 15:04:05")
		},
	}
	templates = template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html"))
}

// Serve starts the HTTP server on 127.0.0.1:port and blocks until the
// context is cancelled. The audit-open app passed in must have its Audit
// field set.
func Serve(ctx context.Context, a *app.App, port int, stdout io.Writer) error {
	a.AuditWebOpen(ctx, fmt.Sprintf("127.0.0.1:%d", port))

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(a))
	mux.HandleFunc("/audit", handleAudit(a))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/static/", http.FileServerFS(assets))

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      localhostOnly(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Fprintf(stdout, "my-secrets web UI → http://127.0.0.1:%d\n", port)
	fmt.Fprintln(stdout, "press Ctrl-C to stop")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdown)
		// Reap the server goroutine.
		<-errCh
		return err
	}
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
