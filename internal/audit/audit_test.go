package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestLog(t *testing.T) *Log {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.sqlite")
	l, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestWriteRead(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()

	detail, _ := json.Marshal(map[string]any{"kind": "ai", "pid": 1234})
	for i := 0; i < 5; i++ {
		_, err := l.Write(ctx, Entry{
			Action: ActionGet, SecretPath: "jasp/tok", Org: "jasp",
			ActorKind: ActorAI, ActorDetail: detail, Result: ResultOK, Reason: "ok",
		})
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	entries, err := l.Tail(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
	if entries[0].ActorKind != ActorAI {
		t.Errorf("actor_kind mismatch: %q", entries[0].ActorKind)
	}
}

func TestFilters(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "jasp/a", Org: "jasp", ActorKind: ActorAI, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "jasp/b", Org: "jasp", ActorKind: ActorHuman, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "private/x", Org: "private", ActorKind: ActorAI, Result: ResultDenied, Reason: "policy"})

	ai, err := l.Tail(ctx, Filter{Actor: ActorAI, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(ai) != 2 {
		t.Errorf("filter actor=ai: want 2 entries, got %d", len(ai))
	}
	denied := 0
	for _, e := range ai {
		if e.Result == ResultDenied {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("want 1 denied ai entry, got %d", denied)
	}
}

func TestAppendOnly(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	seq, err := l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorHuman, Result: ResultOK})
	if err != nil {
		t.Fatal(err)
	}
	// Try to update — should fail.
	_, err = l.db.ExecContext(ctx, `UPDATE audit_log SET action='tamper' WHERE seq=?`, seq)
	if err == nil {
		t.Fatal("expected UPDATE to fail on append-only table")
	}
	// Try to delete — should fail.
	_, err = l.db.ExecContext(ctx, `DELETE FROM audit_log WHERE seq=?`, seq)
	if err == nil {
		t.Fatal("expected DELETE to fail on append-only table")
	}
}

func TestVerifyContiguous(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorAI, Result: ResultOK})
	}
	ok, miss, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(miss) != 0 {
		t.Errorf("expected no gaps, got missing=%v", miss)
	}
}

func TestCount(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	if n, err := l.Count(ctx); err != nil || n != 0 {
		t.Errorf("Count empty = %d, err=%v", n, err)
	}
	for i := 0; i < 7; i++ {
		_, _ = l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorAI, Result: ResultOK})
	}
	n, err := l.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Errorf("Count = %d, want 7", n)
	}
}

func TestFiltersExtra(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	_, _ = l.Write(ctx, Entry{Action: ActionGet, SecretPath: "jasp/tok", Org: "jasp", ActorKind: ActorAI, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionAdd, SecretPath: "jasp/new", Org: "jasp", ActorKind: ActorHuman, Result: ResultOK})
	_, _ = l.Write(ctx, Entry{Action: ActionSearch, SecretPath: "", Org: "", ActorKind: ActorScript, Result: ResultOK, Reason: "q=abc"})

	// Action filter
	get, _ := l.Tail(ctx, Filter{Action: ActionGet, Limit: 10})
	if len(get) != 1 {
		t.Errorf("action=get: want 1, got %d", len(get))
	}

	// Org filter
	jasp, _ := l.Tail(ctx, Filter{Org: "jasp", Limit: 10})
	if len(jasp) != 2 {
		t.Errorf("org=jasp: want 2, got %d", len(jasp))
	}

	// Path (LIKE) filter
	tok, _ := l.Tail(ctx, Filter{Path: "tok", Limit: 10})
	if len(tok) != 1 || tok[0].SecretPath != "jasp/tok" {
		t.Errorf("path LIKE tok: %+v", tok)
	}

	// Since filter: future date excludes everything.
	future, _ := l.Tail(ctx, Filter{Since: time.Now().Add(24 * time.Hour), Limit: 10})
	if len(future) != 0 {
		t.Errorf("future since: want 0, got %d", len(future))
	}

	// Limit default (<=0 uses 50). Only cheap check: no error and returns rows.
	all, err := l.Tail(ctx, Filter{Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("default limit: want 3 rows, got %d", len(all))
	}
}

func TestWriteDefaults(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	// Write an entry with empty ActorKind / Result — defaults should kick in.
	seq, err := l.Write(ctx, Entry{Action: ActionGet})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := l.Tail(ctx, Filter{Limit: 5})
	if len(rows) == 0 || rows[0].Seq != seq {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if rows[0].ActorKind != ActorScript {
		t.Errorf("actor_kind default = %q, want script", rows[0].ActorKind)
	}
	if rows[0].Result != ResultOK {
		t.Errorf("result default = %q, want ok", rows[0].Result)
	}
	if rows[0].TS.IsZero() {
		t.Error("TS default missing")
	}
}

func TestCloseNil(t *testing.T) {
	var l *Log
	if err := l.Close(); err != nil {
		t.Errorf("nil close: %v", err)
	}
	l2 := &Log{}
	if err := l2.Close(); err != nil {
		t.Errorf("zero close: %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p) || filepath.Base(p) != "audit.sqlite" {
		t.Errorf("unexpected default path: %q", p)
	}
}

func TestOpenDefaultPath(t *testing.T) {
	// Open("") uses DefaultPath. Redirect HOME to keep the real user state
	// untouched.
	t.Setenv("HOME", t.TempDir())
	l, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Count(context.Background()); err != nil {
		t.Errorf("count on default-path log: %v", err)
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	ts := time.Now().UTC().Truncate(time.Millisecond)
	_, _ = l.Write(ctx, Entry{TS: ts, Action: ActionGet, ActorKind: ActorAI, Result: ResultOK})
	e, _ := l.Tail(ctx, Filter{Limit: 1})
	if len(e) != 1 {
		t.Fatalf("want 1 entry")
	}
	if !e[0].TS.Equal(ts) {
		t.Errorf("ts mismatch: got %v, want %v", e[0].TS, ts)
	}
}

func TestHostAutoPopulated(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	wantHost, err := os.Hostname()
	if err != nil {
		t.Skipf("os.Hostname unavailable: %v", err)
	}
	_, _ = l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorHuman, Result: ResultOK})
	rows, _ := l.Tail(ctx, Filter{Limit: 1})
	if len(rows) != 1 {
		t.Fatalf("want 1 row")
	}
	if rows[0].Host != wantHost {
		t.Errorf("host = %q, want %q", rows[0].Host, wantHost)
	}
}

func TestHostExplicitNotOverwritten(t *testing.T) {
	l := newTestLog(t)
	ctx := context.Background()
	_, _ = l.Write(ctx, Entry{Action: ActionGet, ActorKind: ActorHuman, Result: ResultOK, Host: "explicit-host"})
	rows, _ := l.Tail(ctx, Filter{Limit: 1})
	if len(rows) != 1 || rows[0].Host != "explicit-host" {
		t.Fatalf("host not preserved: %+v", rows)
	}
}

// TestMigrateOldSchemaAddsHostColumn simulates a pre-existing DB written
// before the host column existed (schema without it, one row inserted the
// old way) and verifies Open()/migrate() adds the column without error and
// old rows read back with an empty host rather than failing the scan.
func TestMigrateOldSchemaAddsHostColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	const oldSchema = `
	CREATE TABLE audit_log (
		seq           INTEGER PRIMARY KEY AUTOINCREMENT,
		ts            TEXT    NOT NULL,
		action        TEXT    NOT NULL,
		secret_path   TEXT    NOT NULL DEFAULT '',
		org           TEXT    NOT NULL DEFAULT '',
		actor_kind    TEXT    NOT NULL,
		actor_detail  TEXT    NOT NULL DEFAULT '',
		result        TEXT    NOT NULL,
		reason        TEXT    NOT NULL DEFAULT ''
	);`
	if _, err := raw.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO audit_log (ts, action, actor_kind, result) VALUES (?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), ActionGet, ActorHuman, ResultOK); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	l, err := Open(path)
	if err != nil {
		t.Fatalf("open pre-host-column db: %v", err)
	}
	defer l.Close()

	rows, err := l.Tail(context.Background(), Filter{Limit: 5})
	if err != nil {
		t.Fatalf("tail after migration: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 pre-existing row, got %d", len(rows))
	}
	if rows[0].Host != "" {
		t.Errorf("pre-existing row host = %q, want empty", rows[0].Host)
	}

	// New writes on the migrated DB populate host normally.
	_, _ = l.Write(context.Background(), Entry{Action: ActionGet, ActorKind: ActorHuman, Result: ResultOK})
	rows, _ = l.Tail(context.Background(), Filter{Limit: 5})
	if len(rows) != 2 {
		t.Fatalf("want 2 rows after new write, got %d", len(rows))
	}
	if rows[0].Host == "" {
		t.Error("new row after migration should have a populated host")
	}
}
