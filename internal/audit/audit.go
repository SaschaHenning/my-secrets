// Package audit writes an append-only audit log of every access to a secret.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Action types recorded in the log.
const (
	ActionInit   = "init"
	ActionGet    = "get"
	ActionList   = "list"
	ActionSearch = "search"
	ActionAdd    = "add"
	ActionRotate = "rotate"
	ActionRemove = "remove"
	ActionExport = "export"
	ActionWebOpen = "web_open"
	ActionMCPStart = "mcp_start"
)

// Results recorded against each action.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Actor kinds recorded with each entry.
const (
	ActorHuman  = "human"
	ActorAI     = "ai"
	ActorScript = "script"
)

// Entry captures a single audit record.
type Entry struct {
	Seq         int64           `json:"seq"`
	TS          time.Time       `json:"ts"`
	Action      string          `json:"action"`
	SecretPath  string          `json:"secret_path,omitempty"`
	Org         string          `json:"org,omitempty"`
	ActorKind   string          `json:"actor_kind"`
	ActorDetail json.RawMessage `json:"actor_detail,omitempty"`
	Result      string          `json:"result"`
	Reason      string          `json:"reason,omitempty"`
}

// Log wraps the underlying SQLite DB used for audit writes.
type Log struct {
	db *sql.DB
}

// DefaultPath returns the usual audit DB path:
// ~/.local/share/my-secrets/audit.sqlite.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "my-secrets", "audit.sqlite"), nil
}

// Open opens (and creates if missing) the audit DB. An empty path uses
// DefaultPath().
func Open(path string) (*Log, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	// Pragmas: WAL for concurrent readers (web UI) + strict foreign keys.
	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set wal: %w", err)
	}
	l := &Log{db: db}
	if err := l.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

// Write appends a single audit entry. Returns the assigned sequence number.
func (l *Log) Write(ctx context.Context, e Entry) (int64, error) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.ActorKind == "" {
		e.ActorKind = ActorScript
	}
	if e.Result == "" {
		e.Result = ResultOK
	}
	var detail []byte
	if len(e.ActorDetail) > 0 {
		detail = []byte(e.ActorDetail)
	}
	res, err := l.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, action, secret_path, org, actor_kind, actor_detail, result, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.TS.UTC().Format(time.RFC3339Nano), e.Action, e.SecretPath, e.Org,
		e.ActorKind, string(detail), e.Result, e.Reason)
	if err != nil {
		return 0, fmt.Errorf("audit write: %w", err)
	}
	return res.LastInsertId()
}

// Filter narrows a Tail / Since query.
type Filter struct {
	Actor  string
	Action string
	Org    string
	Path   string
	Since  time.Time
	Limit  int
}

// Tail returns the most recent entries, honouring Filter.
func (l *Log) Tail(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	q := `SELECT seq, ts, action, secret_path, org, actor_kind, actor_detail, result, reason
	      FROM audit_log WHERE 1=1`
	args := []any{}
	if f.Actor != "" {
		q += ` AND actor_kind = ?`
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.Org != "" {
		q += ` AND org = ?`
		args = append(args, f.Org)
	}
	if f.Path != "" {
		q += ` AND secret_path LIKE ?`
		args = append(args, "%"+f.Path+"%")
	}
	if !f.Since.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	q += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit tail: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows)
}

// Verify walks the log and reports any gaps in the sequence counter (i.e.
// rows deleted via an out-of-band tool).
func (l *Log) Verify(ctx context.Context) (ok bool, missing []int64, err error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return false, nil, fmt.Errorf("audit verify: %w", err)
	}
	defer rows.Close()
	var prev int64
	first := true
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			return false, missing, err
		}
		if first {
			prev = s
			first = false
			continue
		}
		for prev+1 < s {
			prev++
			missing = append(missing, prev)
		}
		prev = s
	}
	return len(missing) == 0, missing, rows.Err()
}

// Count returns the total number of rows in the audit log.
func (l *Log) Count(ctx context.Context) (int64, error) {
	var n int64
	err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

func scanEntries(rows *sql.Rows) ([]Entry, error) {
	var out []Entry
	for rows.Next() {
		var e Entry
		var tsStr, detail string
		if err := rows.Scan(&e.Seq, &tsStr, &e.Action, &e.SecretPath, &e.Org,
			&e.ActorKind, &detail, &e.Result, &e.Reason); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			e.TS = t
		}
		if detail != "" {
			e.ActorDetail = json.RawMessage(detail)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
	seq           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts            TEXT    NOT NULL,
	action        TEXT    NOT NULL,
	secret_path   TEXT    NOT NULL DEFAULT '',
	org           TEXT    NOT NULL DEFAULT '',
	actor_kind    TEXT    NOT NULL,
	actor_detail  TEXT    NOT NULL DEFAULT '',
	result        TEXT    NOT NULL,
	reason        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_kind);
CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_log(secret_path);

-- Append-only enforcement: triggers prevent UPDATE/DELETE on audit rows.
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
	SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
	SELECT RAISE(ABORT, 'audit_log is append-only');
END;
`

func (l *Log) migrate() error {
	_, err := l.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	return nil
}
