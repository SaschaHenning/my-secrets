// Package audit writes an append-only audit log of every access to a secret.
package audit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Action types recorded in the log.
const (
	ActionInit            = "init"
	ActionGet             = "get"
	ActionList            = "list"
	ActionSearch          = "search"
	ActionAdd             = "add"
	ActionRotate          = "rotate"
	ActionRemove          = "remove"
	ActionExport          = "export"
	ActionKeyBackup       = "key_backup"
	ActionWebOpen         = "web_open"
	ActionMCPStart        = "mcp_start"
	ActionDoctor          = "doctor"
	ActionRecipientAdd    = "recipient_add"
	ActionRecipientList   = "recipient_list"
	ActionRecipientRemove = "recipient_remove"
	ActionSyncSetup       = "sync_setup"
	ActionSyncPush        = "sync_push"
	ActionSyncPull        = "sync_pull"
	ActionTOTPGenerate    = "totp_generate"
	ActionSkillInstall    = "skill_install"
	// ActionListDetail is written by App.BrowseDetailed — a metadata
	// listing that decrypts every visible entry but is NOT a read of any
	// single secret. Kept distinct from ActionGet so that "last read"
	// queries (LastAccessByPath) stay meaningful: browsing the web UI's
	// entries list must never look like reading every secret in it.
	ActionListDetail = "list_detail"
	// ActionHistory is written by App.History — reading an entry's git
	// commit metadata (hash/timestamp/message), never its decrypted
	// content. Policy-gated like every other path-taking action, so a
	// denied path doesn't leak how many times it was ever changed.
	ActionHistory = "history"
	// ActionBWPush is the per-run summary row of `mys bw-push` — one row
	// per mirror run (server + change counts), on top of the per-secret
	// get rows the app layer writes anyway.
	ActionBWPush = "bw_push"
	// ActionBWImport is the per-run summary row of `mys bw-import` — one
	// row per diff or apply run (server + diff class counts, plus the
	// applied/skipped/failed outcome on --apply), on top of the
	// per-secret get/add rows the app layer writes anyway.
	ActionBWImport = "bw_import"
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
	// Host is the local hostname of the machine that wrote this row.
	// Forward-compat only: a future cross-machine audit view needs it to
	// tell entries apart by origin, but this package does no merging or
	// syncing of logs across machines itself. Deliberately excluded from
	// the signed hash chain (see canonicalBytes in signing.go) so that
	// enabling this column does not invalidate signatures on rows written
	// before it existed.
	Host string `json:"host,omitempty"`
}

// Log wraps the underlying SQLite DB used for audit writes.
type Log struct {
	db       *sql.DB
	signMode bool
	privKey  ed25519.PrivateKey
	keyStore KeyStore
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
// DefaultPath(). Signed-chain mode is auto-enabled if MYS_AUDIT_SIGN=1.
func Open(path string) (*Log, error) {
	return OpenWithKeyStore(path, nil)
}

// OpenWithKeyStore is Open with an injected KeyStore. Used by tests. A
// nil KeyStore means „use the default keychain-backed store when sign
// mode is enabled".
func OpenWithKeyStore(path string, ks KeyStore) (*Log, error) {
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
	// Opt-in: signed hash-chain mode.
	if envSignEnabled() {
		if ks == nil {
			defKS, err := DefaultKeyStore()
			if err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("audit signing: default keystore: %w", err)
			}
			ks = defKS
		}
		priv, err := ks.Load()
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("audit signing: load key: %w",
				fmt.Errorf("%w — refusing to continue without signing keys (unset %s to disable)", err, EnvSignMode))
		}
		// Force public-key materialisation so the verify file is always there.
		if _, perr := ks.Public(); perr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("audit signing: public key: %w", perr)
		}
		l.signMode = true
		l.privKey = priv
		l.keyStore = ks
	}
	return l, nil
}

// SignModeEnabled reports whether the Log is writing signed rows.
func (l *Log) SignModeEnabled() bool { return l != nil && l.signMode }

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
	if e.Host == "" {
		// Best-effort: a hostname lookup failure must never block an
		// audit write, so a blank host is an accepted outcome, not
		// escalated to an error.
		if h, err := os.Hostname(); err == nil {
			e.Host = h
		}
	}
	var detail []byte
	if len(e.ActorDetail) > 0 {
		detail = []byte(e.ActorDetail)
	}

	if !l.signMode {
		res, err := l.db.ExecContext(ctx, `
			INSERT INTO audit_log (ts, action, secret_path, org, actor_kind, actor_detail, result, reason, host)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, e.TS.UTC().Format(time.RFC3339Nano), e.Action, e.SecretPath, e.Org,
			e.ActorKind, string(detail), e.Result, e.Reason, e.Host)
		if err != nil {
			return 0, fmt.Errorf("audit write: %w", err)
		}
		return res.LastInsertId()
	}

	// Signed path: wrap in an IMMEDIATE transaction so the prev_hash read
	// and the INSERT are atomic with respect to concurrent writers.
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("audit begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		// Some sqlite drivers auto-begin; ignore "cannot start a transaction within a transaction".
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// 1. Find predecessor row_hash (nil if table empty or prior rows unsigned).
	var prev []byte
	row := tx.QueryRowContext(ctx, `
		SELECT row_hash FROM audit_log
		WHERE row_hash IS NOT NULL
		ORDER BY seq DESC
		LIMIT 1
	`)
	if err := row.Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("audit fetch prev_hash: %w", err)
	}

	// 2. Insert without chain columns first to obtain the AUTOINCREMENT seq.
	res, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (ts, action, secret_path, org, actor_kind, actor_detail, result, reason, host)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.TS.UTC().Format(time.RFC3339Nano), e.Action, e.SecretPath, e.Org,
		e.ActorKind, string(detail), e.Result, e.Reason, e.Host)
	if err != nil {
		return 0, fmt.Errorf("audit write signed: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	e.Seq = seq

	// 3. Compute chain hash + signature using the assigned seq.
	rowHash := chainHash(e, prev)
	sig := ed25519.Sign(l.privKey, rowHash)

	// 4. Update the row with prev_hash, row_hash, signature. We must allow
	//    this by briefly bypassing the append-only UPDATE trigger. Because
	//    we only populate three previously-NULL columns in the same
	//    transaction as the insert, we guard that by a precondition check.
	//    The trigger stays active at rest.
	if _, err := tx.ExecContext(ctx, `DROP TRIGGER IF EXISTS audit_no_update`); err != nil {
		return 0, fmt.Errorf("audit drop trigger: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE audit_log
		SET prev_hash = ?, row_hash = ?, signature = ?
		WHERE seq = ?
	`, prev, rowHash, sig, seq)
	if err != nil {
		return 0, fmt.Errorf("audit write chain cols: %w", err)
	}
	if _, err := tx.ExecContext(ctx, appendOnlyUpdateTrigger); err != nil {
		return 0, fmt.Errorf("audit restore trigger: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit commit: %w", err)
	}
	committed = true
	return seq, nil
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
	q := `SELECT seq, ts, action, secret_path, org, actor_kind, actor_detail, result, reason, host
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

// VerifySignatures walks the audit log and recomputes the hash-chain and
// Ed25519 signatures for every signed row. Returns ok=true iff every
// signed row matches. badSeqs contains the seq of every failing row
// (signature mismatch or broken chain). Unsigned rows (written before
// sign-mode was enabled) are skipped.
func (l *Log) VerifySignatures(ctx context.Context) (ok bool, badSeqs []int64, checked int, err error) {
	pub, err := l.loadPublicKey()
	if err != nil {
		return false, nil, 0, err
	}
	rows, err := l.db.QueryContext(ctx, `
		SELECT seq, ts, action, secret_path, org, actor_kind, actor_detail, result, reason,
		       prev_hash, row_hash, signature
		FROM audit_log
		ORDER BY seq ASC
	`)
	if err != nil {
		return false, nil, 0, fmt.Errorf("audit verify signatures: %w", err)
	}
	defer rows.Close()

	var prevRowHash []byte
	havePrev := false
	for rows.Next() {
		var e Entry
		var tsStr, detail string
		var prevHash, rowHash, sig []byte
		if err := rows.Scan(&e.Seq, &tsStr, &e.Action, &e.SecretPath, &e.Org,
			&e.ActorKind, &detail, &e.Result, &e.Reason,
			&prevHash, &rowHash, &sig); err != nil {
			return false, badSeqs, checked, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, tsStr); perr == nil {
			e.TS = t
		}
		if detail != "" {
			e.ActorDetail = json.RawMessage(detail)
		}
		// Skip unsigned rows (pre-migration or sign-mode off).
		if rowHash == nil && sig == nil && prevHash == nil {
			continue
		}
		checked++

		// 1. prev_hash linkage.
		if havePrev {
			if !byteEqual(prevHash, prevRowHash) {
				badSeqs = append(badSeqs, e.Seq)
				prevRowHash = rowHash
				havePrev = true
				continue
			}
		} else {
			// First signed row: prev_hash must be NULL or 32 zero bytes.
			if len(prevHash) != 0 && !isAllZero(prevHash) {
				badSeqs = append(badSeqs, e.Seq)
				prevRowHash = rowHash
				havePrev = true
				continue
			}
		}

		// 2. Recompute row_hash from canonical bytes + prev_hash.
		want := chainHash(e, prevHash)
		if !byteEqual(want, rowHash) {
			badSeqs = append(badSeqs, e.Seq)
			prevRowHash = rowHash
			havePrev = true
			continue
		}
		// 3. Verify signature.
		if !ed25519.Verify(pub, rowHash, sig) {
			badSeqs = append(badSeqs, e.Seq)
		}
		prevRowHash = rowHash
		havePrev = true
	}
	if err := rows.Err(); err != nil {
		return false, badSeqs, checked, err
	}
	return len(badSeqs) == 0, badSeqs, checked, nil
}

// loadPublicKey prefers the file-backed pub key (works even after binary
// restart without touching Keychain) and falls back to the live keystore.
func (l *Log) loadPublicKey() (ed25519.PublicKey, error) {
	if l.keyStore != nil {
		return l.keyStore.Public()
	}
	// Fall back to default file path (verify without having written).
	ks, err := DefaultKeyStore()
	if err != nil {
		return nil, err
	}
	return ks.Public()
}

func byteEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Count returns the total number of rows in the audit log.
func (l *Log) Count(ctx context.Context) (int64, error) {
	var n int64
	err := l.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// LastAccess returns the most recent successful ActionGet timestamp for a
// single path, or the zero Time if it was never read (or read only via
// ActionListDetail — see LastAccessByPath's doc). Used by the entry
// detail page, where fetching the bulk map for one path would be
// wasteful; LastAccessByPath remains the right call for a list view.
func (l *Log) LastAccess(ctx context.Context, path string) (time.Time, error) {
	var ts sql.NullString
	err := l.db.QueryRowContext(ctx, `
		SELECT MAX(ts) FROM audit_log
		WHERE action = ? AND result = ? AND secret_path = ?
	`, ActionGet, ResultOK, path).Scan(&ts)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit last access: %w", err)
	}
	if !ts.Valid {
		return time.Time{}, nil
	}
	t, perr := time.Parse(time.RFC3339Nano, ts.String)
	if perr != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// LastAccessByPath returns the most recent successful ActionGet
// timestamp per secret path — the data behind "last read" in the web
// UI. Deliberately filtered to action=get, result=ok: browsing
// (ActionListDetail, written by App.BrowseDetailed/App.Inspect) must
// never count as a read, or opening the entries browser would stamp
// every visible entry as "just read" and the feature would be
// meaningless. ts is stored as RFC3339Nano text, which sorts correctly
// as a string, so MAX(ts) needs no window function.
func (l *Log) LastAccessByPath(ctx context.Context) (map[string]time.Time, error) {
	rows, err := l.db.QueryContext(ctx, `
		SELECT secret_path, MAX(ts) FROM audit_log
		WHERE action = ? AND result = ? AND secret_path != ''
		GROUP BY secret_path
	`, ActionGet, ResultOK)
	if err != nil {
		return nil, fmt.Errorf("audit last access: %w", err)
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var path, tsStr string
		if err := rows.Scan(&path, &tsStr); err != nil {
			return nil, err
		}
		t, perr := time.Parse(time.RFC3339Nano, tsStr)
		if perr != nil {
			continue
		}
		out[path] = t
	}
	return out, rows.Err()
}

func scanEntries(rows *sql.Rows) ([]Entry, error) {
	var out []Entry
	for rows.Next() {
		var e Entry
		var tsStr, detail string
		if err := rows.Scan(&e.Seq, &tsStr, &e.Action, &e.SecretPath, &e.Org,
			&e.ActorKind, &detail, &e.Result, &e.Reason, &e.Host); err != nil {
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
	reason        TEXT    NOT NULL DEFAULT '',
	prev_hash     BLOB,
	row_hash      BLOB,
	signature     BLOB,
	host          TEXT    NOT NULL DEFAULT ''
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

// appendOnlyUpdateTrigger is the plain CREATE TRIGGER used to restore the
// UPDATE guard after a signed-write has briefly dropped it.
const appendOnlyUpdateTrigger = `
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
	SELECT RAISE(ABORT, 'audit_log is append-only');
END;
`

// migrate creates the schema on first run and adds the chain columns to
// pre-existing DBs.
func (l *Log) migrate() error {
	if _, err := l.db.Exec(schema); err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	// Upgrade path: older DBs don't have the chain columns. SQLite does not
	// support ADD COLUMN IF NOT EXISTS, so we try and ignore „duplicate
	// column" errors.
	for _, col := range []string{"prev_hash", "row_hash", "signature"} {
		_, err := l.db.Exec(fmt.Sprintf(`ALTER TABLE audit_log ADD COLUMN %s BLOB`, col))
		if err != nil && !isDuplicateColumnErr(err) {
			return fmt.Errorf("audit migrate %s: %w", col, err)
		}
	}
	if _, err := l.db.Exec(`ALTER TABLE audit_log ADD COLUMN host TEXT NOT NULL DEFAULT ''`); err != nil && !isDuplicateColumnErr(err) {
		return fmt.Errorf("audit migrate host: %w", err)
	}
	return nil
}

func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite surfaces the SQLite error as a string like
	// „duplicate column name: row_hash".
	msg := err.Error()
	return containsFold(msg, "duplicate column")
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	// A tiny case-insensitive Contains to avoid pulling in strings in the
	// import cycle (keeps the migration file self-contained).
	ls, lsub := len(s), len(sub)
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
