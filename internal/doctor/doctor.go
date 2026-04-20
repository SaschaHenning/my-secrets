// Package doctor runs a series of read-only health checks against the
// my-secrets installation and returns a structured report. It is the engine
// behind the `mys doctor` CLI subcommand.
//
// Each check is side-effect-free and must run in well under a second on a
// warm system. Individual checks may hit the filesystem, query gopass via
// the subprocess CLI, or open a temporary audit DB — but they must never
// touch the real audit DB (writes happen only at the aggregate level in the
// caller) and never surface any secret material.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
)

// Status is the verdict of a single check.
type Status string

const (
	// StatusPass means: criterion fully met.
	StatusPass Status = "pass"
	// StatusWarn means: not a failure, but the user should know.
	StatusWarn Status = "warn"
	// StatusFail means: hard failure — exit code non-zero.
	StatusFail Status = "fail"
	// StatusSkip means: check could not run (e.g. feature disabled). Does
	// not contribute to the exit code.
	StatusSkip Status = "skip"
)

// Check is the result of running one named check.
type Check struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
	Remedy  string `json:"remedy,omitempty"`
}

// Summary aggregates the status counts.
type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// Report is the top-level container returned to callers and serialised in
// JSON output.
type Report struct {
	Checks    []Check   `json:"checks"`
	Summary   Summary   `json:"summary"`
	Timestamp time.Time `json:"timestamp"`
}

// CheckFunc is the shared signature of every individual check.
type CheckFunc func(ctx context.Context) Check

// registeredCheck pairs an ID with its function. The slice order drives
// report output order.
type registeredCheck struct {
	ID string
	Fn CheckFunc
}

// Registry returns the ordered set of checks that Run will execute. Tests
// may use it to exercise subsets; the public CLI `mys doctor --only` flag
// filters against these IDs.
func Registry() []registeredCheck {
	return []registeredCheck{
		{ID: "store", Fn: CheckStore},
		{ID: "gpg-key", Fn: CheckGPGKey},
		{ID: "recipients", Fn: CheckRecipients},
		{ID: "git-remote", Fn: CheckGitRemote},
		{ID: "sync-age", Fn: CheckSyncAge},
		{ID: "audit-writable", Fn: CheckAuditWritable},
		{ID: "audit-gaps", Fn: CheckAuditGaps},
		{ID: "signed-chain", Fn: CheckSignedChain},
		{ID: "paperkey-backup", Fn: CheckPaperkeyBackup},
		{ID: "policy", Fn: CheckPolicy},
		{ID: "rotation-overdue", Fn: CheckRotationOverdue},
	}
}

// Run executes every registered check (or the subset named in only) and
// returns the aggregate report. The report is always fully populated, even
// if a check returns an error — the error becomes part of that check's
// Message.
func Run(ctx context.Context, only []string) Report {
	r := Report{Timestamp: time.Now().UTC()}
	onlySet := map[string]struct{}{}
	for _, id := range only {
		onlySet[strings.TrimSpace(id)] = struct{}{}
	}
	for _, rc := range Registry() {
		if len(onlySet) > 0 {
			if _, want := onlySet[rc.ID]; !want {
				continue
			}
		}
		c := rc.Fn(ctx)
		if c.ID == "" {
			c.ID = rc.ID
		}
		r.Checks = append(r.Checks, c)
		switch c.Status {
		case StatusPass:
			r.Summary.Pass++
		case StatusWarn:
			r.Summary.Warn++
		case StatusFail:
			r.Summary.Fail++
		case StatusSkip:
			r.Summary.Skip++
		}
	}
	return r
}

// ----------------------------------------------------------------------------
// Check implementations
// ----------------------------------------------------------------------------

// passwordStoreDir returns the active gopass store directory.
//
// Priority order matches gopass itself:
//  1. $PASSWORD_STORE_DIR if set.
//  2. The path reported by `gopass config mounts.path` — this picks up
//     any non-default store the user (or a bootstrap script) has
//     configured.
//  3. ~/.password-store as the conventional fallback.
func passwordStoreDir() (string, error) {
	if p := strings.TrimSpace(os.Getenv("PASSWORD_STORE_DIR")); p != "" {
		return p, nil
	}
	if gopass := gopassBinary(); gopass != "" {
		if out, err := exec.Command(gopass, "config", "mounts.path").Output(); err == nil {
			if path := filterGopassOutput(string(out)); path != "" {
				return path, nil
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".password-store"), nil
}

// filterGopassOutput returns the last non-empty line of a gopass command's
// stdout that is NOT a „⚠ Running '...' in <path>..." prefix. Recent
// gopass versions print such a banner before the actual command output,
// which every parser that used to treat the whole stdout as data now has
// to strip.
func filterGopassOutput(s string) string {
	var last string
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		// Skip the banner — works with emoji warnings as well as plain.
		if strings.Contains(l, "Running '") && strings.Contains(l, "' in ") {
			continue
		}
		last = l
	}
	return last
}

// CheckStore — check #1: gopass store directory exists.
func CheckStore(_ context.Context) Check {
	c := Check{ID: "store", Label: "gopass store exists"}
	p, err := passwordStoreDir()
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("cannot resolve store dir: %v", err)
		c.Remedy = "set PASSWORD_STORE_DIR or ensure $HOME is readable"
		return c
	}
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("store directory missing: %s", p)
		c.Remedy = "run `gopass setup` to initialise the store"
		return c
	}
	c.Status = StatusPass
	c.Message = fmt.Sprintf("found at %s", p)
	return c
}

// CheckGPGKey — check #2: at least one GPG secret key is available.
func CheckGPGKey(ctx context.Context) Check {
	c := Check{ID: "gpg-key", Label: "GPG secret key available"}
	gpg := gpgBinary()
	if gpg == "" {
		c.Status = StatusFail
		c.Message = "gpg binary not found on PATH"
		c.Remedy = "install GnuPG (`brew install gnupg`)"
		return c
	}
	out, err := exec.CommandContext(ctx, gpg, "--list-secret-keys", "--with-colons").Output()
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("gpg --list-secret-keys failed: %v", err)
		c.Remedy = "run `gpg --list-secret-keys` to inspect your keyring"
		return c
	}
	count, firstFpr := parseSecretKeys(string(out))
	if count == 0 {
		c.Status = StatusFail
		c.Message = "no secret key found"
		c.Remedy = "generate one with `gpg --full-generate-key`"
		return c
	}
	c.Status = StatusPass
	if firstFpr != "" {
		c.Message = fmt.Sprintf("%d secret key(s) available (first fpr: %s)", count, shortFpr(firstFpr))
	} else {
		c.Message = fmt.Sprintf("%d secret key(s) available", count)
	}
	return c
}

// parseSecretKeys counts `sec` records in gpg --with-colons output and
// returns the fingerprint of the first one if present.
func parseSecretKeys(colons string) (int, string) {
	var count int
	var firstFpr string
	lines := strings.Split(colons, "\n")
	inSec := false
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "sec":
			count++
			inSec = true
		case "fpr":
			if inSec && firstFpr == "" && len(fields) >= 10 {
				firstFpr = fields[9]
				inSec = false
			}
		}
	}
	return count, firstFpr
}

func shortFpr(f string) string {
	if len(f) <= 8 {
		return f
	}
	return f[len(f)-8:]
}

// CheckRecipients — check #3: gopass recipients count.
func CheckRecipients(ctx context.Context) Check {
	c := Check{ID: "recipients", Label: "gopass recipients"}
	gopass := gopassBinary()
	if gopass == "" {
		c.Status = StatusFail
		c.Message = "gopass binary not found on PATH"
		c.Remedy = "install gopass (`brew install gopass`)"
		return c
	}
	out, err := exec.CommandContext(ctx, gopass, "recipients").Output()
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("gopass recipients failed: %v", err)
		c.Remedy = "run `gopass recipients` manually to diagnose"
		return c
	}
	n := countRecipients(string(out))
	switch {
	case n >= 2:
		c.Status = StatusPass
		c.Message = fmt.Sprintf("%d recipients configured", n)
	case n == 1:
		c.Status = StatusWarn
		c.Message = "only 1 recipient — no backup device"
		c.Remedy = "run: mys recipient add <key>"
	default:
		c.Status = StatusFail
		c.Message = "no recipients configured"
		c.Remedy = "run: gopass recipients add <key>"
	}
	return c
}

// countRecipients counts recipient lines from `gopass recipients` output.
// The output format is a tree with a header line followed by entries like
// „└── 0xABCDEF … <name>". We count any line that looks like a hex key id.
func countRecipients(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Accept lines that contain a 0x-prefixed hex id or a 16-40 char hex
		// fingerprint. We stay generous because gopass output varies.
		if strings.Contains(line, "0x") {
			n++
			continue
		}
		// Fallback: at least 16 hex chars in the line.
		hex := 0
		for _, r := range line {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				hex++
			}
		}
		if hex >= 16 {
			n++
		}
	}
	return n
}

// CheckGitRemote — check #4: gopass store has a git remote configured.
func CheckGitRemote(ctx context.Context) Check {
	c := Check{ID: "git-remote", Label: "gopass git remote"}
	gopass := gopassBinary()
	if gopass == "" {
		c.Status = StatusWarn
		c.Message = "gopass binary not found on PATH"
		c.Remedy = "install gopass (`brew install gopass`)"
		return c
	}
	out, err := exec.CommandContext(ctx, gopass, "git", "remote", "-v").Output()
	if err != nil {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("gopass git remote failed: %v", err)
		c.Remedy = "configure a remote with `gopass git remote add origin <url>`"
		return c
	}
	// Strip the „Running '...'"-banner gopass prints before the actual
	// git output.
	var lines []string
	for _, l := range trimmedLines(string(out)) {
		if strings.Contains(l, "Running '") && strings.Contains(l, "' in ") {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) == 0 {
		c.Status = StatusWarn
		c.Message = "no git remote configured"
		c.Remedy = "configure a remote with `gopass git remote add origin <url>`"
		return c
	}
	// Take the first token after the remote name (fetch URL) as summary.
	first := lines[0]
	fields := strings.Fields(first)
	url := first
	if len(fields) >= 2 {
		url = fields[1]
	}
	c.Status = StatusPass
	c.Message = fmt.Sprintf("remote: %s", url)
	return c
}

// CheckSyncAge — check #5: how long ago did we last sync from the remote?
func CheckSyncAge(ctx context.Context) Check {
	c := Check{ID: "sync-age", Label: "last sync age"}
	gopass := gopassBinary()
	if gopass == "" {
		c.Status = StatusWarn
		c.Message = "gopass binary not found on PATH"
		c.Remedy = "install gopass (`brew install gopass`)"
		return c
	}
	// Prefer FETCH_HEAD (the last fetch from the remote); fall back to HEAD
	// when the store has never fetched.
	ref := "FETCH_HEAD"
	out, err := exec.CommandContext(ctx, gopass, "git", "log", "-1", "--format=%ct", ref).Output()
	tsStr := filterGopassOutput(string(out))
	if err != nil || tsStr == "" {
		ref = "HEAD"
		out, err = exec.CommandContext(ctx, gopass, "git", "log", "-1", "--format=%ct", ref).Output()
		if err != nil {
			c.Status = StatusWarn
			c.Message = fmt.Sprintf("could not read git log: %v", err)
			c.Remedy = "initialise git in the store: `gopass git init`"
			return c
		}
		tsStr = filterGopassOutput(string(out))
	}
	if tsStr == "" {
		c.Status = StatusWarn
		c.Message = "no commits in store"
		return c
	}
	var unix int64
	if _, perr := fmt.Sscanf(tsStr, "%d", &unix); perr != nil || unix == 0 {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("unparseable git timestamp: %q", tsStr)
		return c
	}
	age := time.Since(time.Unix(unix, 0))
	days := int(age.Hours() / 24)
	switch {
	case days <= 7:
		c.Status = StatusPass
		c.Message = fmt.Sprintf("%d day(s) ago (ref=%s)", days, ref)
	case days <= 30:
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("%d days ago (ref=%s)", days, ref)
		c.Remedy = "run: mys sync push"
	default:
		c.Status = StatusFail
		c.Message = fmt.Sprintf("%d days ago (ref=%s)", days, ref)
		c.Remedy = "run: mys sync push"
	}
	return c
}

// CheckAuditWritable — check #6: audit DB can be opened and written to.
//
// The probe goes into a *separate* temporary DB so the real audit log is
// untouched. That keeps the check read-only with respect to operational
// state while still exercising the same code path (Open + Write).
func CheckAuditWritable(ctx context.Context) Check {
	c := Check{ID: "audit-writable", Label: "audit DB writable"}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("mys-doctor-probe-%d-%d.sqlite", os.Getpid(), time.Now().UnixNano()))
	defer func() {
		_ = os.Remove(tmp)
		_ = os.Remove(tmp + "-wal")
		_ = os.Remove(tmp + "-shm")
	}()
	// Force the default (unsigned) open path regardless of MYS_AUDIT_SIGN so
	// a misconfigured signing keystore cannot fail this check. Restore the
	// env var afterwards.
	prev, had := os.LookupEnv(audit.EnvSignMode)
	_ = os.Unsetenv(audit.EnvSignMode)
	defer func() {
		if had {
			_ = os.Setenv(audit.EnvSignMode, prev)
		}
	}()
	l, err := audit.Open(tmp)
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("open: %v", err)
		c.Remedy = "check permissions on $HOME/.local/share/my-secrets"
		return c
	}
	defer l.Close()
	seq, err := l.Write(ctx, audit.Entry{
		Action:    "doctor_probe",
		ActorKind: audit.ActorScript,
		Result:    audit.ResultOK,
		Reason:    "doctor write probe",
	})
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("write: %v", err)
		c.Remedy = "check disk space and permissions on the audit DB dir"
		return c
	}
	if seq <= 0 {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("unexpected seq: %d", seq)
		return c
	}
	c.Status = StatusPass
	c.Message = "temp DB open+write ok"
	return c
}

// CheckAuditGaps — check #7: the real audit DB has a contiguous seq range.
func CheckAuditGaps(ctx context.Context) Check {
	c := Check{ID: "audit-gaps", Label: "audit log gaps"}
	// Open the real DB read-only by using its default path. Open() creates
	// the DB if missing but never writes rows on its own, so this is safe.
	l, err := audit.Open("")
	if err != nil {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("cannot open audit DB: %v", err)
		c.Remedy = "run `mys init` to initialise"
		return c
	}
	defer l.Close()
	ok, missing, verr := l.Verify(ctx)
	if verr != nil {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("verify failed: %v", verr)
		return c
	}
	if ok {
		total, _ := l.Count(ctx)
		c.Status = StatusPass
		c.Message = fmt.Sprintf("no gaps (%d rows)", total)
		return c
	}
	c.Status = StatusWarn
	c.Message = fmt.Sprintf("gaps at seqs: %v", missing)
	c.Remedy = "investigate — rows may have been removed out-of-band"
	return c
}

// CheckSignedChain — check #8: if signed-chain mode is enabled, all signed
// rows verify. If the mode is off, the check is skipped.
func CheckSignedChain(ctx context.Context) Check {
	c := Check{ID: "signed-chain", Label: "signed audit chain"}
	v := strings.ToLower(strings.TrimSpace(os.Getenv(audit.EnvSignMode)))
	if !(v == "1" || v == "true" || v == "yes") {
		c.Status = StatusSkip
		c.Message = "signed mode not enabled (MYS_AUDIT_SIGN unset)"
		return c
	}
	l, err := audit.Open("")
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("open: %v", err)
		c.Remedy = "unset MYS_AUDIT_SIGN or repair keystore"
		return c
	}
	defer l.Close()
	ok, bad, checked, verr := l.VerifySignatures(ctx)
	if verr != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("verify signatures: %v", verr)
		return c
	}
	if ok {
		c.Status = StatusPass
		c.Message = fmt.Sprintf("%d signed row(s) verified", checked)
		return c
	}
	c.Status = StatusFail
	c.Message = fmt.Sprintf("%d signed row(s) tampered: %v", len(bad), bad)
	c.Remedy = "restore the audit DB from backup"
	return c
}

// backupEntry is the minimal shape needed for check #9. The real format
// (introduced by issue #18) may have more fields; we only care that at
// least one entry exists.
type backupEntry struct {
	Created time.Time `json:"created"`
}

// backupsJSONPath returns the canonical path for the paperkey backup marker
// file: ~/.local/share/my-secrets/backups.json.
func backupsJSONPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "my-secrets", "backups.json"), nil
}

// CheckPaperkeyBackup — check #9: the paperkey backup marker file has at
// least one recorded entry.
func CheckPaperkeyBackup(_ context.Context) Check {
	c := Check{ID: "paperkey-backup", Label: "paperkey backup recorded"}
	p, err := backupsJSONPath()
	if err != nil {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("cannot resolve path: %v", err)
		return c
	}
	data, err := os.ReadFile(p)
	if err != nil {
		c.Status = StatusWarn
		c.Message = "no paperkey backup recorded"
		c.Remedy = "create one with `mys paperkey backup`"
		return c
	}
	// Accept either a JSON array or an object with an „entries" array — we
	// only need to know whether at least one entry is present.
	trim := strings.TrimSpace(string(data))
	if trim == "" || trim == "[]" || trim == "{}" {
		c.Status = StatusWarn
		c.Message = "backups.json is empty"
		c.Remedy = "create one with `mys paperkey backup`"
		return c
	}
	var arr []backupEntry
	if json.Unmarshal(data, &arr) == nil {
		if len(arr) == 0 {
			c.Status = StatusWarn
			c.Message = "backups.json has 0 entries"
			c.Remedy = "create one with `mys paperkey backup`"
			return c
		}
		c.Status = StatusPass
		c.Message = fmt.Sprintf("%d backup(s) recorded", len(arr))
		return c
	}
	var wrap struct {
		Entries []backupEntry `json:"entries"`
	}
	if json.Unmarshal(data, &wrap) == nil && len(wrap.Entries) > 0 {
		c.Status = StatusPass
		c.Message = fmt.Sprintf("%d backup(s) recorded", len(wrap.Entries))
		return c
	}
	c.Status = StatusWarn
	c.Message = "backups.json present but no entries parsed"
	c.Remedy = "check the file format or re-create with `mys paperkey backup`"
	return c
}

// CheckPolicy — check #10: scope-policy.yaml exists and parses cleanly.
func CheckPolicy(_ context.Context) Check {
	c := Check{ID: "policy", Label: "scope policy file"}
	p, err := policy.DefaultPath()
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("cannot resolve policy path: %v", err)
		return c
	}
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Status = StatusWarn
			c.Message = fmt.Sprintf("missing at %s (using baked-in defaults)", p)
			c.Remedy = "run `mys init` to write the default policy"
			return c
		}
		c.Status = StatusFail
		c.Message = fmt.Sprintf("stat policy: %v", err)
		return c
	}
	pol, err := policy.Load(p)
	if err != nil {
		c.Status = StatusFail
		c.Message = fmt.Sprintf("parse error: %v", err)
		c.Remedy = "fix the YAML or restore from a known-good copy"
		return c
	}
	// Successful parse is enough — empty policy files still load but the
	// actors map will be empty; warn in that case to catch obvious mistakes.
	if pol == nil || len(pol.Actors) == 0 {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("%s has no actors defined", p)
		c.Remedy = "restore the default with `mys init`"
		return c
	}
	c.Status = StatusPass
	c.Message = fmt.Sprintf("%d actor(s) defined at %s", len(pol.Actors), p)
	return c
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

// gpgBinary resolves gpg / gpg2 on PATH.
func gpgBinary() string {
	for _, name := range []string{"gpg", "gpg2"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// gopassBinary resolves gopass on PATH.
func gopassBinary() string {
	if p, err := exec.LookPath("gopass"); err == nil {
		return p
	}
	return ""
}

func trimmedLines(s string) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
