package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/caller"
	"github.com/SaschaHenning/my-secrets/internal/recipient"
	"github.com/spf13/cobra"
)

// stubRunner lets cmd-level tests pretend gpg and gopass are present without
// actually running them.
type stubRunner struct {
	calls    []string
	handlers map[string]stubResp
}

type stubResp struct {
	out []byte
	err error
}

func (s *stubRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, key)
	if r, ok := s.handlers[key]; ok {
		return r.out, r.err
	}
	for pfx, r := range s.handlers {
		if strings.HasPrefix(key, pfx) {
			return r.out, r.err
		}
	}
	return nil, fmt.Errorf("unexpected call: %s", key)
}

const showKeysFixture = `tru::1:1705320000:1760441808:3:1:5
pub:-:3072:1:ABCDEF0123456789:1705320000:1760441808::-:::scESC:::::::
fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
uid:-::::1705320000::11111111111111111111111111111111::Alice Example \x3calice@example.org\x3e::::::::::0:
`

// newTestAuditHome redirects HOME so the audit Log lives in a temp dir and
// returns the path the Log will be created at.
func newTestAuditHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return filepath.Join(home, ".local", "share", "my-secrets", "audit.sqlite")
}

func openTestAudit(t *testing.T, dbPath string) *audit.Log {
	t.Helper()
	l, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// clearAISignals makes the current process look like a human TTY session for
// caller.Identify. We cannot flip IsTerminal off, but we can strip the
// AI-only env flags that would otherwise pin the caller to KindAI.
func clearAISignals(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION",
		"CURSOR", "CURSOR_SESSION",
	} {
		t.Setenv(k, "")
	}
}

// newTestCmd returns a minimal cobra.Command with stdin/stdout wired to the
// provided buffers.
func newTestCmd(stdin, stdout *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.SetIn(stdin)
	c.SetOut(stdout)
	c.SetErr(stdout)
	return c
}

// TestRecipientAdd_DeniedForAI verifies that AI callers cannot add recipients
// even when --yes is set. The audit row must be written with result=denied.
func TestRecipientAdd_DeniedForAI(t *testing.T) {
	dbPath := newTestAuditHome(t)
	// Pin this test process as an AI caller via the env flag.
	t.Setenv("CLAUDECODE", "1")

	// Sanity-check the classification for this process.
	if caller.Identify("").Kind != caller.KindAI {
		t.Fatalf("expected KindAI, got %s", caller.Identify("").Kind)
	}

	var stdout bytes.Buffer
	cmd := newTestCmd(&bytes.Buffer{}, &stdout)

	// --yes is irrelevant — AI denial happens before Import.
	err := runRecipientAdd(context.Background(), cmd, "", "does-not-matter", true)
	if !errors.Is(err, errRecipientAIDenied) {
		t.Fatalf("want errRecipientAIDenied, got %v", err)
	}

	// Verify the audit row is recorded denied.
	al := openTestAudit(t, dbPath)
	rows, err := al.Tail(context.Background(), audit.Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("expected at least one audit row")
	}
	found := false
	for _, r := range rows {
		if r.Action == audit.ActionRecipientAdd && r.Result == audit.ResultDenied {
			found = true
			if !strings.Contains(r.Reason, "ai caller refused") {
				t.Errorf("reason mismatch: %q", r.Reason)
			}
			if r.ActorKind != string(caller.KindAI) {
				t.Errorf("actor_kind = %q", r.ActorKind)
			}
		}
	}
	if !found {
		t.Fatalf("expected a denied recipient_add row, got %+v", rows)
	}
}

// TestRecipientRemove_DeniedForAI mirrors the above for the remove command.
func TestRecipientRemove_DeniedForAI(t *testing.T) {
	dbPath := newTestAuditHome(t)
	t.Setenv("CLAUDECODE", "1")

	var stdout bytes.Buffer
	cmd := newTestCmd(&bytes.Buffer{}, &stdout)
	err := runRecipientRemove(context.Background(), cmd, "",
		"AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
	if !errors.Is(err, errRecipientAIDenied) {
		t.Fatalf("want errRecipientAIDenied, got %v", err)
	}
	al := openTestAudit(t, dbPath)
	rows, _ := al.Tail(context.Background(), audit.Filter{Limit: 5})
	if len(rows) == 0 || rows[0].Action != audit.ActionRecipientRemove || rows[0].Result != audit.ResultDenied {
		t.Fatalf("expected a denied recipient_remove row, got %+v", rows)
	}
	var detail map[string]any
	_ = json.Unmarshal(rows[0].ActorDetail, &detail)
	if detail["kind"] != "ai" {
		t.Errorf("actor_detail.kind = %v, want ai", detail["kind"])
	}
}

// TestRecipientAdd_WithYes drives the happy-path Add flow through runRecipientAdd
// while pretending to be a human TTY, with the subprocess layer stubbed.
//
// Skipped when the surrounding process has an AI parent-chain marker (claude,
// cursor, ...) we cannot strip — in that case caller.Identify pins the kind
// to KindAI regardless of --requester, and the AI-denial would trip first.
func TestRecipientAdd_WithYes(t *testing.T) {
	dbPath := newTestAuditHome(t)
	clearAISignals(t)
	if caller.Identify("human").Kind == caller.KindAI {
		t.Skip("parent chain pins this test process as AI — cannot exercise human path")
	}

	stub := &stubRunner{handlers: map[string]stubResp{
		"gpg --batch --import ":         {},
		"gpg --with-colons --show-keys": {out: []byte(showKeysFixture)},
		"gopass recipients add ":        {},
	}}
	restore := recipient.WithRunner(stub)
	defer restore()

	// Create a key file for Import's os.Stat check.
	keyfile := filepath.Join(t.TempDir(), "second.asc")
	if err := os.WriteFile(keyfile, []byte("pretend-armored"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	cmd := newTestCmd(&bytes.Buffer{}, &stdout)
	if err := runRecipientAdd(context.Background(), cmd, "human", keyfile, true); err != nil {
		t.Fatalf("runRecipientAdd: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555") {
		t.Errorf("stdout did not print fingerprint: %q", out)
	}
	if !strings.Contains(out, "added recipient") {
		t.Errorf("stdout missing success line: %q", out)
	}
	// Assert audit row is OK with fpr in reason.
	al := openTestAudit(t, dbPath)
	rows, _ := al.Tail(context.Background(), audit.Filter{Limit: 5,
		Action: audit.ActionRecipientAdd})
	if len(rows) == 0 {
		t.Fatal("no recipient_add audit rows")
	}
	ok := false
	for _, r := range rows {
		if r.Result == audit.ResultOK &&
			strings.Contains(r.Reason, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("no successful recipient_add row with fpr in reason, rows=%+v", rows)
	}
}

// TestRecipientAdd_NonInteractiveAborts verifies that piping stdin without
// --yes aborts cleanly (no error to the shell), writes a denied audit row,
// and prints "aborted".
func TestRecipientAdd_NonInteractiveAborts(t *testing.T) {
	dbPath := newTestAuditHome(t)
	clearAISignals(t)
	if caller.Identify("human").Kind == caller.KindAI {
		t.Skip("parent chain pins this test process as AI — cannot exercise human path")
	}

	stub := &stubRunner{handlers: map[string]stubResp{
		"gpg --batch --import ":         {},
		"gpg --with-colons --show-keys": {out: []byte(showKeysFixture)},
	}}
	restore := recipient.WithRunner(stub)
	defer restore()

	keyfile := filepath.Join(t.TempDir(), "second.asc")
	if err := os.WriteFile(keyfile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Custom stdin reader (bytes.Buffer) → isTerminalStdin returns false.
	var stdin, stdout bytes.Buffer
	cmd := newTestCmd(&stdin, &stdout)
	err := runRecipientAdd(context.Background(), cmd, "human", keyfile, false /*yes*/)
	if err != nil {
		t.Fatalf("expected clean abort, got err: %v", err)
	}
	if !strings.Contains(stdout.String(), "aborted") {
		t.Errorf("expected 'aborted' in output, got %q", stdout.String())
	}
	al := openTestAudit(t, dbPath)
	rows, _ := al.Tail(context.Background(), audit.Filter{Limit: 5,
		Action: audit.ActionRecipientAdd})
	if len(rows) == 0 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("expected a denied recipient_add row, got %+v", rows)
	}
	if !strings.Contains(rows[0].Reason, "user=declined") {
		t.Errorf("reason should mention declined: %q", rows[0].Reason)
	}
}

// TestRecipientList_AllowsAI ensures listing is permitted for AI callers
// (read-only op). Audit row is OK.
func TestRecipientList_AllowsAI(t *testing.T) {
	dbPath := newTestAuditHome(t)
	t.Setenv("CLAUDECODE", "1")

	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass recipients": {out: []byte("")},
	}}
	restore := recipient.WithRunner(stub)
	defer restore()

	var stdout bytes.Buffer
	cmd := newTestCmd(&bytes.Buffer{}, &stdout)
	if err := runRecipientList(context.Background(), cmd, ""); err != nil {
		t.Fatalf("runRecipientList: %v", err)
	}
	al := openTestAudit(t, dbPath)
	rows, _ := al.Tail(context.Background(), audit.Filter{Limit: 5,
		Action: audit.ActionRecipientList})
	if len(rows) == 0 || rows[0].Result != audit.ResultOK {
		t.Fatalf("expected an OK recipient_list row, got %+v", rows)
	}
	if rows[0].ActorKind != string(caller.KindAI) {
		t.Errorf("actor_kind = %q, want ai", rows[0].ActorKind)
	}
}

// TestConfirmAdd_YesFlag exercises the --yes path in confirmAdd.
func TestConfirmAdd_YesFlag(t *testing.T) {
	var out bytes.Buffer
	ok, err := confirmAdd(&bytes.Buffer{}, &out, true)
	if err != nil || !ok {
		t.Fatalf("yes=true: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(out.String(), "auto-confirmed") {
		t.Errorf("expected 'auto-confirmed' note")
	}
}

// TestConfirmAdd_NonTerminalStdinAborts confirms that a non-terminal reader
// without --yes aborts with ok=false, nil error.
func TestConfirmAdd_NonTerminalStdinAborts(t *testing.T) {
	var out bytes.Buffer
	ok, err := confirmAdd(&bytes.Buffer{}, &out, false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for non-terminal stdin without --yes")
	}
}
