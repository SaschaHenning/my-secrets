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
	syncpkg "github.com/SaschaHenning/my-secrets/internal/sync"
	"github.com/SaschaHenning/my-secrets/internal/teamkeys"
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

const (
	recipientTestFingerprint = "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
	otherTestFingerprint     = "BBBB1111CCCC2222DDDD3333EEEE4444FFFF5555"
)

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

func humanRecipientDetail() caller.Detail {
	return caller.Detail{
		Kind:   caller.KindHuman,
		Reason: "test human caller",
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

func saveRecipientSyncConfig(t *testing.T, remotes ...syncpkg.StoreRemote) {
	t.Helper()
	cfg, err := syncpkg.Load("")
	if err != nil {
		t.Fatalf("load recipient sync config: %v", err)
	}
	cfg.Layout = syncpkg.LayoutPerOrg
	cfg.Remotes = remotes
	if err := syncpkg.Save("", cfg); err != nil {
		t.Fatalf("save recipient sync config: %v", err)
	}
}

func writeRecipientTeamManifest(
	t *testing.T,
	mountPath string,
	members ...teamkeys.Member,
) {
	t.Helper()
	manifest := &teamkeys.File{Version: 1, Members: members}
	if err := teamkeys.Save(
		filepath.Join(mountPath, teamkeys.Filename),
		manifest,
	); err != nil {
		t.Fatalf("save recipient team manifest: %v", err)
	}
}

func recipientTeamMember(fingerprint string) teamkeys.Member {
	return teamkeys.Member{
		Name:        "Alice Example",
		Fingerprint: fingerprint,
		Email:       "alice@example.org",
	}
}

func createRecipientKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recipient.asc")
	if err := os.WriteFile(path, []byte("pretend-armored"), 0o600); err != nil {
		t.Fatalf("write recipient key: %v", err)
	}
	return path
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

func TestRecipientMutations_DeniedForAIByMount(t *testing.T) {
	tests := []struct {
		name   string
		action string
		mount  string
		run    func(context.Context, *cobra.Command, string) error
	}{
		{
			name:   "default add",
			action: audit.ActionRecipientAdd,
			run: func(ctx context.Context, cmd *cobra.Command, mount string) error {
				return runRecipientAddForMount(
					ctx, cmd, "", "must-not-be-imported", mount, true)
			},
		},
		{
			name:   "shared add",
			action: audit.ActionRecipientAdd,
			mount:  "jasp",
			run: func(ctx context.Context, cmd *cobra.Command, mount string) error {
				return runRecipientAddForMount(
					ctx, cmd, "", "must-not-be-imported", mount, true)
			},
		},
		{
			name:   "default remove",
			action: audit.ActionRecipientRemove,
			run: func(ctx context.Context, cmd *cobra.Command, mount string) error {
				return runRecipientRemoveForMount(
					ctx, cmd, "", recipientTestFingerprint, mount)
			},
		},
		{
			name:   "shared remove",
			action: audit.ActionRecipientRemove,
			mount:  "jasp",
			run: func(ctx context.Context, cmd *cobra.Command, mount string) error {
				return runRecipientRemoveForMount(
					ctx, cmd, "", recipientTestFingerprint, mount)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := newTestAuditHome(t)
			t.Setenv("CLAUDECODE", "1")

			stub := &stubRunner{handlers: map[string]stubResp{}}
			restore := recipient.WithRunner(stub)
			defer restore()

			cmd := newTestCmd(&bytes.Buffer{}, &bytes.Buffer{})
			err := tc.run(context.Background(), cmd, tc.mount)
			if !errors.Is(err, errRecipientAIDenied) {
				t.Fatalf("error = %v, want errRecipientAIDenied", err)
			}
			if len(stub.calls) != 0 {
				t.Fatalf("AI denial invoked subprocesses: %v", stub.calls)
			}

			al := openTestAudit(t, dbPath)
			rows, err := al.Tail(context.Background(), audit.Filter{
				Action: tc.action,
				Limit:  5,
			})
			if err != nil {
				t.Fatalf("read audit: %v", err)
			}
			if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
				t.Fatalf("audit rows = %+v, want one denied row", rows)
			}
			if rows[0].Org != tc.mount {
				t.Fatalf("audit org = %q, want %q", rows[0].Org, tc.mount)
			}
		})
	}
}

// TestRecipientAdd_WithYes drives the default-mount happy path with the
// subprocess layer stubbed.
func TestRecipientAdd_WithYes(t *testing.T) {
	dbPath := newTestAuditHome(t)

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
	if err := runRecipientAddForMountAs(
		context.Background(),
		cmd,
		humanRecipientDetail(),
		keyfile,
		"",
		true,
	); err != nil {
		t.Fatalf("runRecipientAdd: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555") {
		t.Errorf("stdout did not print fingerprint: %q", out)
	}
	if !strings.Contains(out, "added recipient") {
		t.Errorf("stdout missing success line: %q", out)
	}
	wantCalls := []string{
		"gpg --batch --import " + keyfile,
		"gpg --with-colons --show-keys " + keyfile,
		"gopass recipients add " + recipientTestFingerprint,
	}
	if strings.Join(stub.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("default recipient calls = %v, want %v", stub.calls, wantCalls)
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

func TestRecipientAdd_SharedMountReconcilesTeamManifest(t *testing.T) {
	tests := []struct {
		name        string
		memberFPR   string
		wantOutput  string
		wantWarning bool
	}{
		{
			name:       "listed member",
			memberFPR:  recipientTestFingerprint,
			wantOutput: "team member: Alice Example <alice@example.org>",
		},
		{
			name:        "manifest may lag new member",
			memberFPR:   otherTestFingerprint,
			wantOutput:  "not listed in team-keys.yaml",
			wantWarning: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := newTestAuditHome(t)

			mountPath := t.TempDir()
			writeRecipientTeamManifest(t, mountPath, recipientTeamMember(tc.memberFPR))
			saveRecipientSyncConfig(t, syncpkg.StoreRemote{
				Mount:  "jasp",
				URL:    "file:///test/jasp.git",
				Shared: true,
			})
			keyfile := createRecipientKeyFile(t)

			stub := &stubRunner{handlers: map[string]stubResp{
				"gopass config mounts.jasp.path": {
					out: []byte(mountPath + "\n"),
				},
				"gpg --batch --import " + keyfile: {},
				"gpg --with-colons --show-keys " + keyfile: {
					out: []byte(showKeysFixture),
				},
				"gopass --yes recipients add --store jasp " + recipientTestFingerprint: {},
			}}
			restore := recipient.WithRunner(stub)
			defer restore()

			var output bytes.Buffer
			cmd := newTestCmd(&bytes.Buffer{}, &output)
			err := runRecipientAddForMountAs(
				context.Background(),
				cmd,
				humanRecipientDetail(),
				keyfile,
				"jasp",
				true,
			)
			if err != nil {
				t.Fatalf("run shared recipient add: %v", err)
			}
			if !strings.Contains(output.String(), tc.wantOutput) {
				t.Fatalf("output %q does not contain %q", output.String(), tc.wantOutput)
			}
			if !strings.Contains(output.String(), `shared mount "jasp"`) {
				t.Fatalf("shared warning missing from output: %q", output.String())
			}

			wantCalls := []string{
				"gopass config mounts.jasp.path",
				"gpg --batch --import " + keyfile,
				"gpg --with-colons --show-keys " + keyfile,
				"gopass config mounts.jasp.path",
				"gopass config mounts.jasp.path",
				"gopass --yes recipients add --store jasp " + recipientTestFingerprint,
			}
			if strings.Join(stub.calls, "\n") != strings.Join(wantCalls, "\n") {
				t.Fatalf("shared recipient calls = %v, want %v", stub.calls, wantCalls)
			}

			al := openTestAudit(t, dbPath)
			rows, err := al.Tail(context.Background(), audit.Filter{
				Action: audit.ActionRecipientAdd,
				Org:    "jasp",
				Limit:  5,
			})
			if err != nil {
				t.Fatalf("read shared recipient audit: %v", err)
			}
			if len(rows) != 1 || rows[0].Result != audit.ResultOK {
				t.Fatalf("shared recipient audit rows = %+v", rows)
			}
			hasTeamName := strings.Contains(rows[0].Reason, "team_name=Alice Example")
			if hasTeamName == tc.wantWarning {
				t.Fatalf("audit reason %q hasTeamName=%v, want %v",
					rows[0].Reason, hasTeamName, !tc.wantWarning)
			}
		})
	}
}

func TestRecipientAdd_SharedMountRequiresManifestBeforeImport(t *testing.T) {
	dbPath := newTestAuditHome(t)

	mountPath := t.TempDir()
	saveRecipientSyncConfig(t, syncpkg.StoreRemote{
		Mount:  "jasp",
		URL:    "file:///test/jasp.git",
		Shared: true,
	})
	stub := &stubRunner{handlers: map[string]stubResp{
		"gopass config mounts.jasp.path": {out: []byte(mountPath + "\n")},
	}}
	restore := recipient.WithRunner(stub)
	defer restore()

	cmd := newTestCmd(&bytes.Buffer{}, &bytes.Buffer{})
	err := runRecipientAddForMountAs(
		context.Background(),
		cmd,
		humanRecipientDetail(),
		"must-not-be-imported",
		"jasp",
		true,
	)
	if err == nil || !strings.Contains(err.Error(), teamkeys.Filename) {
		t.Fatalf("error = %v, want missing %s", err, teamkeys.Filename)
	}
	if strings.Join(stub.calls, "\n") != "gopass config mounts.jasp.path" {
		t.Fatalf("calls = %v, key import must not run", stub.calls)
	}

	al := openTestAudit(t, dbPath)
	rows, err := al.Tail(context.Background(), audit.Filter{
		Action: audit.ActionRecipientAdd,
		Org:    "jasp",
		Limit:  5,
	})
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("audit rows = %+v, want denied shared add", rows)
	}
}

func TestRecipientAdd_NamedPersonalMountKeepsOwnDevicePath(t *testing.T) {
	newTestAuditHome(t)

	saveRecipientSyncConfig(t, syncpkg.StoreRemote{
		Mount: "work",
		URL:   "file:///test/work.git",
	})
	keyfile := createRecipientKeyFile(t)
	stub := &stubRunner{handlers: map[string]stubResp{
		"gpg --batch --import " + keyfile: {},
		"gpg --with-colons --show-keys " + keyfile: {
			out: []byte(showKeysFixture),
		},
		"gopass recipients add --store work " + recipientTestFingerprint: {},
	}}
	restore := recipient.WithRunner(stub)
	defer restore()

	var output bytes.Buffer
	cmd := newTestCmd(&bytes.Buffer{}, &output)
	err := runRecipientAddForMountAs(
		context.Background(),
		cmd,
		humanRecipientDetail(),
		keyfile,
		"work",
		true,
	)
	if err != nil {
		t.Fatalf("run named personal recipient add: %v", err)
	}
	wantCalls := []string{
		"gpg --batch --import " + keyfile,
		"gpg --with-colons --show-keys " + keyfile,
		"gopass recipients add --store work " + recipientTestFingerprint,
	}
	if strings.Join(stub.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls = %v, want %v", stub.calls, wantCalls)
	}
	if !strings.Contains(output.String(), "your own second device") {
		t.Fatalf("personal-store warning changed: %q", output.String())
	}
	if strings.Contains(output.String(), `shared mount "work"`) {
		t.Fatalf("personal mount presented as shared: %q", output.String())
	}
}

// TestRecipientAdd_NonInteractiveAborts verifies that piping stdin without
// --yes aborts cleanly (no error to the shell), writes a denied audit row,
// and prints "aborted".
func TestRecipientAdd_NonInteractiveAborts(t *testing.T) {
	dbPath := newTestAuditHome(t)

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
	err := runRecipientAddForMountAs(
		context.Background(),
		cmd,
		humanRecipientDetail(),
		keyfile,
		"",
		false, /* yes */
	)
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

func TestRecipientList_AllowsAIForDefaultAndSharedMounts(t *testing.T) {
	tests := []struct {
		name  string
		mount string
	}{
		{name: "default"},
		{name: "shared", mount: "jasp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := newTestAuditHome(t)
			t.Setenv("CLAUDECODE", "1")

			handlers := map[string]stubResp{
				"gopass recipients": {},
			}
			wantCall := "gopass recipients"
			if tc.mount != "" {
				mountPath := t.TempDir()
				if err := os.WriteFile(
					filepath.Join(mountPath, ".gpg-id"),
					nil,
					0o600,
				); err != nil {
					t.Fatalf("write .gpg-id: %v", err)
				}
				wantCall = "gopass config mounts.jasp.path"
				handlers = map[string]stubResp{
					wantCall: {out: []byte(mountPath + "\n")},
				}
			}

			stub := &stubRunner{handlers: handlers}
			restore := recipient.WithRunner(stub)
			defer restore()

			cmd := newTestCmd(&bytes.Buffer{}, &bytes.Buffer{})
			if err := runRecipientListForMount(
				context.Background(), cmd, "", tc.mount,
			); err != nil {
				t.Fatalf("run recipient list: %v", err)
			}
			if len(stub.calls) != 1 || stub.calls[0] != wantCall {
				t.Fatalf("calls = %v, want [%q]", stub.calls, wantCall)
			}

			al := openTestAudit(t, dbPath)
			rows, err := al.Tail(context.Background(), audit.Filter{
				Action: audit.ActionRecipientList,
				Limit:  5,
			})
			if err != nil {
				t.Fatalf("read audit: %v", err)
			}
			if len(rows) != 1 || rows[0].Result != audit.ResultOK {
				t.Fatalf("audit rows = %+v, want one ok row", rows)
			}
			if rows[0].Org != tc.mount {
				t.Fatalf("audit org = %q, want %q", rows[0].Org, tc.mount)
			}
			if rows[0].ActorKind != string(caller.KindAI) {
				t.Fatalf("actor kind = %q, want ai", rows[0].ActorKind)
			}
		})
	}
}

func TestRecipientRemove_TargetsRequestedMount(t *testing.T) {
	tests := []struct {
		name      string
		mount     string
		shared    bool
		wantCalls []string
	}{
		{
			name:      "default argv unchanged",
			wantCalls: []string{"gopass recipients remove " + recipientTestFingerprint},
		},
		{
			name:  "named personal mount",
			mount: "work",
			wantCalls: []string{
				"gopass recipients remove --store work " + recipientTestFingerprint,
			},
		},
		{
			name:   "shared mount revalidates manifest",
			mount:  "jasp",
			shared: true,
			wantCalls: []string{
				"gopass config mounts.jasp.path",
				"gopass config mounts.jasp.path",
				"gopass recipients remove --store jasp " + recipientTestFingerprint,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := newTestAuditHome(t)

			handlers := map[string]stubResp{}
			if tc.mount != "" {
				saveRecipientSyncConfig(t, syncpkg.StoreRemote{
					Mount:  tc.mount,
					URL:    "file:///test/" + tc.mount + ".git",
					Shared: tc.shared,
				})
			}
			if tc.shared {
				mountPath := t.TempDir()
				writeRecipientTeamManifest(
					t, mountPath, recipientTeamMember(recipientTestFingerprint))
				handlers["gopass config mounts.jasp.path"] = stubResp{
					out: []byte(mountPath + "\n"),
				}
			}
			handlers[tc.wantCalls[len(tc.wantCalls)-1]] = stubResp{}

			stub := &stubRunner{handlers: handlers}
			restore := recipient.WithRunner(stub)
			defer restore()

			var output bytes.Buffer
			cmd := newTestCmd(&bytes.Buffer{}, &output)
			err := runRecipientRemoveForMountAs(
				context.Background(),
				cmd,
				humanRecipientDetail(),
				recipientTestFingerprint,
				tc.mount,
			)
			if err != nil {
				t.Fatalf("run recipient remove: %v", err)
			}
			if strings.Join(stub.calls, "\n") != strings.Join(tc.wantCalls, "\n") {
				t.Fatalf("calls = %v, want %v", stub.calls, tc.wantCalls)
			}
			if !strings.Contains(output.String(), "removed recipient") {
				t.Fatalf("success output missing: %q", output.String())
			}

			al := openTestAudit(t, dbPath)
			rows, err := al.Tail(context.Background(), audit.Filter{
				Action: audit.ActionRecipientRemove,
				Limit:  5,
			})
			if err != nil {
				t.Fatalf("read audit: %v", err)
			}
			if len(rows) != 1 || rows[0].Result != audit.ResultOK {
				t.Fatalf("audit rows = %+v, want one ok row", rows)
			}
			if rows[0].Org != tc.mount {
				t.Fatalf("audit org = %q, want %q", rows[0].Org, tc.mount)
			}
		})
	}
}

func TestMutateRecipientTargetRejectsSharingModeChange(t *testing.T) {
	newTestAuditHome(t)
	saveRecipientSyncConfig(t, syncpkg.StoreRemote{
		Mount: "work",
		URL:   "file:///test/work.git",
	})
	original, err := loadRecipientMountTarget("work")
	if err != nil {
		t.Fatalf("load original target: %v", err)
	}

	saveRecipientSyncConfig(t, syncpkg.StoreRemote{
		Mount:  "work",
		URL:    "file:///test/work.git",
		Shared: true,
	})
	mutated := false
	err = mutateRecipientTarget(
		context.Background(),
		original,
		func(recipientMountTarget) error {
			mutated = true
			return nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "sharing mode changed") {
		t.Fatalf("error = %v, want sharing-mode change", err)
	}
	if mutated {
		t.Fatal("mutation ran after sharing mode changed")
	}
}

func TestRecipientCommandsExposeMountFlagAndScopeHelp(t *testing.T) {
	requester := "human"
	root := recipientCmd(&requester)
	for _, name := range []string{"add", "list", "remove"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatalf("find %s command: %v", name, err)
		}
		flag := cmd.Flags().Lookup("mount")
		if flag == nil {
			t.Fatalf("%s command has no --mount flag", name)
		}
		if flag.DefValue != "" {
			t.Fatalf("%s --mount default = %q, want empty", name, flag.DefValue)
		}
	}
	for _, required := range []string{
		"DEFAULT STORE SCOPE",
		"ONLY",
		"SHARED MOUNT SCOPE",
		"team-keys.yaml",
		"AI callers",
	} {
		if !strings.Contains(root.Long, required) {
			t.Fatalf("recipient help is missing %q: %s", required, root.Long)
		}
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
