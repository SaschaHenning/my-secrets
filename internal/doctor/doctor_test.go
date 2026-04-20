package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setIsolatedHome redirects HOME to a temp dir for the duration of the test
// so checks that read config / backups / audit state cannot see real user
// data. It also clears PASSWORD_STORE_DIR and MYS_AUDIT_SIGN.
func setIsolatedHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("PASSWORD_STORE_DIR", "")
	t.Setenv("MYS_AUDIT_SIGN", "")
	return dir
}

// ----------------------------------------------------------------------------
// CheckStore
// ----------------------------------------------------------------------------

func TestCheckStoreMissing(t *testing.T) {
	home := setIsolatedHome(t)
	// Ensure store dir does NOT exist.
	_ = os.RemoveAll(filepath.Join(home, ".password-store"))
	c := CheckStore(context.Background())
	if c.Status != StatusFail {
		t.Fatalf("want FAIL, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckStorePresent(t *testing.T) {
	home := setIsolatedHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".password-store"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := CheckStore(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckStoreCustomEnv(t *testing.T) {
	setIsolatedHome(t)
	custom := filepath.Join(t.TempDir(), "my-store")
	if err := os.MkdirAll(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSWORD_STORE_DIR", custom)
	c := CheckStore(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, custom) {
		t.Errorf("expected message to reference custom path, got %q", c.Message)
	}
}

// ----------------------------------------------------------------------------
// parseSecretKeys
// ----------------------------------------------------------------------------

func TestParseSecretKeysEmpty(t *testing.T) {
	n, fpr := parseSecretKeys("")
	if n != 0 || fpr != "" {
		t.Errorf("empty input: got n=%d fpr=%q", n, fpr)
	}
}

func TestParseSecretKeysTwo(t *testing.T) {
	colons := "sec:u:4096:1:ABCD:::\n" +
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA11111111:\n" +
		"sec:u:4096:1:EFGH:::\n" +
		"fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB22222222:\n"
	n, fpr := parseSecretKeys(colons)
	if n != 2 {
		t.Errorf("want 2 secret keys, got %d", n)
	}
	if !strings.HasSuffix(fpr, "11111111") {
		t.Errorf("unexpected first fpr: %q", fpr)
	}
}

// ----------------------------------------------------------------------------
// countRecipients
// ----------------------------------------------------------------------------

func TestCountRecipients(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"gopass\n└── 0xABCDEF1234 <alice@example.com>\n", 1},
		{"gopass\n├── 0xABCDEF <a>\n└── 0x123456 <b>\n", 2},
		{"gopass\n└── AAAAAAAAAAAAAAAA (16 hex chars)\n", 1},
	}
	for _, tc := range cases {
		got := countRecipients(tc.in)
		if got != tc.want {
			t.Errorf("countRecipients(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// ----------------------------------------------------------------------------
// CheckAuditWritable
// ----------------------------------------------------------------------------

func TestCheckAuditWritablePass(t *testing.T) {
	setIsolatedHome(t)
	c := CheckAuditWritable(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

// ----------------------------------------------------------------------------
// CheckAuditGaps
// ----------------------------------------------------------------------------

func TestCheckAuditGapsEmptyDB(t *testing.T) {
	setIsolatedHome(t)
	c := CheckAuditGaps(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS on empty DB, got %s (%s)", c.Status, c.Message)
	}
}

// ----------------------------------------------------------------------------
// CheckSignedChain
// ----------------------------------------------------------------------------

func TestCheckSignedChainSkipped(t *testing.T) {
	setIsolatedHome(t)
	// Default: MYS_AUDIT_SIGN unset → must skip.
	c := CheckSignedChain(context.Background())
	if c.Status != StatusSkip {
		t.Fatalf("want SKIP, got %s (%s)", c.Status, c.Message)
	}
}

// ----------------------------------------------------------------------------
// CheckPaperkeyBackup
// ----------------------------------------------------------------------------

func TestCheckPaperkeyBackupMissing(t *testing.T) {
	setIsolatedHome(t)
	c := CheckPaperkeyBackup(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPaperkeyBackupEmptyArray(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".local", "share", "my-secrets", "backups.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPaperkeyBackup(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPaperkeyBackupArrayEntries(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".local", "share", "my-secrets", "backups.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal([]map[string]any{
		{"created": time.Now().UTC().Format(time.RFC3339)},
	})
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPaperkeyBackup(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPaperkeyBackupWrappedEntries(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".local", "share", "my-secrets", "backups.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"entries":[{"created":"2026-01-01T00:00:00Z"}]}`)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPaperkeyBackup(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

// ----------------------------------------------------------------------------
// CheckPolicy
// ----------------------------------------------------------------------------

func TestCheckPolicyMissing(t *testing.T) {
	setIsolatedHome(t)
	c := CheckPolicy(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN on missing policy, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPolicyValid(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".config", "my-secrets", "scope-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `actors:
  human:
    allow: ["**"]
  ai:
    allow: ["jasp/**"]
    deny: ["private/**"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPolicy(context.Background())
	if c.Status != StatusPass {
		t.Fatalf("want PASS, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPolicyInvalidYAML(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".config", "my-secrets", "scope-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// Malformed YAML — unterminated mapping.
	if err := os.WriteFile(p, []byte("actors: {human: [allow:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPolicy(context.Background())
	if c.Status != StatusFail {
		t.Fatalf("want FAIL on invalid YAML, got %s (%s)", c.Status, c.Message)
	}
}

func TestCheckPolicyEmptyActors(t *testing.T) {
	home := setIsolatedHome(t)
	p := filepath.Join(home, ".config", "my-secrets", "scope-policy.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// Valid YAML but no actors defined.
	if err := os.WriteFile(p, []byte("actors: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := CheckPolicy(context.Background())
	if c.Status != StatusWarn {
		t.Fatalf("want WARN on empty actors, got %s (%s)", c.Status, c.Message)
	}
}

// ----------------------------------------------------------------------------
// Run / registry
// ----------------------------------------------------------------------------

func TestRunFilterByOnly(t *testing.T) {
	setIsolatedHome(t)
	r := Run(context.Background(), []string{"policy", "paperkey-backup"})
	if len(r.Checks) != 2 {
		t.Fatalf("want 2 checks, got %d", len(r.Checks))
	}
	ids := map[string]bool{}
	for _, c := range r.Checks {
		ids[c.ID] = true
	}
	if !ids["policy"] || !ids["paperkey-backup"] {
		t.Errorf("unexpected ids: %+v", ids)
	}
}

func TestRunSummaryCounts(t *testing.T) {
	setIsolatedHome(t)
	// Only run cheap, deterministic checks to avoid flakiness from gpg /
	// gopass presence on the build machine.
	r := Run(context.Background(), []string{"signed-chain", "paperkey-backup", "policy"})
	total := r.Summary.Pass + r.Summary.Warn + r.Summary.Fail + r.Summary.Skip
	if total != len(r.Checks) {
		t.Errorf("summary total %d != len(checks) %d", total, len(r.Checks))
	}
	// signed-chain must be SKIP, paperkey-backup WARN, policy WARN in the
	// isolated empty HOME.
	want := map[string]Status{
		"signed-chain":    StatusSkip,
		"paperkey-backup": StatusWarn,
		"policy":          StatusWarn,
	}
	for _, c := range r.Checks {
		if w, ok := want[c.ID]; ok && c.Status != w {
			t.Errorf("check %s: got %s, want %s (%s)", c.ID, c.Status, w, c.Message)
		}
	}
}

func TestRegistryOrderStable(t *testing.T) {
	reg1 := Registry()
	reg2 := Registry()
	if len(reg1) != len(reg2) {
		t.Fatalf("registry length changed across calls: %d vs %d", len(reg1), len(reg2))
	}
	for i := range reg1 {
		if reg1[i].ID != reg2[i].ID {
			t.Errorf("registry order unstable at %d: %q vs %q", i, reg1[i].ID, reg2[i].ID)
		}
	}
}

func TestRegistryHasAllTenChecks(t *testing.T) {
	reg := Registry()
	if len(reg) != 10 {
		t.Fatalf("expected 10 registered checks, got %d", len(reg))
	}
	wantIDs := []string{
		"store", "gpg-key", "recipients", "git-remote", "sync-age",
		"audit-writable", "audit-gaps", "signed-chain",
		"paperkey-backup", "policy",
	}
	for i, id := range wantIDs {
		if reg[i].ID != id {
			t.Errorf("registry[%d].ID = %q, want %q", i, reg[i].ID, id)
		}
	}
}
