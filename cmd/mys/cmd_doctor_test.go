package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// runDoctor invokes the doctor command with the given args and captures
// stdout. It isolates HOME to t.TempDir() and clears MYS_AUDIT_SIGN /
// PASSWORD_STORE_DIR so the suite does not see real user state.
func runDoctor(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PASSWORD_STORE_DIR", "")
	t.Setenv("MYS_AUDIT_SIGN", "")

	var requester string
	cmd := doctorCmd(&requester)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return buf.String(), err
}

func TestDoctorJSONOnlyOutputsValidJSON(t *testing.T) {
	out, _ := runDoctor(t, "--json", "--only", "policy,paperkey-backup,signed-chain")
	// The doctor may return non-nil err if FAIL count > 0, but with the
	// picked checks on an empty HOME we expect WARN+WARN+SKIP → no FAIL.
	var report struct {
		Checks []struct {
			ID      string `json:"id"`
			Label   string `json:"label"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"checks"`
		Summary struct {
			Pass int `json:"pass"`
			Warn int `json:"warn"`
			Fail int `json:"fail"`
			Skip int `json:"skip"`
		} `json:"summary"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output not valid JSON: %v\n---\n%s", err, out)
	}
	if len(report.Checks) != 3 {
		t.Fatalf("want 3 checks, got %d (%+v)", len(report.Checks), report.Checks)
	}
	if report.Summary.Fail != 0 {
		t.Errorf("unexpected fail count: %d", report.Summary.Fail)
	}
	if report.Timestamp == "" {
		t.Error("timestamp missing")
	}
	// Ensure summary totals add up to the number of checks.
	total := report.Summary.Pass + report.Summary.Warn + report.Summary.Fail + report.Summary.Skip
	if total != len(report.Checks) {
		t.Errorf("summary total %d != len(checks) %d", total, len(report.Checks))
	}
}

func TestDoctorTextOutputHasSummaryLine(t *testing.T) {
	out, _ := runDoctor(t, "--only", "policy,signed-chain")
	if !strings.Contains(out, "Summary:") {
		t.Errorf("missing Summary line in output:\n%s", out)
	}
	if !strings.Contains(out, "PASS") && !strings.Contains(out, "WARN") && !strings.Contains(out, "SKIP") {
		t.Errorf("no status prefixes found:\n%s", out)
	}
}

func TestDoctorOnlyFilterRestrictsChecks(t *testing.T) {
	out, _ := runDoctor(t, "--json", "--only", "signed-chain")
	if !strings.Contains(out, `"id": "signed-chain"`) {
		t.Errorf("expected signed-chain id in output:\n%s", out)
	}
	// Other IDs must be absent.
	for _, id := range []string{"store", "gpg-key", "recipients", "policy", "paperkey-backup"} {
		if strings.Contains(out, `"id": "`+id+`"`) {
			t.Errorf("filter leaked id %q into output:\n%s", id, out)
		}
	}
}

func TestDoctorFailExitOnFailingCheck(t *testing.T) {
	// Store-check on an isolated empty HOME fails (no ~/.password-store).
	_, err := runDoctor(t, "--only", "store")
	if err == nil {
		t.Fatalf("expected non-nil error when a check fails")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}
