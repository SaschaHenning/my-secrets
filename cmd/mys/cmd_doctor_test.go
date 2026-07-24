package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
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

type fakeDoctorRotationApp struct {
	entries     []*store.Entry
	readErr     error
	closeErr    error
	closed      bool
	closeCtxErr error
	hasDeadline bool
	closeCalls  int
}

func (application *fakeDoctorRotationApp) DoctorRotationEntries(
	context.Context,
) ([]*store.Entry, error) {
	return application.entries, application.readErr
}

func (application *fakeDoctorRotationApp) Close(ctx context.Context) error {
	application.closed = true
	application.closeCalls++
	application.closeCtxErr = ctx.Err()
	_, application.hasDeadline = ctx.Deadline()
	return application.closeErr
}

func TestAppRotationProviderUsesRequesterAndClosesApp(t *testing.T) {
	application := &fakeDoctorRotationApp{
		entries: []*store.Entry{{Path: "jasp/a"}},
	}
	var gotRequester string
	provider := appRotationProvider{
		requester: "claude-code",
		open: func(
			_ context.Context,
			requester string,
		) (doctorRotationApp, error) {
			gotRequester = requester
			return application, nil
		},
	}

	entries, err := provider.Entries(context.Background())
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if gotRequester != "claude-code" {
		t.Fatalf("requester = %q, want claude-code", gotRequester)
	}
	if len(entries) != 1 || entries[0].Path != "jasp/a" {
		t.Fatalf("entries = %#v", entries)
	}
	if !application.closed {
		t.Fatal("app was not closed")
	}
	if application.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", application.closeCalls)
	}
}

func TestAppRotationProviderPropagatesOpenAndReadErrors(t *testing.T) {
	openFailure := appRotationProvider{
		open: func(
			context.Context,
			string,
		) (doctorRotationApp, error) {
			return nil, errors.New("open failed")
		},
	}
	if _, err := openFailure.Entries(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "open failed") {
		t.Fatalf("open error = %v", err)
	}

	application := &fakeDoctorRotationApp{readErr: errors.New("read failed")}
	readFailure := appRotationProvider{
		open: func(
			context.Context,
			string,
		) (doctorRotationApp, error) {
			return application, nil
		},
	}
	if _, err := readFailure.Entries(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "read failed") {
		t.Fatalf("read error = %v", err)
	}
	if !application.closed {
		t.Fatal("app was not closed after read failure")
	}

	closeFailure := &fakeDoctorRotationApp{
		entries:  []*store.Entry{{Path: "jasp/secret"}},
		closeErr: errors.New("close failed"),
	}
	provider := appRotationProvider{
		open: func(
			context.Context,
			string,
		) (doctorRotationApp, error) {
			return closeFailure, nil
		},
	}
	if entries, err := provider.Entries(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "close failed") {
		t.Fatalf("close error = %v", err)
	} else if entries != nil {
		t.Fatalf("entries returned with close failure: %+v", entries)
	}
}

func TestAppRotationProviderClosesWithDetachedBoundedContext(t *testing.T) {
	application := &fakeDoctorRotationApp{
		entries: []*store.Entry{{Path: "jasp/a"}},
	}
	provider := appRotationProvider{
		open: func(
			context.Context,
			string,
		) (doctorRotationApp, error) {
			return application, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entries, err := provider.Entries(ctx)

	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "jasp/a" {
		t.Fatalf("entries = %+v", entries)
	}
	if application.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", application.closeCalls)
	}
	if application.closeCtxErr != nil {
		t.Fatalf(
			"close inherited caller cancellation: %v",
			application.closeCtxErr,
		)
	}
	if !application.hasDeadline {
		t.Fatal("close context has no bounded deadline")
	}
}
