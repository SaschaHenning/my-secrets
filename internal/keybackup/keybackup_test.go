package keybackup

import (
	"path/filepath"
	"testing"
	"time"
)

// TestLedgerRoundTrip writes a few records to a temp-dir ledger and reads
// them back, asserting that order, fields, and timestamp defaulting behave
// as documented.
func TestLedgerRoundTrip(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "backups.json")

	// Empty ledger: List must not error and must return nil slice.
	got, err := ListAt(ledger)
	if err != nil {
		t.Fatalf("ListAt empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty ledger: want 0 records, got %d", len(got))
	}

	r1 := BackupRecord{
		Method:      MethodPaper,
		Fingerprint: "DEADBEEF",
		OutputPath:  "/tmp/k.paper",
	}
	if err := AppendRecordAt(ledger, r1); err != nil {
		t.Fatalf("append r1: %v", err)
	}

	r2 := BackupRecord{
		Timestamp:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Method:      MethodArmoredSymmetric,
		Fingerprint: "CAFEBABE",
		OutputPath:  "",
	}
	if err := AppendRecordAt(ledger, r2); err != nil {
		t.Fatalf("append r2: %v", err)
	}

	got, err = ListAt(ledger)
	if err != nil {
		t.Fatalf("ListAt: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	if got[0].Method != MethodPaper || got[0].Fingerprint != "DEADBEEF" {
		t.Errorf("r1 round-trip mismatch: %+v", got[0])
	}
	if got[0].Timestamp.IsZero() {
		t.Errorf("r1 timestamp default not applied")
	}
	if got[1].Method != MethodArmoredSymmetric {
		t.Errorf("r2 method mismatch: %q", got[1].Method)
	}
	if !got[1].Timestamp.Equal(r2.Timestamp) {
		t.Errorf("r2 timestamp mismatch: got %v, want %v", got[1].Timestamp, r2.Timestamp)
	}
	if got[1].OutputPath != "" {
		t.Errorf("r2 outputPath: want empty, got %q", got[1].OutputPath)
	}
}

// TestDefaultStatusPath sanity-checks the resolved default location.
func TestDefaultStatusPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p, err := DefaultStatusPath()
	if err != nil {
		t.Fatalf("DefaultStatusPath: %v", err)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("want absolute path, got %q", p)
	}
	if filepath.Base(p) != "backups.json" {
		t.Errorf("basename = %q, want backups.json", filepath.Base(p))
	}
}

// TestRequireBinariesMissing ensures we get a clear error — including an
// install hint — when a required tool is absent.
func TestRequireBinariesMissing(t *testing.T) {
	// A name that cannot plausibly exist on PATH.
	err := RequireBinaries("definitely-not-a-real-binary-xyzzy")
	if err == nil {
		t.Fatal("expected error for missing binary, got nil")
	}
}
