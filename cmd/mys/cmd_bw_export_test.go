package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/bw"
	"github.com/SaschaHenning/my-secrets/internal/store"
)

func TestBwExportCmd_RequiresBothConfirmFlags(t *testing.T) {
	req := "human"
	for _, args := range [][]string{
		{},
		{"--reveal"},
		{"--i-understand"},
	} {
		c := bwExportCmd(&req)
		c.SetArgs(args)
		c.SetOut(&bytes.Buffer{})
		c.SetErr(&bytes.Buffer{})
		if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "--reveal and --i-understand") {
			t.Errorf("args %v: err = %v, want confirm-flags refusal", args, err)
		}
	}
}

func TestBwExportCmd_RefusesAICallersAndAuditsIt(t *testing.T) {
	// Route the refusal audit row into an isolated log instead of the
	// developer's real DB. The command closes the App it opens, so the
	// stub hands out a dedicated handle and the assertion re-opens the
	// same file afterwards.
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	prev := openAuditOnly
	openAuditOnly = func() (*app.App, error) {
		l, err := audit.Open(dbPath)
		if err != nil {
			return nil, err
		}
		return &app.App{Audit: l, Override: "ai"}, nil
	}
	t.Cleanup(func() { openAuditOnly = prev })

	req := "ai"
	c := bwExportCmd(&req)
	c.SetArgs([]string{"--reveal", "--i-understand"})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "refused for AI callers") {
		t.Errorf("err = %v, want AI refusal", err)
	}
	l, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen audit: %v", err)
	}
	defer l.Close()
	rows, err := l.Tail(context.Background(), audit.Filter{Action: audit.ActionExport})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied {
		t.Fatalf("rows = %+v, want exactly one denied export row", rows)
	}
}

func TestRunBwExport_WritesSummaryAuditRow(t *testing.T) {
	a := fakeApp(t, &store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"})
	var stdout, stderr bytes.Buffer
	if err := runBwExport(context.Background(), a, &stdout, &stderr, "jasp", ""); err != nil {
		t.Fatalf("runBwExport: %v", err)
	}
	rows, err := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionExport})
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(rows) != 1 || rows[0].Result != audit.ResultOK {
		t.Fatalf("rows = %+v, want exactly one ok export row", rows)
	}
	if !strings.Contains(rows[0].Reason, "count=1") || !strings.Contains(rows[0].Reason, "dest=stdout") {
		t.Errorf("reason = %q, want dest + count", rows[0].Reason)
	}
}

func TestRunBwExport_EmitsImportablePayload(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{
			Path:     "jasp/stage/api-key",
			Org:      "jasp",
			Kind:     store.KindAPIKey,
			Username: "svc",
			URL:      "https://api.jasp.eu",
			Password: "k3y",
		},
		&store.Entry{
			Path:          "zuhause/github-2fa",
			Org:           "zuhause",
			Kind:          store.KindTOTP,
			Password:      "JBSWY3DPEHPK3PXP",
			TOTPIssuer:    "GitHub",
			TOTPLabel:     "sascha",
			TOTPAlgorithm: "SHA1",
		},
	)
	var stdout, stderr bytes.Buffer
	if err := runBwExport(context.Background(), a, &stdout, &stderr, "", ""); err != nil {
		t.Fatalf("runBwExport: %v", err)
	}
	var payload bw.Export
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if payload.Encrypted {
		t.Error("encrypted must be false")
	}
	if len(payload.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(payload.Items))
	}
	folderIDs := map[string]bool{}
	for _, f := range payload.Folders {
		folderIDs[f.ID] = true
		if !strings.HasPrefix(f.Name, bw.FolderPrefix) {
			t.Errorf("folder %q outside the %s/ namespace", f.Name, bw.FolderPrefix)
		}
	}
	for _, it := range payload.Items {
		if it.Type != bw.TypeLogin {
			t.Errorf("item %q type = %d, want %d", it.Name, it.Type, bw.TypeLogin)
		}
		if !folderIDs[it.FolderID] {
			t.Errorf("item %q references undeclared folder %q", it.Name, it.FolderID)
		}
	}
}

func TestRunBwExport_SkipsUnmappableEntries(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/good", Org: "jasp", Password: "x"},
		&store.Entry{
			// Unsupported TOTP algorithm — must be skipped with a
			// warning, not abort the whole export.
			Path: "jasp/legacy-2fa", Org: "jasp", Kind: store.KindTOTP,
			Password: "JBSWY3DPEHPK3PXP", TOTPAlgorithm: "MD5",
		},
	)
	var stdout, stderr bytes.Buffer
	if err := runBwExport(context.Background(), a, &stdout, &stderr, "", ""); err != nil {
		t.Fatalf("runBwExport: %v", err)
	}
	var payload bw.Export
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Name != "good" {
		t.Fatalf("items = %+v, want only jasp/good", payload.Items)
	}
	if !strings.Contains(stderr.String(), "skip jasp/legacy-2fa") {
		t.Errorf("stderr = %q, want skip warning for legacy-2fa", stderr.String())
	}
}

func TestRunBwExport_OrgFilter(t *testing.T) {
	a := fakeApp(t,
		&store.Entry{Path: "jasp/a", Org: "jasp", Password: "x"},
		&store.Entry{Path: "zuhause/b", Org: "zuhause", Password: "y"},
	)
	var stdout, stderr bytes.Buffer
	if err := runBwExport(context.Background(), a, &stdout, &stderr, "jasp", ""); err != nil {
		t.Fatalf("runBwExport: %v", err)
	}
	var payload bw.Export
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Name != "a" {
		t.Fatalf("items = %+v, want exactly jasp/a as %q", payload.Items, "a")
	}
}
