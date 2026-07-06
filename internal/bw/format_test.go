package bw

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files")

func testEntries() []*store.Entry {
	return []*store.Entry{
		{
			Path:          "jasp/stage/jwt-access-secret",
			Org:           "jasp",
			Kind:          store.KindToken,
			Username:      "svc-stage",
			URL:           "https://stage.jasp.eu",
			Domain:        "stage.jasp.eu",
			GitHubProject: "JASP-eu/congplan",
			Tags:          []string{"stage", "jwt"},
			Notes:         "rotates with each deploy",
			Password:      "s3cr3t-token",
			RotateAfter:   "90d",
			Fields: map[string]string{
				"region":     "eu-central-1",
				"api_secret": "extra-s3cr3t",
			},
		},
		{
			// Org intentionally empty — must be derived from the path.
			Path:          "zuhause/github-2fa",
			Kind:          store.KindTOTP,
			Password:      "JBSWY3DPEHPK3PXP",
			TOTPIssuer:    "GitHub",
			TOTPLabel:     "sascha",
			TOTPAlgorithm: "SHA1",
			TOTPDigits:    6,
			TOTPPeriod:    30,
		},
		{
			Path:     "toplevel-note",
			Kind:     store.KindPassword,
			Password: "hunter2",
		},
	}
}

func TestBuildExport_Golden(t *testing.T) {
	exp, err := BuildExport(testEntries())
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	got, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "export_golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("export payload drifted from golden file.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestBuildExport_FolderRefsResolve(t *testing.T) {
	exp, err := BuildExport(testEntries())
	if err != nil {
		t.Fatalf("BuildExport: %v", err)
	}
	ids := map[string]string{}
	for _, f := range exp.Folders {
		ids[f.ID] = f.Name
	}
	if len(ids) != 3 {
		t.Fatalf("folders = %d, want 3 (mys, mys/jasp, mys/zuhause)", len(ids))
	}
	for _, it := range exp.Items {
		if it.Type != TypeLogin {
			t.Errorf("item %q type = %d, want %d", it.Name, it.Type, TypeLogin)
		}
		if _, ok := ids[it.FolderID]; !ok {
			t.Errorf("item %q folderId %q not declared in folders", it.Name, it.FolderID)
		}
		if len(it.Fields) == 0 || it.Fields[0].Name != FieldPath {
			t.Errorf("item %q must carry %s as first custom field", it.Name, FieldPath)
		}
	}
}

func TestFolderID_Deterministic(t *testing.T) {
	a, b := FolderID("mys/jasp"), FolderID("mys/jasp")
	if a != b {
		t.Fatalf("FolderID not deterministic: %q vs %q", a, b)
	}
	if a == FolderID("mys/zuhause") {
		t.Fatal("distinct folder names must yield distinct ids")
	}
}

func TestItemFromEntry_TOTP(t *testing.T) {
	e := &store.Entry{
		Path:       "zuhause/github-2fa",
		Org:        "zuhause",
		Kind:       store.KindTOTP,
		Password:   "JBSWY3DPEHPK3PXP",
		TOTPIssuer: "GitHub",
	}
	it, err := ItemFromEntry(e)
	if err != nil {
		t.Fatalf("ItemFromEntry: %v", err)
	}
	if it.Login.Password != "" {
		t.Error("TOTP entry must not fill login.password")
	}
	if !strings.HasPrefix(it.Login.TOTP, "otpauth://totp/") {
		t.Errorf("login.totp = %q, want otpauth URI", it.Login.TOTP)
	}
	if !strings.Contains(it.Login.TOTP, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("login.totp %q missing seed", it.Login.TOTP)
	}
}

func TestItemFromEntry_BadTOTPAlgorithmFails(t *testing.T) {
	e := &store.Entry{
		Path:          "zuhause/broken",
		Org:           "zuhause",
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPAlgorithm: "MD5",
	}
	if _, err := ItemFromEntry(e); err == nil {
		t.Fatal("want error for unsupported TOTP algorithm")
	}
}

func TestMetadataFields_ExportsEntryFields(t *testing.T) {
	e := &store.Entry{
		Path: "jasp/x", Org: "jasp", Password: "p",
		Fields: map[string]string{"api_secret": "v1", "region": "eu"},
	}
	it, err := ItemFromEntry(e)
	if err != nil {
		t.Fatalf("ItemFromEntry: %v", err)
	}
	got := map[string]int{}
	for _, f := range it.Fields {
		got[f.Name] = f.Type
	}
	if typ, ok := got["field.api_secret"]; !ok || typ != FieldHidden {
		t.Errorf("field.api_secret = (%d, %v), want hidden custom field", typ, ok)
	}
	if typ, ok := got["field.region"]; !ok || typ != FieldText {
		t.Errorf("field.region = (%d, %v), want text custom field", typ, ok)
	}
}

func TestItemFromEntry_EmptyTOTPSeedFails(t *testing.T) {
	e := &store.Entry{Path: "zuhause/empty", Org: "zuhause", Kind: store.KindTOTP}
	if _, err := ItemFromEntry(e); err == nil {
		t.Fatal("want error for empty totp seed")
	}
}

func TestItemName_StripsOrgPrefix(t *testing.T) {
	e := &store.Entry{Path: "jasp/stage/jwt", Org: "jasp"}
	if got := ItemName(e); got != "stage/jwt" {
		t.Errorf("ItemName = %q, want %q", got, "stage/jwt")
	}
}
