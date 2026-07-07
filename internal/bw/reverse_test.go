package bw

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SaschaHenning/my-secrets/internal/store"
)

func TestEntryFromItem_RoundtripPassword(t *testing.T) {
	orig := &store.Entry{
		Path:          "jasp/svc",
		Org:           "jasp",
		Kind:          store.KindPassword,
		Username:      "u",
		URL:           "https://x.example",
		Notes:         "note",
		Password:      "pw",
		RotateAfter:   "90d",
		Tags:          []string{"a", "b"},
		Domain:        "x.example",
		GitHubProject: "org/repo",
		Fields:        map[string]string{"region": "eu", "api_secret": "s"},
	}
	it, err := ItemFromEntry(orig)
	if err != nil {
		t.Fatalf("ItemFromEntry: %v", err)
	}
	got, err := EntryFromItem(it, FolderName("jasp"))
	if err != nil {
		t.Fatalf("EntryFromItem: %v", err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Errorf("roundtrip mismatch:\ngot  %+v\nwant %+v", got, orig)
	}
}

func TestEntryFromItem_RoundtripTOTP(t *testing.T) {
	orig := &store.Entry{
		Path:          "zuhause/otp",
		Org:           "zuhause",
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:    "GitHub",
		TOTPLabel:     "me",
		TOTPAlgorithm: "SHA256",
		TOTPDigits:    8,
		TOTPPeriod:    60,
	}
	it, err := ItemFromEntry(orig)
	if err != nil {
		t.Fatalf("ItemFromEntry: %v", err)
	}
	got, err := EntryFromItem(it, FolderName("zuhause"))
	if err != nil {
		t.Fatalf("EntryFromItem: %v", err)
	}
	if !reflect.DeepEqual(got, orig) {
		t.Errorf("roundtrip mismatch:\ngot  %+v\nwant %+v", got, orig)
	}
}

func TestEntryFromItem_ForeignCustomFieldKept(t *testing.T) {
	it := Item{
		Type: TypeLogin,
		Name: "router",
		Fields: []Field{
			{Name: "wifi_code", Value: "1234", Type: FieldText},
		},
		Login: &Login{Password: "pw"},
	}
	e, err := EntryFromItem(it, "mys/zuhause")
	if err != nil {
		t.Fatalf("EntryFromItem: %v", err)
	}
	if e.Fields["wifi_code"] != "1234" {
		t.Errorf("hand-added Bitwarden field must survive as a structured extra, got %+v", e.Fields)
	}
}

func TestEntryFromItem_RejectsNonLogin(t *testing.T) {
	if _, err := EntryFromItem(Item{Type: 2, Name: "note"}, "mys"); err == nil {
		t.Error("non-login item must be rejected")
	}
}

func TestEntryFromItem_RejectsBadTOTPURI(t *testing.T) {
	it := Item{Type: TypeLogin, Name: "x", Login: &Login{TOTP: "otpauth://hotp/x?secret=A"}}
	if _, err := EntryFromItem(it, "mys"); err == nil {
		t.Error("unparseable totp uri must be rejected")
	}
}

func TestPathForItem(t *testing.T) {
	withKey := Item{Fields: []Field{{Name: FieldPath, Value: "jasp/moved"}}, Name: "other"}
	cases := []struct {
		name   string
		item   Item
		folder string
		want   string
	}{
		{"mys-path wins", withKey, "mys/zuhause", "jasp/moved"},
		{"phone item derives org/name", Item{Name: "router"}, "mys/zuhause", "zuhause/router"},
		{"bare mys root maps to top-level", Item{Name: "solo"}, "mys", "solo"},
	}
	for _, c := range cases {
		if got := PathForItem(c.item, c.folder); got != c.want {
			t.Errorf("%s: PathForItem = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMergeEntry_AppliesOnlyChangedFields(t *testing.T) {
	existing := &store.Entry{
		Path: "jasp/a", Org: "jasp", Kind: store.KindPassword,
		Username: "store-user", Password: "store-pw", URL: "https://old",
		Notes: "store-note", RotateAfter: "90d",
		Fields: map[string]string{"region": "eu", "tier": "prod"},
	}
	incoming := &store.Entry{
		Path: "jasp/a", Username: "bw-user", Password: "bw-pw",
		URL: "https://new", Notes: "bw-note",
		Fields: map[string]string{"region": "us"},
	}
	got := MergeEntry(existing, incoming, []string{"password", "field.region"})
	if got.Password != "bw-pw" || got.Fields["region"] != "us" {
		t.Errorf("changed fields not applied: %+v", got)
	}
	if got.Username != "store-user" || got.URL != "https://old" || got.Notes != "store-note" {
		t.Errorf("un-diffed fields must keep store values: %+v", got)
	}
	if got.RotateAfter != "90d" || got.Fields["tier"] != "prod" {
		t.Errorf("store-only metadata must survive: %+v", got)
	}
	if existing.Password != "store-pw" || existing.Fields["region"] != "eu" {
		t.Errorf("existing entry must not be mutated: %+v", existing)
	}
}

func TestMergeEntry_DeletesRemovedField(t *testing.T) {
	existing := &store.Entry{Path: "jasp/a", Fields: map[string]string{"region": "eu"}}
	incoming := &store.Entry{Path: "jasp/a"}
	got := MergeEntry(existing, incoming, []string{"field.region"})
	if _, ok := got.Fields["region"]; ok {
		t.Errorf("field removed in Bitwarden must be deleted on merge: %+v", got.Fields)
	}
}

func TestMergeEntry_TOTPSwitchCarriesAllParameters(t *testing.T) {
	existing := &store.Entry{Path: "jasp/a", Kind: store.KindPassword, Password: "pw"}
	incoming := &store.Entry{
		Path: "jasp/a", Kind: store.KindTOTP, Password: "SEED",
		TOTPIssuer: "I", TOTPLabel: "L", TOTPAlgorithm: "SHA256", TOTPDigits: 8, TOTPPeriod: 60,
	}
	got := MergeEntry(existing, incoming, []string{"totp"})
	if got.Kind != store.KindTOTP || got.Password != "SEED" ||
		got.TOTPIssuer != "I" || got.TOTPLabel != "L" ||
		got.TOTPAlgorithm != "SHA256" || got.TOTPDigits != 8 || got.TOTPPeriod != 60 {
		t.Errorf("totp switch must carry the full parameter set: %+v", got)
	}
}

func TestChangedFields_NamesOnlySorted(t *testing.T) {
	stored := &store.Entry{
		Path: "jasp/a", Username: "u1", Password: "p1", URL: "https://a",
		Notes: "n1", Fields: map[string]string{"region": "eu", "gone": "x"},
	}
	incoming := &store.Entry{
		Path: "jasp/a", Username: "u2", Password: "p2", URL: "https://b",
		Notes: "n2", Fields: map[string]string{"region": "us", "added": "y"},
	}
	got := ChangedFields(stored, incoming)
	want := []string{"field.added", "field.gone", "field.region", "notes", "password", "url", "username"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ChangedFields = %v, want %v", got, want)
	}
	for _, name := range got {
		if strings.Contains(name, "p1") || strings.Contains(name, "p2") {
			t.Errorf("changed list must carry names only: %v", got)
		}
	}
}

func TestChangedFields_InSyncAfterMirrorRoundtrip(t *testing.T) {
	// A pushed entry read back through the reverse mapping must diff
	// empty — including TOTP entries relying on defaults (label from the
	// item name, SHA1/6/30 parameters made explicit by the otpauth URI).
	entries := []*store.Entry{
		{Path: "jasp/svc", Org: "jasp", Kind: store.KindPassword, Username: "u", Password: "pw",
			URL: "https://x.example", Domain: "x.example", Fields: map[string]string{"region": "eu"}},
		{Path: "zuhause/otp", Org: "zuhause", Kind: store.KindTOTP, Password: "JBSWY3DPEHPK3PXP"},
	}
	for _, orig := range entries {
		it, err := ItemFromEntry(orig)
		if err != nil {
			t.Fatalf("%s: ItemFromEntry: %v", orig.Path, err)
		}
		incoming, err := EntryFromItem(it, FolderName(orig.Org))
		if err != nil {
			t.Fatalf("%s: EntryFromItem: %v", orig.Path, err)
		}
		if diff := ChangedFields(orig, incoming); len(diff) != 0 {
			t.Errorf("%s: roundtrip must be in sync, got changes %v", orig.Path, diff)
		}
	}
}

func TestChangedFields_TOTPParameterChangeFlagsTOTP(t *testing.T) {
	stored := &store.Entry{Path: "z/otp", Kind: store.KindTOTP, Password: "SEED", TOTPLabel: "otp"}
	incoming := &store.Entry{Path: "z/otp", Kind: store.KindTOTP, Password: "NEWSEED", TOTPLabel: "otp"}
	if got := ChangedFields(stored, incoming); !reflect.DeepEqual(got, []string{"totp"}) {
		t.Errorf("ChangedFields = %v, want [totp]", got)
	}
}
