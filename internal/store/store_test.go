package store

import (
	"reflect"
	"testing"

	"github.com/gopasspw/gopass/pkg/gopass/secrets"
)

func TestOrgOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"jasp/github", "jasp"},
		{"zuhause/proxmox/root", "zuhause"},
		{"top-level", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := OrgOf(tc.in); got != tc.want {
			t.Errorf("OrgOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskedPassword(t *testing.T) {
	if MaskedPassword("") != "" {
		t.Error("empty input should produce empty masked output")
	}
	if m := MaskedPassword("secret"); m != "******" {
		t.Errorf("MaskedPassword(\"secret\") = %q, want \"******\"", m)
	}
}

// TestInterfaceAssertion is a compile-time check that *Store satisfies
// Interface. The var _ declaration does the same thing at compile time, but
// a runtime check gives nicer error messages should the Interface drift.
func TestInterfaceAssertion(t *testing.T) {
	var _ Interface = (*Store)(nil)
}

// buildSecret constructs a gopass.Secret in memory (no GPG required).
func buildSecret(password string, kv map[string]string) *secrets.AKV {
	sec := secrets.NewAKV()
	sec.SetPassword(password)
	for k, v := range kv {
		_ = sec.Set(k, v)
	}
	return sec
}

func TestEntryFromSecret(t *testing.T) {
	sec := buildSecret("p1", map[string]string{
		"username":       "alice",
		"url":            "https://example.com",
		"kind":           KindAPIKey,
		"github_project": "owner/repo",
		"notes":          "primary",
		"tags":           "one, two , three",
	})
	e := entryFromSecret("jasp/github", sec)
	if e.Path != "jasp/github" || e.Org != "jasp" {
		t.Errorf("path/org = %q/%q", e.Path, e.Org)
	}
	if e.Password != "p1" {
		t.Errorf("password = %q", e.Password)
	}
	if e.Username != "alice" || e.URL != "https://example.com" || e.Kind != KindAPIKey {
		t.Errorf("metadata not copied: %+v", e)
	}
	if e.GitHubProject != "owner/repo" {
		t.Errorf("github_project = %q", e.GitHubProject)
	}
	if e.Notes != "primary" {
		t.Errorf("notes = %q", e.Notes)
	}
	if !reflect.DeepEqual(e.Tags, []string{"one", "two", "three"}) {
		t.Errorf("tags = %v", e.Tags)
	}
}

func TestEntryFromSecret_EmptyMetadata(t *testing.T) {
	// A freshly-created secret with just a password produces an entry with
	// empty metadata fields.
	sec := buildSecret("pw-only", nil)
	e := entryFromSecret("toplevel", sec)
	if e.Path != "toplevel" || e.Org != "" {
		t.Errorf("path/org = %q/%q", e.Path, e.Org)
	}
	if e.Password != "pw-only" {
		t.Errorf("password = %q", e.Password)
	}
	if e.Username != "" || e.URL != "" || e.Kind != "" || e.GitHubProject != "" ||
		e.Notes != "" || e.Tags != nil {
		t.Errorf("unexpected metadata: %+v", e)
	}
}

func TestSecretMatches(t *testing.T) {
	sec := buildSecret("shh", map[string]string{
		"username": "alice",
		"url":      "https://example.com",
		"notes":    "primary account",
	})
	// secretMatches expects its query pre-lowercased (contract with the
	// caller Search(), which lowercases before invoking).
	cases := []struct {
		q    string
		want bool
	}{
		{"alice", true},    // matches username value
		{"username", true}, // matches a key name
		{"primary", true},  // matches notes value
		{"does-not-match", false},
		{"example", true}, // matches url value
	}
	for _, tc := range cases {
		if got := secretMatches(sec, tc.q); got != tc.want {
			t.Errorf("secretMatches(%q) = %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestSecretMatches_Nil(t *testing.T) {
	if secretMatches(nil, "anything") {
		t.Error("nil secret must never match")
	}
}

func TestSetIfNotEmpty(t *testing.T) {
	sec := secrets.NewAKV()
	setIfNotEmpty(sec, "k", "")
	if _, ok := sec.Get("k"); ok {
		t.Error("empty value must not be set")
	}
	setIfNotEmpty(sec, "k", "v")
	if v, _ := sec.Get("k"); v != "v" {
		t.Errorf("Get(k) = %q, want v", v)
	}
}

func TestEntryFromSecret_TOTPFields(t *testing.T) {
	sec := buildSecret("JBSWY3DPEHPK3PXP", map[string]string{
		"kind":           KindTOTP,
		"totp_issuer":    "GitHub",
		"totp_label":     "sascha",
		"totp_algorithm": "SHA256",
		"totp_digits":    "8",
		"totp_period":    "60",
	})
	e := entryFromSecret("jasp/github-2fa", sec)
	if e.Kind != KindTOTP {
		t.Errorf("kind = %q, want totp", e.Kind)
	}
	if e.Password != "JBSWY3DPEHPK3PXP" {
		t.Errorf("seed = %q", e.Password)
	}
	if e.TOTPIssuer != "GitHub" {
		t.Errorf("issuer = %q", e.TOTPIssuer)
	}
	if e.TOTPLabel != "sascha" {
		t.Errorf("label = %q", e.TOTPLabel)
	}
	if e.TOTPAlgorithm != "SHA256" {
		t.Errorf("algorithm = %q", e.TOTPAlgorithm)
	}
	if e.TOTPDigits != 8 {
		t.Errorf("digits = %d", e.TOTPDigits)
	}
	if e.TOTPPeriod != 60 {
		t.Errorf("period = %d", e.TOTPPeriod)
	}
}

func TestEntryFromSecret_TOTPFieldsMissing(t *testing.T) {
	// A regular (non-TOTP) entry must leave all TOTP fields zero.
	sec := buildSecret("p1", map[string]string{
		"username": "alice",
		"kind":     KindPassword,
	})
	e := entryFromSecret("jasp/github", sec)
	if e.TOTPIssuer != "" || e.TOTPLabel != "" || e.TOTPAlgorithm != "" ||
		e.TOTPDigits != 0 || e.TOTPPeriod != 0 {
		t.Errorf("TOTP fields leaked on non-TOTP entry: %+v", e)
	}
}

func TestEntryFromSecret_DomainAndFields(t *testing.T) {
	sec := buildSecret("p1", map[string]string{
		"username":         "alice",
		"domain":           "aws.amazon.com",
		"field.account_id": "123456",
		"field.region":     "eu-central-1",
		"field.api_secret": "do-not-leak",
	})
	e := entryFromSecret("jasp/aws", sec)
	if e.Domain != "aws.amazon.com" {
		t.Errorf("domain = %q, want aws.amazon.com", e.Domain)
	}
	if len(e.Fields) != 3 {
		t.Fatalf("fields = %+v", e.Fields)
	}
	if e.Fields["account_id"] != "123456" {
		t.Errorf("account_id = %q", e.Fields["account_id"])
	}
	if e.Fields["region"] != "eu-central-1" {
		t.Errorf("region = %q", e.Fields["region"])
	}
	if e.Fields["api_secret"] != "do-not-leak" {
		t.Errorf("api_secret value must be preserved on read: %q", e.Fields["api_secret"])
	}
}

func TestSecretMatches_SecretLikeFieldValueHidden(t *testing.T) {
	sec := buildSecret("shh", map[string]string{
		"username":         "alice",
		"field.account_id": "12345",
		"field.api_secret": "leaky-value",
	})
	// The account_id VALUE is searchable.
	if !secretMatches(sec, "12345") {
		t.Error("account_id value should match")
	}
	// The api_secret VALUE must NOT be searchable.
	if secretMatches(sec, "leaky-value") {
		t.Error("api_secret value leaked through search")
	}
	// The api_secret KEY still matches.
	if !secretMatches(sec, "api_secret") {
		t.Error("api_secret key name should match")
	}
}

func TestIsSecretLikeFieldKey(t *testing.T) {
	secretLike := []string{
		"password", "field.password", "db_password",
		"secret", "api_secret", "client_secret",
		"token", "access_token", "refresh_token",
		"api_key", "apikey",
		"private_key", "privatekey",
		"credential", "credentials",
	}
	for _, k := range secretLike {
		if !IsSecretLikeFieldKey(k) {
			t.Errorf("IsSecretLikeFieldKey(%q) = false, want true", k)
		}
	}
	safe := []string{"account_id", "region", "tenant", "username", "url", "notes"}
	for _, k := range safe {
		if IsSecretLikeFieldKey(k) {
			t.Errorf("IsSecretLikeFieldKey(%q) = true, want false", k)
		}
	}
}

// Close on a nil Store must not panic.
func TestStore_Close_Nil(t *testing.T) {
	var s *Store
	if err := s.Close(nil); err != nil {
		t.Errorf("close on nil store: %v", err)
	}
	s2 := &Store{}
	if err := s2.Close(nil); err != nil {
		t.Errorf("close on zero store: %v", err)
	}
}
