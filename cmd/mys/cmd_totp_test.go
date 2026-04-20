package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaschaHenning/my-secrets/internal/app"
	"github.com/SaschaHenning/my-secrets/internal/audit"
	"github.com/SaschaHenning/my-secrets/internal/policy"
	"github.com/SaschaHenning/my-secrets/internal/store"
	"github.com/SaschaHenning/my-secrets/internal/store/fake"
)

// TestBuildTOTPEntry_FromURI covers the happy path for parsing a full
// otpauth:// URI. The resulting store.Entry must carry the seed and all
// metadata defaulted from the URI when no CLI flag overrides them.
func TestBuildTOTPEntry_FromURI(t *testing.T) {
	uri := "otpauth://totp/GitHub:sascha?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
	e, err := buildTOTPEntry("jasp/github", uri, totpAddOptions{})
	if err != nil {
		t.Fatalf("buildTOTPEntry: %v", err)
	}
	if e.Kind != store.KindTOTP {
		t.Errorf("kind = %q", e.Kind)
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
	if e.TOTPAlgorithm != "SHA1" {
		t.Errorf("algorithm = %q", e.TOTPAlgorithm)
	}
	if e.TOTPDigits != 6 {
		t.Errorf("digits = %d", e.TOTPDigits)
	}
	if e.TOTPPeriod != 30 {
		t.Errorf("period = %d", e.TOTPPeriod)
	}
	if e.Org != "jasp" {
		t.Errorf("org = %q", e.Org)
	}
}

// TestBuildTOTPEntry_RawSeed ensures a raw base32 seed is accepted and
// that whitespace/lowercase forms are normalised.
func TestBuildTOTPEntry_RawSeed(t *testing.T) {
	e, err := buildTOTPEntry("jasp/github", "jbsw y3dp ehpk 3pxp", totpAddOptions{
		Issuer: "GitHub",
		Label:  "sascha",
	})
	if err != nil {
		t.Fatalf("buildTOTPEntry: %v", err)
	}
	if e.Password != "JBSWY3DPEHPK3PXP" {
		t.Errorf("seed = %q, want normalised upper", e.Password)
	}
	if e.TOTPIssuer != "GitHub" || e.TOTPLabel != "sascha" {
		t.Errorf("flags ignored: %+v", e)
	}
	if e.TOTPAlgorithm != "SHA1" || e.TOTPDigits != 6 || e.TOTPPeriod != 30 {
		t.Errorf("defaults missing: %+v", e)
	}
}

// TestBuildTOTPEntry_FlagOverrides ensures CLI flags take precedence
// over URI values when both are set.
func TestBuildTOTPEntry_FlagOverrides(t *testing.T) {
	uri := "otpauth://totp/GitHub:sascha?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
	e, err := buildTOTPEntry("jasp/github", uri, totpAddOptions{
		Issuer:    "OverrideCo",
		Label:     "other@example.com",
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	})
	if err != nil {
		t.Fatalf("buildTOTPEntry: %v", err)
	}
	if e.TOTPIssuer != "OverrideCo" {
		t.Errorf("issuer = %q, want OverrideCo", e.TOTPIssuer)
	}
	if e.TOTPLabel != "other@example.com" {
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

func TestBuildTOTPEntry_Errors(t *testing.T) {
	if _, err := buildTOTPEntry("x/y", "", totpAddOptions{}); err == nil {
		t.Error("want error on empty input")
	}
	if _, err := buildTOTPEntry("x/y", "otpauth://not-valid", totpAddOptions{}); err == nil {
		t.Error("want error on garbled uri")
	}
}

func TestFormatCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"487291", "487 291"},
		{"1234567", "123 4567"},
		{"12345678", "1234 5678"},
		{"123", "123"}, // unusual lengths untouched
	}
	for _, tc := range cases {
		if got := formatCode(tc.in); got != tc.want {
			t.Errorf("formatCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// totpTestApp wires the fake store into an *app.App with its own audit
// DB and a policy that grants the „claude-code" classification full
// access — otherwise the policy would deny private/** paths even in
// tests. See internal/app/app_test.go for the same pattern.
func totpTestApp(t *testing.T, entries ...*store.Entry) *app.App {
	t.Helper()
	l, err := audit.Open(filepath.Join(t.TempDir(), "audit.sqlite"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	pol := &policy.Policy{Actors: map[string]policy.Rules{
		"human":       {Allow: []string{"**"}},
		"script":      {Allow: []string{"**"}},
		"ai":          {Allow: []string{"**"}},
		"claude-code": {Allow: []string{"**"}},
	}}
	return &app.App{
		Store:    fake.NewWithEntries(entries...),
		Audit:    l,
		Policy:   pol,
		Override: "claude-code",
	}
}

// TestRunTOTPOnce_PrintsCodeAndMetadata exercises the bare
// `mys totp <path>` code path using a frozen time source. It asserts
// that the two-line format contains the path, issuer:label, a 6-digit
// code and a seconds-left marker.
func TestRunTOTPOnce_PrintsCodeAndMetadata(t *testing.T) {
	frozen := time.Unix(1700000000, 0)
	prev := nowFunc
	nowFunc = func() time.Time { return frozen }
	t.Cleanup(func() { nowFunc = prev })

	a := totpTestApp(t, &store.Entry{
		Path:          "jasp/github",
		Kind:          store.KindTOTP,
		Password:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:    "GitHub",
		TOTPLabel:     "sascha",
		TOTPAlgorithm: "SHA1",
		TOTPDigits:    6,
		TOTPPeriod:    30,
	})

	var buf bytes.Buffer
	if err := runTOTPOnce(context.Background(), a, "jasp/github", &buf); err != nil {
		t.Fatalf("runTOTPOnce: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "jasp/github") {
		t.Errorf("missing path in output: %q", out)
	}
	if !strings.Contains(out, "(GitHub:sascha)") {
		t.Errorf("missing issuer:label: %q", out)
	}
	if !strings.Contains(out, "s left)") {
		t.Errorf("missing seconds-left marker: %q", out)
	}
	// Must include a 6-digit code in "123 456" form.
	// We can't pin the exact code without re-implementing HOTP here, so
	// we assert the pattern: 3 digits, space, 3 digits.
	if !hasDigitGroup(out, 3, 3) {
		t.Errorf("no '### ###' code group in output: %q", out)
	}
	// Audit row written.
	rows, _ := a.Audit.Tail(context.Background(), audit.Filter{Action: audit.ActionTOTPGenerate, Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("want one totp_generate row, got %d", len(rows))
	}
	if rows[0].Result != audit.ResultOK {
		t.Errorf("result = %q", rows[0].Result)
	}
}

// hasDigitGroup reports whether s contains a run of len1 digits, a
// single space, then len2 digits. A tiny scanner — pulling in regexp
// for a three-char match felt excessive.
func hasDigitGroup(s string, len1, len2 int) bool {
	runes := []rune(s)
	for i := 0; i+len1+1+len2 <= len(runes); i++ {
		ok := true
		for j := 0; j < len1; j++ {
			if runes[i+j] < '0' || runes[i+j] > '9' {
				ok = false
				break
			}
		}
		if !ok || runes[i+len1] != ' ' {
			continue
		}
		ok = true
		for j := 0; j < len2; j++ {
			r := runes[i+len1+1+j]
			if r < '0' || r > '9' {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TestRunTOTPOnce_NonTOTPReturnsError confirms a non-TOTP entry bubbles
// up as an error instead of printing garbage.
func TestRunTOTPOnce_NonTOTPReturnsError(t *testing.T) {
	a := totpTestApp(t, &store.Entry{
		Path: "jasp/plain", Kind: store.KindPassword, Password: "p",
	})
	var buf bytes.Buffer
	if err := runTOTPOnce(context.Background(), a, "jasp/plain", &buf); err == nil {
		t.Fatal("want error for non-totp entry")
	} else if !strings.Contains(err.Error(), "not a totp entry") {
		t.Errorf("error = %v", err)
	}
}
