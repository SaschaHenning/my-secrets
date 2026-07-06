package totp

import (
	"strings"
	"testing"

	"github.com/pquerna/otp"
)

func TestBuildURI_RoundTripsThroughParseURI(t *testing.T) {
	in := Entry{
		Seed:      "JBSWY3DPEHPK3PXP",
		Issuer:    "GitHub",
		Label:     "sascha@example.com",
		Algorithm: otp.AlgorithmSHA256,
		Digits:    otp.DigitsEight,
		Period:    60,
	}
	uri := BuildURI(in)
	got, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI(%q): %v", uri, err)
	}
	if got.Seed != in.Seed {
		t.Errorf("seed = %q, want %q", got.Seed, in.Seed)
	}
	if got.Issuer != in.Issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer, in.Issuer)
	}
	if got.Label != in.Label {
		t.Errorf("label = %q, want %q", got.Label, in.Label)
	}
	if got.Algorithm != in.Algorithm {
		t.Errorf("algorithm = %v, want %v", got.Algorithm, in.Algorithm)
	}
	if got.Digits != in.Digits {
		t.Errorf("digits = %v, want %v", got.Digits, in.Digits)
	}
	if got.Period != in.Period {
		t.Errorf("period = %d, want %d", got.Period, in.Period)
	}
}

func TestBuildURI_DefaultsAreExplicit(t *testing.T) {
	uri := BuildURI(Entry{Seed: "jbswy3dpehpk3pxp", Label: "acct"})
	for _, want := range []string{"algorithm=SHA1", "digits=6", "period=30", "secret=JBSWY3DPEHPK3PXP"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri %q missing %q", uri, want)
		}
	}
	if strings.Contains(uri, "issuer=") {
		t.Errorf("uri %q must not carry an issuer parameter", uri)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/acct?") {
		t.Errorf("uri %q must use the bare label as path", uri)
	}
}

func TestBuildURI_EscapesSlashInLabel(t *testing.T) {
	uri := BuildURI(Entry{Seed: "JBSWY3DPEHPK3PXP", Label: "stage/2fa"})
	if !strings.HasPrefix(uri, "otpauth://totp/stage%2F2fa?") {
		t.Errorf("uri %q: slash in label must be escaped as a single path segment", uri)
	}
	got, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if got.Label != "stage/2fa" {
		t.Errorf("label round trip = %q, want %q", got.Label, "stage/2fa")
	}
}

func TestBuildURI_IssuerPrefixesLabel(t *testing.T) {
	uri := BuildURI(Entry{Seed: "JBSWY3DPEHPK3PXP", Issuer: "My Corp", Label: "me@corp.eu"})
	if !strings.HasPrefix(uri, "otpauth://totp/My%20Corp:me@corp.eu?") {
		t.Errorf("uri %q: want escaped issuer-prefixed label", uri)
	}
	if !strings.Contains(uri, "issuer=My+Corp") {
		t.Errorf("uri %q: want issuer query parameter", uri)
	}
}
