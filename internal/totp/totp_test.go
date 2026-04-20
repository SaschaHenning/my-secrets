package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
)

func TestParseURI(t *testing.T) {
	uri := "otpauth://totp/GitHub:sascha?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
	e, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if e.Seed != "JBSWY3DPEHPK3PXP" {
		t.Errorf("seed = %q", e.Seed)
	}
	if e.Issuer != "GitHub" {
		t.Errorf("issuer = %q", e.Issuer)
	}
	if e.Label != "sascha" {
		t.Errorf("label = %q", e.Label)
	}
	if e.Algorithm != otp.AlgorithmSHA1 {
		t.Errorf("algorithm = %v", e.Algorithm)
	}
	if e.Digits != otp.DigitsSix {
		t.Errorf("digits = %v", e.Digits)
	}
	if e.Period != 30 {
		t.Errorf("period = %d", e.Period)
	}
}

func TestParseURI_ErrorsForNonTOTP(t *testing.T) {
	if _, err := ParseURI(""); err == nil {
		t.Error("want error for empty uri")
	}
	if _, err := ParseURI("otpauth://hotp/x?secret=ABCDEFGH&issuer=X"); err == nil {
		t.Error("want error for hotp uri")
	}
	if _, err := ParseURI("https://example.com"); err == nil {
		t.Error("want error for non-otpauth scheme")
	}
	// Missing secret is a hard error, even via fallback.
	if _, err := ParseURI("otpauth://totp/X:y?issuer=X"); err == nil {
		t.Error("want error for missing secret")
	}
}

func TestParseURI_FallbackNoIssuerQuery(t *testing.T) {
	// NewKeyFromURL rejects URIs without an `issuer` query; the manual
	// fallback must pick the issuer out of the label path.
	uri := "otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP"
	e, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("fallback parse: %v", err)
	}
	if e.Issuer != "Acme" {
		t.Errorf("fallback issuer = %q, want Acme", e.Issuer)
	}
	if e.Label != "bob" {
		t.Errorf("fallback label = %q, want bob", e.Label)
	}
	if e.Seed != "JBSWY3DPEHPK3PXP" {
		t.Errorf("fallback seed = %q", e.Seed)
	}
}

// TestGenerateCode_RFC6238 exercises the Appendix B test vectors. The
// shared secret is the ASCII string "12345678901234567890" (and its
// longer 32-byte / 64-byte variants for SHA256 / SHA512) encoded as
// base32. Expected codes are published at 8 digits in the RFC.
func TestGenerateCode_RFC6238(t *testing.T) {
	const (
		sha1Seed   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		sha256Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
		sha512Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
	)
	cases := []struct {
		name string
		seed string
		alg  otp.Algorithm
		t    int64
		want string
	}{
		{"SHA1/T=59", sha1Seed, otp.AlgorithmSHA1, 59, "94287082"},
		{"SHA1/T=1111111109", sha1Seed, otp.AlgorithmSHA1, 1111111109, "07081804"},
		{"SHA1/T=1111111111", sha1Seed, otp.AlgorithmSHA1, 1111111111, "14050471"},
		{"SHA1/T=1234567890", sha1Seed, otp.AlgorithmSHA1, 1234567890, "89005924"},
		{"SHA256/T=59", sha256Seed, otp.AlgorithmSHA256, 59, "46119246"},
		{"SHA256/T=1111111109", sha256Seed, otp.AlgorithmSHA256, 1111111109, "68084774"},
		{"SHA512/T=59", sha512Seed, otp.AlgorithmSHA512, 59, "90693936"},
		{"SHA512/T=1111111109", sha512Seed, otp.AlgorithmSHA512, 1111111109, "25091201"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, secondsLeft, err := GenerateCode(tc.seed, Options{
				Algorithm: tc.alg,
				Digits:    otp.DigitsEight,
				Period:    30,
			}, time.Unix(tc.t, 0))
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			if got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
			if secondsLeft < 1 || secondsLeft > 30 {
				t.Errorf("secondsLeft = %d, want 1..30", secondsLeft)
			}
		})
	}
}

func TestGenerateCode_Determinism(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1700000000, 0)
	c1, s1, err := GenerateCode(seed, DefaultOptions(), now)
	if err != nil {
		t.Fatal(err)
	}
	c2, s2, err := GenerateCode(seed, DefaultOptions(), now)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Errorf("deterministic generate returned different codes: %q vs %q", c1, c2)
	}
	if s1 != s2 {
		t.Errorf("secondsLeft deterministic: %d vs %d", s1, s2)
	}
	if len(c1) != 6 {
		t.Errorf("default digits = %d, want 6", len(c1))
	}
	// Only digits.
	for _, r := range c1 {
		if r < '0' || r > '9' {
			t.Fatalf("code %q contains non-digit rune %q", c1, r)
		}
	}
}

func TestGenerateCode_SecondsLeft(t *testing.T) {
	const seed = "JBSWY3DPEHPK3PXP"
	// At exactly the start of a window the full period should remain.
	_, secs, err := GenerateCode(seed, DefaultOptions(), time.Unix(30, 0))
	if err != nil {
		t.Fatal(err)
	}
	if secs != 30 {
		t.Errorf("secondsLeft at window start = %d, want 30", secs)
	}
	// Partway through — 7 seconds consumed, 23 remaining.
	_, secs, err = GenerateCode(seed, DefaultOptions(), time.Unix(37, 0))
	if err != nil {
		t.Fatal(err)
	}
	if secs != 23 {
		t.Errorf("secondsLeft at +7s = %d, want 23", secs)
	}
}

func TestGenerateCode_EmptySeed(t *testing.T) {
	_, _, err := GenerateCode("", DefaultOptions(), time.Now())
	if err == nil {
		t.Error("want error for empty seed")
	}
	_, _, err = GenerateCode("   ", DefaultOptions(), time.Now())
	if err == nil {
		t.Error("want error for whitespace seed")
	}
}

func TestGenerateCode_InvalidSeed(t *testing.T) {
	_, _, err := GenerateCode("!!not-base32!!", DefaultOptions(), time.Now())
	if err == nil {
		t.Error("want error for invalid base32 seed")
	}
}

func TestParseAlgorithm(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want otp.Algorithm
	}{
		{"", true, otp.AlgorithmSHA1},
		{"sha1", true, otp.AlgorithmSHA1},
		{"SHA1", true, otp.AlgorithmSHA1},
		{"sha256", true, otp.AlgorithmSHA256},
		{"SHA512", true, otp.AlgorithmSHA512},
		{"MD5", false, 0},
	}
	for _, tc := range cases {
		got, err := ParseAlgorithm(tc.in)
		if tc.ok && err != nil {
			t.Errorf("ParseAlgorithm(%q): %v", tc.in, err)
			continue
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("ParseAlgorithm(%q) expected error", tc.in)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAlgorithm(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseDigits(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want otp.Digits
	}{
		{"", true, otp.DigitsSix},
		{"6", true, otp.DigitsSix},
		{"7", true, otp.Digits(7)},
		{"8", true, otp.DigitsEight},
		{"9", false, 0},
		{"abc", false, 0},
	}
	for _, tc := range cases {
		got, err := ParseDigits(tc.in)
		if tc.ok && err != nil {
			t.Errorf("ParseDigits(%q): %v", tc.in, err)
			continue
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("ParseDigits(%q) expected error", tc.in)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDigits(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAlgorithmString(t *testing.T) {
	if AlgorithmString(otp.AlgorithmSHA1) != "SHA1" {
		t.Errorf("SHA1 = %q", AlgorithmString(otp.AlgorithmSHA1))
	}
	if AlgorithmString(otp.AlgorithmSHA256) != "SHA256" {
		t.Errorf("SHA256 = %q", AlgorithmString(otp.AlgorithmSHA256))
	}
	// Just sanity check the SHA512 variant — we do not rely on its exact
	// string in downstream code but it should include "512".
	if !strings.Contains(AlgorithmString(otp.AlgorithmSHA512), "512") {
		t.Errorf("SHA512 = %q", AlgorithmString(otp.AlgorithmSHA512))
	}
}

func TestWindowIndex(t *testing.T) {
	if got := WindowIndex(time.Unix(59, 0), 30); got != 1 {
		t.Errorf("WindowIndex(59,30) = %d, want 1", got)
	}
	if got := WindowIndex(time.Unix(60, 0), 30); got != 2 {
		t.Errorf("WindowIndex(60,30) = %d, want 2", got)
	}
	if got := WindowIndex(time.Unix(30, 0), 0); got != 1 {
		t.Errorf("WindowIndex(30,0) = %d, want 1 (0 period defaults to 30)", got)
	}
}
