package store

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Already-bare hosts pass through untouched.
		{"aws.amazon.com", "aws.amazon.com"},
		{"JASP.eu", "jasp.eu"},

		// Full URLs with every possible piece.
		{"https://aws.amazon.com", "aws.amazon.com"},
		{"http://aws.amazon.com/", "aws.amazon.com"},
		{"https://aws.amazon.com/console", "aws.amazon.com"},
		{"https://user:pw@aws.amazon.com:443/console?x=1#frag", "aws.amazon.com"},
		{"user:pw@host:8080/path?q=1#frag", "host"},

		// www. and trailing slash / dot stripping.
		{"www.jasp.eu/", "jasp.eu"},
		{"www.JASP.EU", "jasp.eu"},
		{"jasp.eu.", "jasp.eu"},

		// Schemeless but with a path or query.
		{"jasp.eu/foo", "jasp.eu"},
		{"jasp.eu?x=1", "jasp.eu"},

		// Edge cases.
		{"", ""},
		{"   ", ""},
		{"localhost:8080", "localhost"},

		// Review finding I4: scheme-prefixed garbage must not produce a
		// half-parsed „https:"-style host — return empty instead.
		{"https://[[[", ""},
		{"http://example.com:not-port", ""},
		{"://bad", ""},

		// Review finding I5: IPv6 literals are preserved with brackets
		// and have their port stripped correctly; "www." and trailing
		// dot logic must not touch them.
		{"[2001:db8::1]:8080", "[2001:db8::1]"},
		{"[2001:db8::1]", "[2001:db8::1]"},
		{"https://[2001:db8::1]:443/path", "[2001:db8::1]"},
	}
	for _, tc := range cases {
		got := NormalizeDomain(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDeriveDomainAlias(t *testing.T) {
	if DeriveDomain("https://aws.amazon.com:443/foo") != "aws.amazon.com" {
		t.Error("DeriveDomain should alias NormalizeDomain")
	}
	if DeriveDomain("") != "" {
		t.Error("DeriveDomain(\"\") should be empty")
	}
}

func TestMatchDomainTiers(t *testing.T) {
	type want struct {
		tier    string
		matched bool
		hintSub string // substring that must appear in the hint
	}
	cases := []struct {
		name   string
		query  string
		stored string
		w      want
	}{
		{"exact identity", "jasp.eu", "jasp.eu", want{TierExact, true, "exact"}},
		{"exact with scheme+path", "https://jasp.eu/", "jasp.eu", want{TierExact, true, "exact"}},
		{"exact www strip", "www.jasp.eu", "jasp.eu", want{TierExact, true, "exact"}},

		{"query parent of stored", "jasp.eu", "mail.jasp.eu", want{TierSubdomain, true, "subdomain"}},
		{"stored parent of query", "mail.jasp.eu", "jasp.eu", want{TierSubdomain, true, "subdomain"}},

		{"substring query inside stored", "amazon", "aws.amazon.com", want{TierSubstring, true, "contained"}},
		// stored "amaz" is contained in query "aws.amazon.com" but not a
		// dot-subdomain of it, so this lands on substring rather than
		// subdomain (both inputs normalise to bare hosts).
		{"substring stored inside query", "aws.amazon.com", "amaz", want{TierSubstring, true, "contained"}},

		{"fuzzy typo single edit", "jazp.eu", "jasp.eu", want{TierFuzzy, true, "typo"}},
		{"fuzzy typo transposition", "gtihub.com", "github.com", want{TierFuzzy, true, "typo"}},

		// Common-TLD-only is not enough for fuzzy.
		{"no match across short domains sharing only TLD", "google.com", "github.com", want{"", false, ""}},

		// Different segment count is not fuzzy.
		{"different segment count", "mail.jasp.eu", "jasp.eu", want{TierSubdomain, true, "subdomain"}},

		// Empty inputs.
		{"empty query", "", "jasp.eu", want{"", false, ""}},
		{"empty stored", "jasp.eu", "", want{"", false, ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tier, hint, matched := MatchDomain(tc.query, tc.stored)
			if matched != tc.w.matched {
				t.Fatalf("matched = %v, want %v (tier=%q hint=%q)", matched, tc.w.matched, tier, hint)
			}
			if tier != tc.w.tier {
				t.Errorf("tier = %q, want %q (hint=%q)", tier, tc.w.tier, hint)
			}
			if tc.w.hintSub != "" && !strings.Contains(hint, tc.w.hintSub) {
				t.Errorf("hint %q does not contain %q", hint, tc.w.hintSub)
			}
		})
	}
}

func TestMatchDomain_FuzzyRequiresSameTLD(t *testing.T) {
	// Different TLDs but short segments — must NOT be fuzzy even though
	// per-segment distance is small.
	if tier, _, matched := MatchDomain("jasp.de", "jasp.eu"); matched {
		t.Errorf("expected no fuzzy across differing TLDs, got tier=%q", tier)
	}
}

func TestLevenshteinSegments(t *testing.T) {
	cases := []struct {
		a, b     string
		wantD    int
		wantOK   bool
		explainQ string
	}{
		{"jasp.eu", "jazp.eu", 1, true, "one segment distance"},
		{"github.com", "gtihub.com", 2, true, "transposition distance"},
		{"github.com", "gitlab.com", 2, true, "two substitutions"},
		{"verylongdomain.com", "verylongdomaim.com", 1, true, "single substitution"},
		// Distance too large per segment.
		{"google.com", "github.com", 0, false, "distance > 2"},
		// Different segment count.
		{"mail.jasp.eu", "jasp.eu", 0, false, "length mismatch"},
		// Different TLD.
		{"jasp.de", "jasp.eu", 0, false, "TLD differs"},
	}
	for _, tc := range cases {
		d, ok := levenshteinSegments(tc.a, tc.b)
		if ok != tc.wantOK {
			t.Errorf("levenshteinSegments(%q, %q) ok=%v, want %v (%s)", tc.a, tc.b, ok, tc.wantOK, tc.explainQ)
		}
		if ok && d != tc.wantD {
			t.Errorf("levenshteinSegments(%q, %q) = %d, want %d", tc.a, tc.b, d, tc.wantD)
		}
	}
}

// Review finding I5: IP literals must never be fuzzy-matched. "1.2.3.4"
// vs "1.2.3.5" is a different machine, not a typo; "[2001:db8::1]" vs
// "[2001:db8::2]" likewise. Both cases must come out as no-match.
func TestMatchDomain_IPLiteralsRejectedByFuzzy(t *testing.T) {
	cases := []struct {
		query, stored string
	}{
		{"1.2.3.4", "1.2.3.5"},
		{"[2001:db8::1]", "[2001:db8::2]"},
		{"192.168.1.1", "192.168.1.2"},
	}
	for _, tc := range cases {
		tier, _, ok := MatchDomain(tc.query, tc.stored)
		if ok && tier == TierFuzzy {
			t.Errorf("MatchDomain(%q, %q) = fuzzy; IP literals must not fuzzy-match",
				tc.query, tc.stored)
		}
	}
	// But IPs that are identical should still classify as exact.
	tier, _, ok := MatchDomain("1.2.3.4", "1.2.3.4")
	if !ok || tier != TierExact {
		t.Errorf("identical IPv4 must be exact, got tier=%q ok=%v", tier, ok)
	}
}

func TestLevenshtein_Basic(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "ab", 2},
		{"kitten", "sitting", 3},
		{"jasp", "jazp", 1},
		{"abc", "abc", 0},
	}
	for _, tc := range cases {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
