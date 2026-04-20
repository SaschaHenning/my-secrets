package store

import (
	"net/url"
	"strings"
)

// DomainMatch describes a single match emitted by MatchDomain-backed search.
// Entry is left as the attached pointer for app-layer callers; tier explains
// why this entry was picked, and hint is a one-line human-readable reason
// suitable both for CLI output and as an MCP field for AI callers.
type DomainMatch struct {
	Entry *Entry
	Tier  string // "exact" | "subdomain" | "substring" | "fuzzy"
	Hint  string
}

// Match tier constants. The order in this list mirrors the preference
// order used when deciding whether a candidate qualifies as a "primary"
// match (exact + subdomain) or a "similar" one (substring + fuzzy).
const (
	TierExact     = "exact"
	TierSubdomain = "subdomain"
	TierSubstring = "substring"
	TierFuzzy     = "fuzzy"
)

// NormalizeDomain reduces an arbitrary user-typed string to its canonical
// host form. It handles full URLs (with scheme/port/userinfo/path/query/
// fragment), bare hosts, and inputs that url.Parse cannot decode — in
// that last case we strip whatever suffix-ish characters look like a
// path or port and fall through to the bare-string branch.
//
// Examples:
//
//	"https://user:pw@aws.amazon.com:443/console?x=1" -> "aws.amazon.com"
//	"www.jasp.eu/"                                   -> "jasp.eu"
//	"aws.amazon.com"                                 -> "aws.amazon.com"
//	""                                               -> ""
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// url.Parse only recognises a scheme-bearing URL as a fully-formed URL.
	// For bare hosts ("jasp.eu") it returns Path-only, so we detect the
	// scheme case first and try the proper parse path.
	if hasSchemePrefix(s) {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return stripHost(u.Host)
		}
		// Scheme-prefixed but unparseable or empty host — e.g. "https://[[[",
		// "://bad", "http://:not-a-port". Falling through to the bare-host
		// branch would leave "https:" or ":" as the result. Review finding
		// I4: we refuse rather than persist garbage.
		return ""
	}
	// Fallback: treat input as a bare host-plus-extras string. Strip
	// anything that looks like a path or query so inputs like
	// "www.jasp.eu/login" still yield "jasp.eu".
	host := s
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	// Userinfo in a schemeless URL.
	if i := strings.Index(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	out := stripHost(host)
	// Reject anything that does not look like a plausible hostname. We
	// require at least one alphanumeric rune and forbid whitespace or
	// obvious syntax leftovers (lone ":", empty-after-strip, etc.). This
	// is the safety net that catches inputs like "://bad" which slip past
	// the scheme-prefix check because their scheme part is empty.
	if !looksLikeHostname(out) {
		return ""
	}
	return out
}

// looksLikeHostname is a last-resort heuristic: a hostname must have at
// least one letter or digit, and must not contain whitespace, slashes,
// or leading/trailing punctuation that would never be in a real host.
func looksLikeHostname(s string) bool {
	if s == "" {
		return false
	}
	// IPv6 literal — already bracket-checked in stripHost.
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return len(s) > 2
	}
	hasAlnum := false
	for _, c := range s {
		switch {
		case c == ' ' || c == '\t' || c == '/' || c == '?' || c == '#':
			return false
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			hasAlnum = true
		}
	}
	return hasAlnum
}

// hasSchemePrefix returns true if s starts with a URL scheme followed by
// "://". We keep the check small and explicit rather than calling into
// url.Parse for every input — the parse is cheap, but the scheme test
// doubles as a guard against ambiguous parses of raw hostnames.
func hasSchemePrefix(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	for _, c := range s[:i] {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// stripHost removes port, trailing dot, and lowercases; it also strips a
// leading "www." which is almost always noise for our matching.
//
// IPv6 literals (bracketed per RFC 3986, e.g. "[2001:db8::1]:8080") are
// handled specially: the port is stripped correctly, and the bracketed
// literal is kept intact so callers can still compare it bit-for-bit.
// IPv6 literals never enter fuzzy matching (they have no dot-segments
// the Levenshtein code understands), which is the correct behaviour —
// we want exact equality on IP literals, not „close enough".
func stripHost(h string) string {
	h = strings.ToLower(h)
	// IPv6 literal: "[addr]" optionally followed by ":port". Strip only
	// the trailing ":port" and keep the brackets + address intact.
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end >= 0 {
			rest := h[end+1:]
			if strings.HasPrefix(rest, ":") {
				if isAllDigits(rest[1:]) {
					h = h[:end+1]
				}
			} else if rest == "" {
				// No port — nothing to strip beyond the bracketed literal.
			} else {
				// Path/garbage after "]" — drop it.
				h = h[:end+1]
			}
		}
		// Do NOT strip "www." or trailing dots from IPv6 literals.
		return h
	}
	// IPv4 / DNS-style host. Strip trailing ":port" if numeric.
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if isAllDigits(h[i+1:]) && i < len(h)-1 {
			h = h[:i]
		}
	}
	h = strings.TrimPrefix(h, "www.")
	h = strings.TrimSuffix(h, ".")
	return h
}

// isAllDigits returns true when s is non-empty and every rune is 0–9.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// looksLikeIPv4 returns true when s has the shape „N.N.N.N" with N in 0..999
// — good enough to rule out fuzzy matching on what is clearly an IP
// literal. We do not validate the numeric range beyond that; semantic
// correctness belongs to a different layer.
func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if !isAllDigits(p) {
			return false
		}
	}
	return true
}

// DeriveDomain is an alias for NormalizeDomain used at the app layer when
// auto-filling Entry.Domain from a non-empty URL. Kept as a separate name
// so call sites read as "derive the domain from this URL" rather than the
// more general "normalise whatever you have".
func DeriveDomain(rawURL string) string {
	return NormalizeDomain(rawURL)
}

// MatchDomain classifies the relationship between a user query and a
// stored domain into one of four tiers, in descending strictness:
//
//  1. exact      — the two normalise to the same host.
//  2. subdomain  — one is a proper subdomain of the other (either direction:
//     a query for "jasp.eu" matches an entry stored as
//     "mail.jasp.eu", and a query for "mail.jasp.eu" matches an
//     entry stored as "jasp.eu"). This is the bidirectional rule the
//     issue body calls out explicitly.
//  3. substring  — one contains the other as a substring but the pair is
//     not a subdomain relationship (e.g. "amazon" inside
//     "aws.amazon.com").
//  4. fuzzy      — every dot-separated segment is within Levenshtein
//     distance 2 of the corresponding segment AND the final
//     segment (the TLD) is identical. This guard keeps totally
//     unrelated short domains like "google.com" and "github.com"
//     from being considered similar even though both share ".com".
//
// matched is false when none of the tiers apply; tier is then empty.
func MatchDomain(query, stored string) (tier string, hint string, matched bool) {
	q := NormalizeDomain(query)
	s := NormalizeDomain(stored)
	if q == "" || s == "" {
		return "", "", false
	}
	if q == s {
		return TierExact, "exact match on " + s, true
	}
	if strings.HasSuffix(s, "."+q) {
		return TierSubdomain, s + " is a subdomain of " + q, true
	}
	if strings.HasSuffix(q, "."+s) {
		return TierSubdomain, q + " is a subdomain of " + s, true
	}
	if strings.Contains(s, q) {
		return TierSubstring, "query \"" + q + "\" is contained in " + s, true
	}
	if strings.Contains(q, s) {
		return TierSubstring, "stored domain \"" + s + "\" is contained in " + q, true
	}
	// Fuzzy: segment-by-segment Levenshtein, TLD must be identical, every
	// segment within distance 2, at least one segment actually different
	// (otherwise we would have matched exact already — but the guard is
	// cheap and defensive).
	if d, ok := levenshteinSegments(q, s); ok && d > 0 {
		return TierFuzzy, "typo: " + q + " vs " + s + " (segment distance " + itoa(d) + ")", true
	}
	return "", "", false
}

// levenshteinSegments returns the sum of per-segment Levenshtein distances
// between q and s if:
//   - both have the same segment count, and
//   - their last segment (the TLD) is identical, and
//   - every individual segment is within distance 2.
//
// If any of those constraints fail it returns (0, false). Requiring an
// identical TLD prevents cross-TLD false positives ("google.com" vs
// "github.com" would pass the per-segment threshold but shares nothing
// semantically). Distance ≤ 2 per segment is the threshold the issue
// body calls out.
func levenshteinSegments(q, s string) (int, bool) {
	// IP literals don't have meaningful dot-segments for fuzzy matching —
	// "1.2.3.4" vs "1.2.3.5" should NOT be classified as a typo. Refuse
	// both IPv6 (bracketed) and IPv4 (all-numeric per-segment) inputs here.
	if strings.HasPrefix(q, "[") || strings.HasPrefix(s, "[") {
		return 0, false
	}
	if looksLikeIPv4(q) || looksLikeIPv4(s) {
		return 0, false
	}
	qp := strings.Split(q, ".")
	sp := strings.Split(s, ".")
	if len(qp) != len(sp) {
		return 0, false
	}
	// Last segment (TLD) must be identical.
	if qp[len(qp)-1] != sp[len(sp)-1] {
		return 0, false
	}
	total := 0
	for i := range qp {
		d := levenshtein(qp[i], sp[i])
		if d > 2 {
			return 0, false
		}
		total += d
	}
	return total, true
}

// levenshtein is a compact iterative Levenshtein distance implementation.
// We use a two-row rolling buffer so allocation stays O(min(len)).
func levenshtein(a, b string) int {
	ra := []rune(a)
	rb := []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			curr[j] = minOf3(del, ins, sub)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

func minOf3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// itoa is a tiny positive-int formatter kept local so this package does
// not need to import strconv just for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
