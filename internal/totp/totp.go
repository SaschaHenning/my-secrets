// Package totp implements the RFC 6238 Time-based One-Time Password
// primitives on top of github.com/pquerna/otp. It exposes a thin wrapper
// around the library so the rest of my-secrets does not have to know
// about the otp types directly.
//
// The package is deliberately side-effect free: all time input is passed
// in so tests can freeze the clock, and the raw base32 seed is treated
// as an opaque string. Callers are responsible for persisting the seed
// (we store it in the existing password field of a store.Entry).
package totp

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Entry is the parsed form of an otpauth:// URI. Zero values of the
// numeric fields mean "library default" (30s / 6 digits / SHA1).
type Entry struct {
	Seed      string
	Issuer    string
	Label     string
	Algorithm otp.Algorithm
	Digits    otp.Digits
	Period    uint
}

// Options controls GenerateCode. All fields have sensible defaults when
// zero: SHA1 / 6 digits / 30 seconds — the Google-Authenticator baseline.
type Options struct {
	Algorithm otp.Algorithm
	Digits    otp.Digits
	Period    uint
}

// DefaultOptions returns the Google-Authenticator defaults.
func DefaultOptions() Options {
	return Options{
		Algorithm: otp.AlgorithmSHA1,
		Digits:    otp.DigitsSix,
		Period:    30,
	}
}

// ParseAlgorithm parses an algorithm string (case-insensitive). Empty
// defaults to SHA1.
func ParseAlgorithm(s string) (otp.Algorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "SHA1":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	}
	return 0, fmt.Errorf("unsupported algorithm %q (want SHA1, SHA256 or SHA512)", s)
}

// ParseDigits parses a digit count. Empty defaults to 6. Accepts 6/7/8
// — the values pquerna/otp supports.
func ParseDigits(s string) (otp.Digits, error) {
	if strings.TrimSpace(s) == "" {
		return otp.DigitsSix, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid digits %q: %w", s, err)
	}
	switch n {
	case 6:
		return otp.DigitsSix, nil
	case 7:
		return otp.Digits(7), nil
	case 8:
		return otp.DigitsEight, nil
	}
	return 0, fmt.Errorf("unsupported digit count %d (want 6, 7 or 8)", n)
}

// AlgorithmString returns the canonical uppercase string for an
// otp.Algorithm (e.g. "SHA1"). Unknown values render as the library
// default stringer.
func AlgorithmString(a otp.Algorithm) string {
	return strings.ToUpper(a.String())
}

// DigitsInt returns the integer representation of an otp.Digits.
func DigitsInt(d otp.Digits) int {
	return d.Length()
}

// ParseURI parses an otpauth:// TOTP URI. It tolerates URIs that
// otp.NewKeyFromURL would reject because they omit the issuer query
// parameter — a situation common in recovery codes exported from
// password managers. When NewKeyFromURL succeeds its values are used
// verbatim; otherwise we fall back to a manual parser.
func ParseURI(uri string) (Entry, error) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return Entry{}, errors.New("empty uri")
	}
	// First attempt: use the upstream parser — it already handles the
	// issuer:label, algorithm, period and digit fields. The upstream
	// parser tolerates a missing `secret` query parameter so we enforce
	// it ourselves.
	if k, err := otp.NewKeyFromURL(uri); err == nil && k.Type() == "totp" && k.Secret() != "" {
		return Entry{
			Seed:      k.Secret(),
			Issuer:    k.Issuer(),
			Label:     k.AccountName(),
			Algorithm: k.Algorithm(),
			Digits:    k.Digits(),
			Period:    uint(k.Period()),
		}, nil
	}
	// Fallback: manual parse. The URL form is
	//   otpauth://totp/<issuer>:<label>?secret=...&issuer=...&algorithm=...&digits=...&period=...
	u, err := url.Parse(uri)
	if err != nil {
		// url.Parse embeds the full offending string in its error — for
		// an otpauth uri that is the secret seed. Never wrap it.
		return Entry{}, errors.New("parse uri: invalid otpauth uri")
	}
	if u.Scheme != "otpauth" {
		return Entry{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if strings.ToLower(u.Host) != "totp" {
		return Entry{}, fmt.Errorf("not a totp uri (host=%q)", u.Host)
	}
	q := u.Query()
	seed := q.Get("secret")
	if seed == "" {
		return Entry{}, errors.New("uri missing secret")
	}
	// Path is "/<issuer>:<label>" or just "/<label>".
	issuer := q.Get("issuer")
	label := strings.TrimPrefix(u.Path, "/")
	if i := strings.Index(label, ":"); i > 0 {
		if issuer == "" {
			issuer = label[:i]
		}
		label = strings.TrimSpace(label[i+1:])
	}
	alg, err := ParseAlgorithm(q.Get("algorithm"))
	if err != nil {
		return Entry{}, err
	}
	digits, err := ParseDigits(q.Get("digits"))
	if err != nil {
		return Entry{}, err
	}
	period := uint(30)
	if p := q.Get("period"); p != "" {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid period %q: %w", p, err)
		}
		period = uint(n)
	}
	return Entry{
		Seed:      seed,
		Issuer:    issuer,
		Label:     label,
		Algorithm: alg,
		Digits:    digits,
		Period:    period,
	}, nil
}

// GenerateCode computes the TOTP code for the given seed at time `now`,
// using the supplied options. Zero-valued option fields fall back to
// the Google-Authenticator defaults (SHA1/6/30). Returns the code plus
// the number of seconds remaining in the current window.
func GenerateCode(seed string, opts Options, now time.Time) (string, int, error) {
	if strings.TrimSpace(seed) == "" {
		return "", 0, errors.New("empty seed")
	}
	o := opts
	if o.Period == 0 {
		o.Period = 30
	}
	if o.Digits == 0 {
		o.Digits = otp.DigitsSix
	}
	// Algorithm 0 happens to be SHA1 in pquerna/otp so it already defaults
	// correctly, but be explicit for clarity.
	code, err := totp.GenerateCodeCustom(seed, now, totp.ValidateOpts{
		Period:    o.Period,
		Digits:    o.Digits,
		Algorithm: o.Algorithm,
	})
	if err != nil {
		return "", 0, fmt.Errorf("generate code: %w", err)
	}
	period := int(o.Period)
	if period <= 0 {
		period = 30
	}
	secondsLeft := period - int(math.Mod(float64(now.Unix()), float64(period)))
	if secondsLeft <= 0 {
		secondsLeft = period
	}
	return code, secondsLeft, nil
}

// WindowIndex returns the RFC 6238 time-step counter for `now` given
// the period. Useful for audit reasons that need to collapse repeated
// calls inside the same window.
func WindowIndex(now time.Time, period uint) int64 {
	p := int64(period)
	if p <= 0 {
		p = 30
	}
	return now.Unix() / p
}
