package totp

import (
	"net/url"
	"strconv"
	"strings"
)

// BuildURI renders an Entry as an otpauth:// TOTP URI — the inverse of
// ParseURI. Algorithm, digits and period are always emitted explicitly so
// consumers (authenticator apps, Bitwarden) never have to guess defaults.
// An empty issuer omits both the label prefix and the issuer parameter.
func BuildURI(e Entry) string {
	label := e.Label
	if e.Issuer != "" {
		if label == "" {
			label = e.Issuer
		} else {
			label = e.Issuer + ":" + label
		}
	}
	q := url.Values{}
	q.Set("secret", strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(e.Seed), " ", "")))
	if e.Issuer != "" {
		q.Set("issuer", e.Issuer)
	}
	q.Set("algorithm", AlgorithmString(e.Algorithm))
	digits := DigitsInt(e.Digits)
	if digits == 0 {
		digits = 6
	}
	q.Set("digits", strconv.Itoa(digits))
	period := e.Period
	if period == 0 {
		period = 30
	}
	q.Set("period", strconv.FormatUint(uint64(period), 10))
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}
	return u.String()
}
