package jwt

import (
	"net/url"
	"strings"
)

// AudienceMatcher decides whether a single audience value contained in a
// token's `aud` claim matches one of the expected audiences. It is invoked
// once per (expected, actual) pair until it returns true.
//
// Returning true means the two values denote the same audience under the
// configured matching semantics; returning false keeps the validation going.
type AudienceMatcher func(expected, actual string) bool

// ExactAudienceMatch is the default audience matching semantics: both values
// must be byte-for-byte equal, mirroring the comparison defined in
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3.
func ExactAudienceMatch(expected, actual string) bool {
	return expected == actual
}

// NormalizedAudienceMatch compares audiences after normalizing them as
// same-origin URL variants. It exists so that values pointing at the same
// logical audience, e.g. "https://api.example.com",
// "HTTPS://API.EXAMPLE.COM:443/" and "https://api.example.com" are treated as
// equal.
//
// For values that parse as absolute URLs, normalization lowercases the scheme
// and host, strips the default port (80 for http, 443 for https), removes
// trailing slashes from the path and keeps any path, query or fragment. Values
// that are not absolute URLs fall back to trimmed, case-sensitive comparison,
// so opaque audience identifiers such as "my-service" keep their exact
// semantics.
func NormalizedAudienceMatch(expected, actual string) bool {
	return normalizeAudience(expected) == normalizeAudience(actual)
}

// PrefixAudienceMatch reports whether the actual audience is equal to the
// expected value or starts with it. This is useful when one expected audience
// covers a hierarchy of values, such as service instances under a common base
// URL.
//
// Because plain prefix matching does not understand path or label boundaries,
// an expected value of "https://api.example.com/v1" also matches
// "https://api.example.com/v1-evil". Callers should therefore end URL-shaped
// expected values with a trailing slash (e.g.
// "https://api.example.com/v1/") whenever boundary enforcement matters, or
// supply a custom [AudienceMatcher].
func PrefixAudienceMatch(expected, actual string) bool {
	return actual == expected || strings.HasPrefix(actual, expected)
}

// NormalizedPrefixAudienceMatch combines [NormalizedAudienceMatch] and
// [PrefixAudienceMatch]: both values are normalized as same-origin URL
// variants before the prefix comparison. The same boundary considerations as
// for [PrefixAudienceMatch] apply; prefer expected values ending in a slash
// for URL-shaped audiences.
func NormalizedPrefixAudienceMatch(expected, actual string) bool {
	expected = normalizeAudience(expected)
	actual = normalizeAudience(actual)
	return actual == expected || strings.HasPrefix(actual, expected)
}

// audienceDefaultPorts lists the ports that are implied by the scheme and
// therefore redundant when present in an audience URL.
var audienceDefaultPorts = map[string]string{
	"http":  "80",
	"https": "443",
}

// normalizeAudience canonicalizes an audience value so that same-origin
// variants compare equal. Values that are not absolute URLs are only trimmed
// of surrounding whitespace, leaving non-URL identifiers case-sensitive.
func normalizeAudience(aud string) string {
	aud = strings.TrimSpace(aud)

	parsed, err := url.Parse(aud)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return aud
	}

	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := parsed.Port(); port != "" && audienceDefaultPorts[scheme] != port {
		host = host + ":" + port
	}

	path := strings.TrimRight(parsed.Path, "/")

	normalized := scheme + "://" + host + path
	if parsed.RawQuery != "" {
		normalized += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		normalized += "#" + parsed.Fragment
	}

	return normalized
}
