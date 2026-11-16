package jwt

import (
	"errors"
	"testing"
)

func Test_normalizeAudience(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		aud  string
		want string
	}{
		{"plain identifier stays untouched", "my-service", "my-service"},
		{"plain identifier keeps case", "My-Service", "My-Service"},
		{"lowercases scheme and host", "HTTPS://API.Example.COM", "https://api.example.com"},
		{"strips https default port", "https://api.example.com:443", "https://api.example.com"},
		{"strips http default port", "http://api.example.com:80", "http://api.example.com"},
		{"keeps non default port", "https://api.example.com:8443", "https://api.example.com:8443"},
		{"removes trailing slash", "https://api.example.com/", "https://api.example.com"},
		{"removes multiple trailing slashes", "https://api.example.com/v1//", "https://api.example.com/v1"},
		{"removes trailing slashes at root", "http://api.example.com:80//", "http://api.example.com"},
		{"keeps path", "HTTPS://API.Example.COM:443/v1/users/", "https://api.example.com/v1/users"},
		{"keeps query", "https://api.example.com?a=1&B=2", "https://api.example.com?a=1&B=2"},
		{"keeps fragment", "https://api.example.com#section", "https://api.example.com#section"},
		{"trims surrounding whitespace", "  https://api.example.com/  ", "https://api.example.com"},
		{"scheme stays significant", "http://api.example.com", "http://api.example.com"},
		{"opaque value with colon is not a url", "urn:example:aud", "urn:example:aud"},
		{"ipv6 host keeps brackets", "http://[2001:db8::1]:8080/path", "http://[2001:db8::1]:8080/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAudience(tt.aud); got != tt.want {
				t.Errorf("normalizeAudience(%q) = %q, want %q", tt.aud, got, tt.want)
			}
		})
	}
}

func Test_NormalizedAudienceMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected string
		actual   string
		want     bool
	}{
		{"same origin variants", "https://api.example.com", "HTTPS://API.EXAMPLE.COM:443/", true},
		{"http default port and slash", "http://api.example.com", "http://api.example.com:80//", true},
		{"different scheme", "https://api.example.com", "http://api.example.com", false},
		{"different host", "https://api.example.com", "https://console.example.com", false},
		{"non default port differs", "https://api.example.com", "https://api.example.com:8443", false},
		{"path differs", "https://api.example.com/v1", "https://api.example.com/v2", false},
		{"query differs", "https://api.example.com?a=1", "https://api.example.com?a=2", false},
		{"non url identifiers stay exact", "my-service", "My-Service", false},
		{"non url identifier exact", "my-service", "my-service", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizedAudienceMatch(tt.expected, tt.actual); got != tt.want {
				t.Errorf("NormalizedAudienceMatch(%q, %q) = %v, want %v", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

func Test_PrefixAudienceMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected string
		actual   string
		want     bool
	}{
		{"exact value", "https://api.example.com/v1/", "https://api.example.com/v1/", true},
		{"nested path", "https://api.example.com/v1/", "https://api.example.com/v1/users", true},
		{"unrelated host", "https://api.example.com/v1/", "https://evil.example.com/v1/users", false},
		{"no boundary without trailing slash", "https://api.example.com/v1", "https://api.example.com/v1-evil", true},
		{"different prefix", "api", "console", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrefixAudienceMatch(tt.expected, tt.actual); got != tt.want {
				t.Errorf("PrefixAudienceMatch(%q, %q) = %v, want %v", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

func Test_NormalizedPrefixAudienceMatch(t *testing.T) {
	t.Parallel()

	if !NormalizedPrefixAudienceMatch("https://api.example.com/v1/", "HTTPS://API.EXAMPLE.COM:443/v1/users/") {
		t.Error("expected normalized prefix match to accept same-origin nested path")
	}

	if NormalizedPrefixAudienceMatch("https://api.example.com/v1/", "https://api.example.com/v2/users") {
		t.Error("expected normalized prefix match to reject a different path prefix")
	}
}

func Test_Validator_verifyAudienceMatchers(t *testing.T) {
	type args struct {
		claims       Claims
		cmp          []string
		expectAllAud bool
		matcher      AudienceMatcher
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "default exact match rejects same origin variant",
			args: args{
				claims: RegisteredClaims{Audience: ClaimStrings{"HTTPS://API.EXAMPLE.COM:443/"}},
				cmp:    []string{"https://api.example.com"},
			},
			wantErr: ErrTokenInvalidAudience,
		},
		{
			name: "normalized match accepts port slash and case variant",
			args: args{
				claims:  RegisteredClaims{Audience: ClaimStrings{"HTTPS://API.EXAMPLE.COM:443/"}},
				cmp:     []string{"https://api.example.com"},
				matcher: NormalizedAudienceMatch,
			},
		},
		{
			name: "normalized any of matches via second expected value",
			args: args{
				claims:  RegisteredClaims{Audience: ClaimStrings{"https://console.example.com"}},
				cmp:     []string{"https://api.example.com", "https://console.example.com/"},
				matcher: NormalizedAudienceMatch,
			},
		},
		{
			name: "normalized all of requires every expected audience",
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"HTTPS://API.EXAMPLE.COM:443/", "https://console.example.com/"}},
				cmp:          []string{"https://api.example.com", "https://console.example.com"},
				expectAllAud: true,
				matcher:      NormalizedAudienceMatch,
			},
		},
		{
			name: "normalized all of fails when one expected audience is absent",
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"https://api.example.com/"}},
				cmp:          []string{"https://api.example.com", "https://console.example.com"},
				expectAllAud: true,
				matcher:      NormalizedAudienceMatch,
			},
			wantErr: ErrTokenInvalidAudience,
		},
		{
			name: "multi value aud any of matches one",
			args: args{
				claims:  RegisteredClaims{Audience: ClaimStrings{"svc-a", "svc-b"}},
				cmp:     []string{"svc-c", "svc-b"},
				matcher: ExactAudienceMatch,
			},
		},
		{
			name: "multi value aud all of satisfied",
			args: args{
				claims:       RegisteredClaims{Audience: ClaimStrings{"svc-a", "svc-b", "svc-c"}},
				cmp:          []string{"svc-a", "svc-c"},
				expectAllAud: true,
				matcher:      ExactAudienceMatch,
			},
		},
		{
			name: "prefix match accepts nested audience",
			args: args{
				claims:  RegisteredClaims{Audience: ClaimStrings{"https://api.example.com/v1/users/42"}},
				cmp:     []string{"https://api.example.com/v1/"},
				matcher: PrefixAudienceMatch,
			},
		},
		{
			name: "prefix match rejects unrelated audience",
			args: args{
				claims:  RegisteredClaims{Audience: ClaimStrings{"https://evil.example.com/v1/users"}},
				cmp:     []string{"https://api.example.com/v1/"},
				matcher: PrefixAudienceMatch,
			},
			wantErr: ErrTokenInvalidAudience,
		},
		{
			name: "custom matcher can implement application semantics",
			args: args{
				claims: RegisteredClaims{Audience: ClaimStrings{"API.EXAMPLE.COM"}},
				cmp:    []string{"api.example.com"},
				matcher: func(expected, actual string) bool {
					return equalFoldASCII(expected, actual)
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				expectedAud:  tt.args.cmp,
				expectAllAud: tt.args.expectAllAud,
				audMatcher:   tt.args.matcher,
			}

			err := v.verifyAudience(tt.args.claims, tt.args.cmp, tt.args.expectAllAud)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("verifyAudience() error = %v, want nil", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("verifyAudience() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// Test_Validator_verifyAudienceFailureKinds asserts that the three failure
// modes of audience validation stay distinguishable and can never be confused
// for one another.
func Test_Validator_verifyAudienceFailureKinds(t *testing.T) {
	v := &Validator{
		expectedAud: []string{"https://api.example.com"},
		audMatcher:  NormalizedAudienceMatch,
	}

	tests := []struct {
		name   string
		claims Claims
		want   error
	}{
		{
			name:   "aud claim missing",
			claims: MapClaims{},
			want:   ErrTokenRequiredClaimMissing,
		},
		{
			name:   "aud claim has wrong type",
			claims: MapClaims{"aud": 123},
			want:   ErrInvalidType,
		},
		{
			name:   "aud value does not match",
			claims: RegisteredClaims{Audience: ClaimStrings{"https://evil.example.com"}},
			want:   ErrTokenInvalidAudience,
		},
	}

	otherFailures := []error{ErrTokenRequiredClaimMissing, ErrInvalidType, ErrTokenInvalidAudience}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.verifyAudience(tt.claims, v.expectedAud, false)
			if err == nil {
				t.Fatal("verifyAudience() error = nil, want failure")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("verifyAudience() error = %v, want errors.Is %v", err, tt.want)
			}
			for _, other := range otherFailures {
				if other == tt.want {
					continue
				}
				if errors.Is(err, other) {
					t.Errorf("error %v must not match unrelated failure %v", err, other)
				}
			}
		})
	}
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
