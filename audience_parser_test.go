package jwt_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var audienceTestKey = []byte("hmac-audience-matcher-secret")

func signAudienceToken(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(audienceTestKey)
	if err != nil {
		t.Fatalf("could not sign token: %v", err)
	}
	return signed
}

func audienceKeyfunc(*jwt.Token) (any, error) {
	return audienceTestKey, nil
}

func TestParser_AudienceMatcherNormalized(t *testing.T) {
	t.Parallel()

	signed := signAudienceToken(t, jwt.RegisteredClaims{
		Audience: jwt.ClaimStrings{"HTTPS://API.EXAMPLE.COM:443/"},
	})

	t.Run("default exact matching rejects the variant", func(t *testing.T) {
		parser := jwt.NewParser(jwt.WithAudience("https://api.example.com"))
		_, err := parser.Parse(signed, audienceKeyfunc)
		if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
			t.Fatalf("expected ErrTokenInvalidAudience, got %v", err)
		}
	})

	t.Run("normalized matching accepts the same origin variant", func(t *testing.T) {
		parser := jwt.NewParser(
			jwt.WithAudience("https://api.example.com"),
			jwt.WithAudienceMatcher(jwt.NormalizedAudienceMatch),
		)
		token, err := parser.Parse(signed, audienceKeyfunc)
		if err != nil {
			t.Fatalf("expected valid token, got %v", err)
		}
		if !token.Valid {
			t.Fatal("expected parsed token to be valid")
		}
	})

	t.Run("prefix matching accepts a nested audience", func(t *testing.T) {
		nested := signAudienceToken(t, jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"https://api.example.com/v1/users/42"},
		})
		parser := jwt.NewParser(
			jwt.WithAudience("https://api.example.com/v1/"),
			jwt.WithAudienceMatcher(jwt.PrefixAudienceMatch),
		)
		if _, err := parser.Parse(nested, audienceKeyfunc); err != nil {
			t.Fatalf("expected valid token, got %v", err)
		}
	})
}

func TestParser_AudienceFailureKinds(t *testing.T) {
	t.Parallel()

	parser := jwt.NewParser(
		jwt.WithAudience("https://api.example.com"),
		jwt.WithAudienceMatcher(jwt.NormalizedAudienceMatch),
	)

	missing := signAudienceToken(t, jwt.RegisteredClaims{})

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	rawClaims := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":123}`))
	signatureInput := header + "." + rawClaims
	sig, err := jwt.SigningMethodHS256.Sign(signatureInput, audienceTestKey)
	if err != nil {
		t.Fatalf("could not sign malformed token: %v", err)
	}
	wrongType := signatureInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	mismatch := signAudienceToken(t, jwt.RegisteredClaims{
		Audience: jwt.ClaimStrings{"https://evil.example.com"},
	})

	tests := []struct {
		name        string
		token       string
		want        error
		exclusiveOf []error
	}{
		{
			name:        "missing aud",
			token:       missing,
			want:        jwt.ErrTokenRequiredClaimMissing,
			exclusiveOf: []error{jwt.ErrInvalidType, jwt.ErrTokenInvalidAudience},
		},
		{
			name:        "aud has wrong type",
			token:       wrongType,
			want:        jwt.ErrInvalidType,
			exclusiveOf: []error{jwt.ErrTokenRequiredClaimMissing, jwt.ErrTokenInvalidAudience},
		},
		{
			name:        "aud value mismatch",
			token:       mismatch,
			want:        jwt.ErrTokenInvalidAudience,
			exclusiveOf: []error{jwt.ErrTokenRequiredClaimMissing, jwt.ErrInvalidType},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser.Parse(tt.token, audienceKeyfunc)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected errors.Is(err, %v), got %v", tt.want, err)
			}
			for _, excluded := range tt.exclusiveOf {
				if errors.Is(err, excluded) {
					t.Errorf("error %v must not match %v", err, excluded)
				}
			}
		})
	}
}
