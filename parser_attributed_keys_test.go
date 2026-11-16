package jwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// makeTokenWithKid builds a signed token and optionally sets the "kid" header.
func makeTokenWithKid(t *testing.T, method jwt.SigningMethod, kid string, key any) string {
	t.Helper()

	token := jwt.NewWithClaims(method, jwt.MapClaims{"foo": "bar"})
	if kid != "" {
		token.Header[jwt.HeaderKeyID] = kid
	}

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signed
}

// tamperSignature flips one character of the signature segment so the token
// remains well-formed but fails signature verification.
func tamperSignature(t *testing.T, tokenString string) string {
	t.Helper()

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not contain three segments")
	}

	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}

	return strings.Join(parts, ".")
}

func TestParser_ParseAttributedKeys(t *testing.T) {
	rsaToken := makeTokenWithKid(t, jwt.SigningMethodRS256, "rsa-1", jwtTestRSAPrivateKey)
	ecToken := makeTokenWithKid(t, jwt.SigningMethodES256, "ec-1", jwtTestEC256PrivateKey)
	unknownKidToken := makeTokenWithKid(t, jwt.SigningMethodRS256, "unknown", jwtTestRSAPrivateKey)

	testCases := []struct {
		name           string
		tokenString    string
		keyFunc        jwt.Keyfunc
		valid          bool
		wantErr        error
		wantNoMatch    bool
		wantInvalidSig bool
	}{
		{
			name:        "attributed multi key, rsa key selected by kid and alg",
			tokenString: rsaToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestEC256PublicKey, Algorithm: "ES256", KeyID: "ec-1"},
						{Key: jwtTestDefaultKey, Algorithm: "RS256", KeyID: "rsa-1"},
					},
				}, nil
			},
			valid: true,
		},
		{
			name:        "attributed multi key, ec key selected by kid and alg",
			tokenString: ecToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestDefaultKey, Algorithm: "RS256", KeyID: "rsa-1"},
						{Key: jwtTestEC256PublicKey, Algorithm: "ES256", KeyID: "ec-1"},
					},
				}, nil
			},
			valid: true,
		},
		{
			name:        "attributed key selected by alg without kid",
			tokenString: rsaToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestEC256PublicKey, Algorithm: "ES256"},
						{Key: jwtTestDefaultKey, Algorithm: "RS256"},
					},
				}, nil
			},
			valid: true,
		},
		{
			name:        "kid mismatch reports no matching key",
			tokenString: unknownKidToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestDefaultKey, Algorithm: "RS256", KeyID: "rsa-1"},
					},
				}, nil
			},
			valid:       false,
			wantErr:     jwt.ErrTokenNoMatchingKey,
			wantNoMatch: true,
		},
		{
			name:        "alg mismatch reports no matching key",
			tokenString: rsaToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestDefaultKey, Algorithm: "ES256", KeyID: "rsa-1"},
					},
				}, nil
			},
			valid:       false,
			wantErr:     jwt.ErrTokenNoMatchingKey,
			wantNoMatch: true,
		},
		{
			name:        "matching key with invalid signature reports signature error",
			tokenString: tamperSignature(t, rsaToken),
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestDefaultKey, Algorithm: "RS256", KeyID: "rsa-1"},
					},
				}, nil
			},
			valid:          false,
			wantErr:        jwt.ErrTokenSignatureInvalid,
			wantInvalidSig: true,
		},
		{
			name:        "legacy keys without attribution keep trying every key",
			tokenString: rsaToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					Keys: []jwt.VerificationKey{jwtTestEC256PublicKey, jwtTestDefaultKey},
				}, nil
			},
			valid: true,
		},
		{
			name:        "legacy keys keep returning signature error, not no matching key",
			tokenString: tamperSignature(t, rsaToken),
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					Keys: []jwt.VerificationKey{jwtTestEC256PublicKey, jwtTestDefaultKey},
				}, nil
			},
			valid:          false,
			wantErr:        jwt.ErrTokenSignatureInvalid,
			wantInvalidSig: true,
		},
		{
			name:        "unattributed keys remain eligible when attributed keys do not match",
			tokenString: unknownKidToken,
			keyFunc: func(*jwt.Token) (any, error) {
				return jwt.VerificationKeySet{
					Keys: []jwt.VerificationKey{jwtTestDefaultKey},
					AttributedKeys: []jwt.AttributedKey{
						{Key: jwtTestEC256PublicKey, KeyID: "ec-1"},
					},
				}, nil
			},
			valid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := jwt.NewParser().Parse(tc.tokenString, tc.keyFunc)

			if tc.valid && err != nil {
				t.Fatalf("expected valid token, got error: %v", err)
			}

			if !tc.valid && err == nil {
				t.Fatalf("expected error, token was accepted as valid")
			}

			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got: %v", tc.wantErr, err)
			}

			if tc.wantNoMatch && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
				t.Fatalf("expected no-matching-key error without signature error, got: %v", err)
			}

			if tc.wantInvalidSig && errors.Is(err, jwt.ErrTokenNoMatchingKey) {
				t.Fatalf("expected signature error without no-matching-key error, got: %v", err)
			}

			if token != nil && token.Valid != tc.valid {
				t.Fatalf("expected token.Valid=%v, got %v", tc.valid, token.Valid)
			}
		})
	}
}
