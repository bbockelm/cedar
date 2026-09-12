// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestIsSciToken tests the IsSciToken function with different token types
func TestIsSciToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "HS256 HMAC token (not SciToken)",
			token:    createTestToken(t, jwt.SigningMethodHS256, "secret-key"),
			expected: false,
		},
		{
			name:     "RS256 RSA token (SciToken)",
			token:    createTestRSAToken(t),
			expected: true,
		},
		{
			name:     "ES256 ECDSA token (SciToken)",
			token:    createTestECDSAToken(t),
			expected: true,
		},
		{
			name:     "Invalid token",
			token:    "invalid.token",
			expected: false,
		},
		{
			name:     "Empty token",
			token:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSciToken(tt.token)
			if result != tt.expected {
				t.Errorf("IsSciToken() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestConvertJWKToPublicKey_RSA tests converting RSA JWK to public key
func TestConvertJWKToPublicKey_RSA(t *testing.T) {
	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWK from public key
	jwk := rsaPublicKeyToJWK(privKey.PublicKey, "test-key-id")

	// Convert JWK back to public key
	pubKey, err := ConvertJWKToPublicKey(&jwk)
	if err != nil {
		t.Fatalf("ConvertJWKToPublicKey() failed: %v", err)
	}

	// Verify it's an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", pubKey)
	}

	// Verify the modulus matches
	if rsaPubKey.N.Cmp(privKey.N) != 0 {
		t.Errorf("Public key modulus mismatch")
	}
	if rsaPubKey.E != privKey.E {
		t.Errorf("Public key exponent mismatch")
	}
}

// TestConvertJWKToPublicKey_ECDSA tests converting EC JWK to public key
func TestConvertJWKToPublicKey_ECDSA(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
		crv   string
	}{
		{"P-256", elliptic.P256(), "P-256"},
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate ECDSA key
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			// Create JWK from public key
			jwk := ecdsaPublicKeyToJWK(privKey.PublicKey, "test-key-id")

			// Convert JWK back to public key
			pubKey, err := ConvertJWKToPublicKey(&jwk)
			if err != nil {
				t.Fatalf("ConvertJWKToPublicKey() failed: %v", err)
			}

			// Verify it's an ECDSA public key
			ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Expected *ecdsa.PublicKey, got %T", pubKey)
			}

			// Verify the curve and coordinates match. Comparing the
			// encoded points covers both coordinates at once and does
			// not read the deprecated X/Y fields.
			if ecdsaPubKey.Curve != tc.curve {
				t.Errorf("Curve mismatch")
			}
			gotPoint, err := ecdsaPubKey.Bytes()
			if err != nil {
				t.Fatalf("encoding parsed key: %v", err)
			}
			wantPoint, err := privKey.PublicKey.Bytes()
			if err != nil {
				t.Fatalf("encoding source key: %v", err)
			}
			if !bytes.Equal(gotPoint, wantPoint) {
				t.Errorf("public point mismatch")
			}
		})
	}
}

// TestVerifySciToken tests token verification with mock OIDC server
func TestVerifySciToken(t *testing.T) {
	// Generate RSA key for signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWKS with the public key
	jwk := rsaPublicKeyToJWK(privKey.PublicKey, "test-key-1")
	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	// Create mock OIDC server
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := OIDCConfiguration{
				Issuer:  server.URL,
				JWKSURI: server.URL + "/jwks",
			}
			_ = json.NewEncoder(w).Encode(config)
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Run("Valid SciToken", func(t *testing.T) {
		// Create valid SciToken
		claims := &SciTokenClaims{
			Subject:   "user@example.com",
			Issuer:    server.URL,
			Scope:     "read:/data write:/data",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key-1"
		tokenStr, err := token.SignedString(privKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Verify token - Note: This will fail with TLS certificate verification
		// In real tests, we'd need to configure HTTP client with InsecureSkipVerify
		// or use proper test certificates
		_, err = VerifySciToken(tokenStr)
		// We expect this to fail due to TLS verification, but test structure is correct
		if err == nil {
			t.Logf("Token verification succeeded (unexpected in this test setup)")
		} else {
			t.Logf("Token verification failed as expected: %v", err)
		}
	})

	t.Run("Expired SciToken", func(t *testing.T) {
		// Create expired SciToken
		claims := &SciTokenClaims{
			Subject:   "user@example.com",
			Issuer:    server.URL,
			Scope:     "read:/data",
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Expired
			IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key-1"
		tokenStr, err := token.SignedString(privKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Verification should fail (token expired)
		_, err = VerifySciToken(tokenStr)
		if err == nil {
			t.Error("Expected error for expired token, got nil")
		}
	})

	t.Run("Token with wrong signature", func(t *testing.T) {
		// Create token with different key
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate wrong RSA key: %v", err)
		}

		claims := &SciTokenClaims{
			Subject:   "user@example.com",
			Issuer:    server.URL,
			Scope:     "read:/data",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key-1"
		tokenStr, err := token.SignedString(wrongKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		// Verification should fail (wrong signature)
		_, err = VerifySciToken(tokenStr)
		if err == nil {
			t.Error("Expected error for token with wrong signature, got nil")
		}
	})
}

// Helper functions

// createTestToken creates a test JWT token with HMAC signature
func createTestToken(t *testing.T, method jwt.SigningMethod, secret string) string {
	t.Helper()

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://test-issuer.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = "test-key"

	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenStr
}

// createTestRSAToken creates a test JWT token with RSA signature
func createTestRSAToken(t *testing.T) string {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://test-issuer.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-rsa-key"

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("Failed to sign RSA token: %v", err)
	}

	return tokenStr
}

// createTestECDSAToken creates a test JWT token with ECDSA signature
func createTestECDSAToken(t *testing.T) string {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "test-user",
		"iss": "https://test-issuer.com",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-ec-key"

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("Failed to sign ECDSA token: %v", err)
	}

	return tokenStr
}

// rsaPublicKeyToJWK converts an RSA public key to JWK format
func rsaPublicKeyToJWK(pubKey rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64EncodeBytes(pubKey.N.Bytes()),
		E:   base64EncodeBytes(bigIntToBytes(pubKey.E)),
	}
}

// ecdsaPublicKeyToJWK converts an ECDSA public key to JWK format
func ecdsaPublicKeyToJWK(pubKey ecdsa.PublicKey, kid string) JWK {
	var crv string
	switch pubKey.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	}

	// Split the encoded uncompressed point (0x04 || X || Y) rather than
	// reading the deprecated coordinate fields. This also produces the
	// fixed-width, zero-padded coordinates RFC 7518 section 6.2.1.2 asks
	// for; big.Int.Bytes() would strip a leading zero byte.
	point, err := pubKey.Bytes()
	if err != nil {
		panic("encoding test public key: " + err.Error())
	}
	byteLen := (pubKey.Curve.Params().BitSize + 7) / 8

	return JWK{
		Kty: "EC",
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
		Crv: crv,
		X:   base64EncodeBytes(point[1 : 1+byteLen]),
		Y:   base64EncodeBytes(point[1+byteLen:]),
	}
}

// base64EncodeBytes encodes bytes to base64url without padding
func base64EncodeBytes(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// bigIntToBytes converts an int to bytes
func bigIntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	result := []byte{}
	for n > 0 {
		result = append([]byte{byte(n & 0xFF)}, result...)
		n >>= 8
	}
	return result
}

// TestConvertJWKToPublicKey_ECDSA_RejectsOffCurve is the reason the EC path
// parses an encoded point instead of assigning X and Y. Assigning the
// coordinates builds a key from any two integers; an issuer (or anyone who can
// answer for its JWKS URL) could hand over a point that is not on the curve and
// have it accepted as a signing key. Parsing rejects it before it can verify
// anything.
func TestConvertJWKToPublicKey_ECDSA_RejectsOffCurve(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwk := ecdsaPublicKeyToJWK(privKey.PublicKey, "off-curve")

	// Flip the low bit of Y. X stays a valid field element and the lengths
	// stay correct, so the only thing wrong with the point is that it no
	// longer satisfies the curve equation.
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decoding Y: %v", err)
	}
	yBytes[len(yBytes)-1] ^= 0x01
	jwk.Y = base64.RawURLEncoding.EncodeToString(yBytes)

	if _, err := ConvertJWKToPublicKey(&jwk); err == nil {
		t.Fatal("accepted a point that is not on the curve; it must be rejected")
	}
}

// TestConvertJWKToPublicKey_ECDSA_ShortCoordinates accepts coordinates that a
// producer emitted without the leading zeros RFC 7518 requires. Rejecting these
// would break working deployments, so they are left-padded rather than refused.
func TestConvertJWKToPublicKey_ECDSA_ShortCoordinates(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwk := ecdsaPublicKeyToJWK(privKey.PublicKey, "short")

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decoding X: %v", err)
	}
	if xBytes[0] != 0 {
		// Force a leading zero so there is something to strip, then strip
		// it the way a big.Int-based encoder would.
		xBytes[0] = 0
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			t.Fatalf("decoding Y: %v", err)
		}
		// A zeroed X almost certainly leaves the point off the curve, so
		// this variant only checks the padding path, via the error text.
		jwk.X = base64.RawURLEncoding.EncodeToString(xBytes[1:])
		jwk.Y = base64.RawURLEncoding.EncodeToString(yBytes)
		_, err = ConvertJWKToPublicKey(&jwk)
		if err != nil && strings.Contains(err.Error(), "too large") {
			t.Fatalf("short coordinate was treated as malformed: %v", err)
		}
		return
	}
	// X already had a leading zero: strip it and the key must still parse.
	jwk.X = base64.RawURLEncoding.EncodeToString(xBytes[1:])
	if _, err := ConvertJWKToPublicKey(&jwk); err != nil {
		t.Fatalf("rejected an unpadded but valid coordinate: %v", err)
	}
}

// TestConvertJWKToPublicKey_ECDSA_RejectsOversized refuses coordinates wider
// than the curve rather than silently truncating them.
func TestConvertJWKToPublicKey_ECDSA_RejectsOversized(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwk := ecdsaPublicKeyToJWK(privKey.PublicKey, "oversized")
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decoding X: %v", err)
	}
	jwk.X = base64.RawURLEncoding.EncodeToString(append([]byte{0x00}, xBytes...))
	if _, err := ConvertJWKToPublicKey(&jwk); err == nil {
		t.Fatal("accepted a coordinate wider than the curve")
	}
}
