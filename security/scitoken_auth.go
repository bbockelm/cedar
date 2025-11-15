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

// Package security provides SCITOKENS authentication implementation
// for CEDAR streams using SSL + SciToken exchange.
//
// This file implements HTCondor's SCITOKENS authentication method based on
// SSL authentication followed by SciToken verification as documented in
// HTCondor's condor_auth_ssl.cpp.
package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SciTokenClaims represents the claims in a SciToken JWT
type SciTokenClaims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Scope     string   `json:"scope,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	JWTID     string   `json:"jti,omitempty"`
	jwt.RegisteredClaims
}

// OIDCConfiguration represents the OIDC discovery document
type OIDCConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key type (RSA, EC, etc.)
	Kid string `json:"kid"`           // Key ID
	Use string `json:"use"`           // Key use (sig, enc)
	Alg string `json:"alg"`           // Algorithm
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // EC X coordinate
	Y   string `json:"y,omitempty"`   // EC Y coordinate
	Crv string `json:"crv,omitempty"` // EC curve name
}

// IsSciToken determines if a JWT token is a SciToken by checking its signature algorithm
// SciTokens use asymmetric signatures (RS*, ES*, PS*), not HMAC (HS*)
func IsSciToken(tokenStr string) bool {
	// Parse token without verification to extract header
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return false
	}

	// Parse just the header to check algorithm
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return false
	}

	// Check if algorithm is asymmetric (not HS*)
	alg := token.Method.Alg()
	return !strings.HasPrefix(alg, "HS")
}

// DiscoverOIDCConfiguration fetches the OIDC configuration from the issuer
func DiscoverOIDCConfiguration(issuer string) (*OIDCConfiguration, error) {
	// Construct the well-known configuration URL
	configURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration from %s: %w", configURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC configuration request returned status %d", resp.StatusCode)
	}

	var config OIDCConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC configuration: %w", err)
	}

	return &config, nil
}

// FetchJWKS fetches the JSON Web Key Set from the JWKS URI
func FetchJWKS(jwksURI string) (*JWKS, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURI, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}

// VerifySciToken verifies a SciToken's signature using OIDC discovery
// Returns the validated claims if successful
func VerifySciToken(tokenStr string) (*SciTokenClaims, error) {
	// Parse token without verification first to get issuer and kid
	unverifiedToken, err := jwt.ParseWithClaims(tokenStr, &SciTokenClaims{}, nil)
	if err != nil && unverifiedToken == nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get claims to extract issuer
	claims, ok := unverifiedToken.Claims.(*SciTokenClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	if claims.Issuer == "" {
		return nil, fmt.Errorf("token missing issuer claim")
	}

	// Get kid from header
	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Discover OIDC configuration (once per token verification)
	config, err := DiscoverOIDCConfiguration(claims.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// Fetch JWKS (once per token verification)
	jwks, err := FetchJWKS(config.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Find the key matching the token's kid
	var publicKey interface{}
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			publicKey, err = ConvertJWKToPublicKey(&key)
			if err != nil {
				return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
			}
			break
		}
	}

	if publicKey == nil {
		return nil, fmt.Errorf("no matching key found for kid: %s", kid)
	}

	// Now verify the token with the public key
	verifiedToken, err := jwt.ParseWithClaims(tokenStr, &SciTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method matches what we expect
		switch publicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok && token.Method.Alg()[:2] != "RS" && token.Method.Alg()[:2] != "PS" {
				return nil, fmt.Errorf("unexpected signing method: %v (expected RSA)", token.Method.Alg())
			}
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v (expected ECDSA)", token.Method.Alg())
			}
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token signature verification failed: %w", err)
	}

	if !verifiedToken.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	verifiedClaims, ok := verifiedToken.Claims.(*SciTokenClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type after verification")
	}

	return verifiedClaims, nil
}

// ConvertJWKToPublicKey converts a JWK to a public key for verification
func ConvertJWKToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		// Decode RSA modulus and exponent from base64url
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
		}

		// Convert to big.Int
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)

		// Create RSA public key
		return &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}, nil

	case "EC":
		// Decode EC coordinates from base64url
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
		}

		// Determine the curve
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

		// Create EC public key
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}
