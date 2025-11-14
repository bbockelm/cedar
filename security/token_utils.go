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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

// GenerateSigningKey generates a signing key and writes it to the specified file
// The key is scrambled using HTCondor's simple_scramble (XOR with 0xdeadbeef)
func GenerateSigningKey(keyFile string) error {
	// Generate 32 random bytes for the key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	// Apply simple_scramble (XOR with 0xdeadbeef)
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		scrambled[i] = key[i] ^ deadbeef[i%len(deadbeef)]
	}

	// Write scrambled key to file
	if err := os.WriteFile(keyFile, scrambled, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// GeneratePoolSigningKey generates a pool signing key and writes it to the specified file
func GeneratePoolSigningKey(keyFile string) error {
	// Generate 64 random bytes for the key
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	// Apply simple_scramble (XOR with 0xdeadbeef)
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	scrambled := make([]byte, len(key))
	for i := range key {
		scrambled[i] = key[i] ^ deadbeef[i%len(deadbeef)]
	}

	// Write scrambled key to file
	if err := os.WriteFile(keyFile, scrambled, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// GenerateJWT generates a JWT token signed with the specified key
// Parameters:
//   - keyDir: Directory containing signing keys
//   - keyID: Name of the key file (used as kid in JWT header)
//   - subject: Subject claim (sub) - username
//   - issuer: Issuer claim (iss) - trust domain
//   - issuedAt: Issued at time (iat)
//   - expiration: Expiration time (exp)
//   - authzLimits: Optional list of authorization limits (e.g., ["READ", "WRITE"]) encoded as scopes
//
// Returns the JWT token string in format: header.payload.signature
func GenerateJWT(keyDir, keyID, subject, issuer string, issuedAt, expiration int64, authzLimits []string) (string, error) {
	// Read and unscramble the signing key
	keyPath := filepath.Join(keyDir, keyID)
	scrambled, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	// Unscramble the key (XOR with 0xdeadbeef)
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	signingKey := make([]byte, len(scrambled))
	for i := range scrambled {
		signingKey[i] = scrambled[i] ^ deadbeef[i%len(deadbeef)]
	}

	// For POOL keys, always duplicate the signing key before passing to HKDF
	// regardless of its original length on disk
	hkdfInputKey := signingKey
	if keyID == "POOL" {
		// Duplicate the key (concatenate with itself)
		hkdfInputKey = make([]byte, len(signingKey)*2)
		copy(hkdfInputKey, signingKey)
		copy(hkdfInputKey[len(signingKey):], signingKey)
	}

	// Generate random jti (JWT ID) - 16 random bytes, hex-encoded
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	// Create JWT header with key ID
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
		"kid": keyID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create JWT payload
	payload := map[string]interface{}{
		"sub": subject,
		"jti": jti,
		"iat": issuedAt,
		"exp": expiration,
	}

	// Add issuer if not empty
	if issuer != "" {
		payload["iss"] = issuer
	}

	// Add scopes if authorization limits are specified
	if len(authzLimits) > 0 {
		scopes := make([]string, len(authzLimits))
		for i, limit := range authzLimits {
			scopes[i] = "condor:/" + limit
		}
		payload["scope"] = scopes
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signature data (header.payload)
	signData := headerB64 + "." + payloadB64

	// Derive JWT signing key using HKDF (matching computeTokenSignature logic)
	const keyStrengthBytes = 32
	jwtKey := make([]byte, keyStrengthBytes)
	hkdfReader := hkdf.New(sha256.New, hkdfInputKey, []byte("htcondor"), []byte("master jwt"))
	if _, err := io.ReadFull(hkdfReader, jwtKey); err != nil {
		return "", fmt.Errorf("failed to derive JWT key: %w", err)
	}

	// Compute signature using HMAC-SHA256 with derived key
	h := hmac.New(sha256.New, jwtKey)
	h.Write([]byte(signData))
	signature := h.Sum(nil)

	// Encode signature
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return complete JWT
	return signData + "." + signatureB64, nil
}

// GenerateTestJWT is a convenience function that generates a signing key and JWT for testing
// Parameters are simplified for common test scenarios
func GenerateTestJWT(keyDir, keyID, subject, issuer string, validDuration time.Duration, authzLimits []string) (string, error) {
	// Ensure key directory exists
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create key directory: %w", err)
	}

	// Generate signing key if it doesn't exist
	keyPath := filepath.Join(keyDir, keyID)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := GenerateSigningKey(keyPath); err != nil {
			return "", fmt.Errorf("failed to generate signing key: %w", err)
		}
	}

	// Create JWT with current time and specified duration
	now := time.Now()
	token, err := GenerateJWT(keyDir, keyID, subject, issuer, now.Unix(), now.Add(validDuration).Unix(), authzLimits)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}
