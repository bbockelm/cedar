package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestJWTValidationWithKeyID(t *testing.T) {
	// Create temporary directory for test keys
	tmpDir, err := os.MkdirTemp("", "jwt-validation-keys-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create pool signing key file (scrambled, as HTCondor stores it)
	poolKeyFile := filepath.Join(tmpDir, "pool_signing_key")
	poolKeyUnscrambled := []byte("test_pool_signing_key_32_bytes!")
	poolKeyScrambled := simple_scramble(poolKeyUnscrambled)
	if err := os.WriteFile(poolKeyFile, poolKeyScrambled, 0600); err != nil {
		t.Fatalf("Failed to write pool key file: %v", err)
	}

	// Create named signing keys directory
	namedKeyDir := filepath.Join(tmpDir, "named_keys")
	if err := os.MkdirAll(namedKeyDir, 0700); err != nil {
		t.Fatalf("Failed to create named key directory: %v", err)
	}

	testKey123Unscrambled := []byte("test_key_123_signing_key_32bytes")
	testKey123Scrambled := simple_scramble(testKey123Unscrambled)
	if err := os.WriteFile(filepath.Join(namedKeyDir, "test-key-123"), testKey123Scrambled, 0600); err != nil {
		t.Fatalf("Failed to write test-key-123 file: %v", err)
	}

	// Create an authenticator to test validation
	auth := &Authenticator{}

	// Test case 1: Valid JWT with key ID
	t.Run("ValidJWTWithKeyID", func(t *testing.T) {
		// Create JWT header with key ID
		header := map[string]interface{}{
			"alg": "HS256",
			"typ": "JWT",
			"kid": "test-key-123",
		}
		headerBytes, _ := json.Marshal(header)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

		// Create JWT payload
		now := time.Now().Unix()
		payload := map[string]interface{}{
			"sub": "testuser@example.com",
			"iss": "test-issuer",
			"iat": now,
			"exp": now + 3600, // Valid for 1 hour
		}
		payloadBytes, _ := json.Marshal(payload)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

		// Create auth data
		authData := &TokenAuthData{
			Token: headerB64 + "." + payloadB64, // header.payload (no signature)
		}

		// Create mock negotiation with key configuration
		negotiation := &SecurityNegotiation{
			ServerConfig: &SecurityConfig{
				TrustDomain:             "example.com",
				TokenPoolSigningKeyFile: poolKeyFile,
				TokenSigningKeyDir:      namedKeyDir,
			},
		}

		// Test validation
		err := auth.validateTokenAndDeriveKeys(authData, negotiation)
		if err != nil {
			t.Errorf("Expected validation to succeed, got: %v", err)
		}

		// Check that client ID was extracted
		if authData.ClientID != "testuser@example.com" {
			t.Errorf("Expected client ID 'testuser@example.com', got: %s", authData.ClientID)
		}

		// Check that server ID was set
		expectedServerID := "server@example.com"
		if authData.ServerID != expectedServerID {
			t.Errorf("Expected server ID '%s', got: %s", expectedServerID, authData.ServerID)
		}

		// Check that signature was computed
		if len(authData.Signature) == 0 {
			t.Error("Expected signature to be computed")
		}

		// Verify signature is HKDF-expanded key + HMAC-SHA256
		// First expand the signing key using HKDF (using unscrambled key)
		jwtKey := make([]byte, 32)
		hkdfReader := hkdf.New(sha256.New, testKey123Unscrambled, []byte("htcondor"), []byte("master jwt"))
		_, _ = io.ReadFull(hkdfReader, jwtKey)

		// Then compute HMAC-SHA256
		mac := hmac.New(sha256.New, jwtKey)
		mac.Write([]byte(authData.Token))
		expectedSig := mac.Sum(nil)[:32]
		if !bytesEqual(authData.Signature, expectedSig) {
			t.Error("Expected signature to be HKDF-expanded + HMAC-SHA256 of token with signing key")
		}
	})

	// Test case 2: JWT without key ID (defaults to POOL)
	t.Run("JWTWithoutKeyID", func(t *testing.T) {
		// Create JWT header without key ID
		header := map[string]interface{}{
			"alg": "HS256",
			"typ": "JWT",
		}
		headerBytes, _ := json.Marshal(header)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

		// Create JWT payload
		now := time.Now().Unix()
		payload := map[string]interface{}{
			"sub": "pooluser@htcondor",
			"iss": "htcondor-pool",
			"iat": now,
			"exp": now + 3600,
		}
		payloadBytes, _ := json.Marshal(payload)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

		// Create auth data
		authData := &TokenAuthData{
			Token: headerB64 + "." + payloadB64,
		}

		// Create mock negotiation with key configuration
		negotiation := &SecurityNegotiation{
			ServerConfig: &SecurityConfig{
				TrustDomain:             "htcondor",
				TokenPoolSigningKeyFile: poolKeyFile,
				TokenSigningKeyDir:      namedKeyDir,
			},
		}

		// Test validation (should default to POOL key)
		err := auth.validateTokenAndDeriveKeys(authData, negotiation)
		if err != nil {
			t.Errorf("Expected validation to succeed with POOL key, got: %v", err)
		}

		if authData.ClientID != "pooluser@htcondor" {
			t.Errorf("Expected client ID 'pooluser@htcondor', got: %s", authData.ClientID)
		}
	})

	// Test case 3: Expired JWT
	t.Run("ExpiredJWT", func(t *testing.T) {
		// Create JWT header
		header := map[string]interface{}{
			"alg": "HS256",
			"typ": "JWT",
		}
		headerBytes, _ := json.Marshal(header)
		headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

		// Create expired JWT payload
		past := time.Now().Unix() - 7200 // 2 hours ago
		payload := map[string]interface{}{
			"sub": "expireduser@example.com",
			"iss": "test-issuer",
			"iat": past - 3600, // issued 3 hours ago
			"exp": past,        // expired 2 hours ago
		}
		payloadBytes, _ := json.Marshal(payload)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

		// Create auth data
		authData := &TokenAuthData{
			Token: headerB64 + "." + payloadB64,
		}

		// Create mock negotiation with key configuration
		negotiation := &SecurityNegotiation{
			ServerConfig: &SecurityConfig{
				TrustDomain:             "example.com",
				TokenPoolSigningKeyFile: poolKeyFile,
				TokenSigningKeyDir:      namedKeyDir,
			},
		}

		// Test validation (should fail due to expiration)
		err := auth.validateTokenAndDeriveKeys(authData, negotiation)
		if err == nil {
			t.Error("Expected validation to fail with expired token")
		}

		if err != nil && !contains(err.Error(), "expired") {
			t.Errorf("Expected expiration error, got: %v", err)
		}
	})
}

func TestLoadSigningKey(t *testing.T) {
	auth := &Authenticator{}

	// Create temporary directory for test keys
	tmpDir, err := os.MkdirTemp("", "token-keys-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create pool signing key file (scrambled, as HTCondor stores it)
	poolKeyFile := filepath.Join(tmpDir, "pool_signing_key")
	poolKeyUnscrambled := []byte("test_pool_signing_key_32_bytes!!")
	poolKeyScrambled := simple_scramble(poolKeyUnscrambled)
	if err := os.WriteFile(poolKeyFile, poolKeyScrambled, 0600); err != nil {
		t.Fatalf("Failed to write pool key file: %v", err)
	}

	// Create named signing keys (scrambled, as HTCondor stores them)
	namedKeyDir := filepath.Join(tmpDir, "named_keys")
	if err := os.MkdirAll(namedKeyDir, 0700); err != nil {
		t.Fatalf("Failed to create named key directory: %v", err)
	}

	testKey123Unscrambled := []byte("test_key_123_signing_key_32bytes")
	testKey123Scrambled := simple_scramble(testKey123Unscrambled)
	if err := os.WriteFile(filepath.Join(namedKeyDir, "test-key-123"), testKey123Scrambled, 0600); err != nil {
		t.Fatalf("Failed to write test-key-123 file: %v", err)
	}

	differentKeyUnscrambled := []byte("different_signing_key_32_bytes!!")
	differentKeyScrambled := simple_scramble(differentKeyUnscrambled)
	if err := os.WriteFile(filepath.Join(namedKeyDir, "different-key"), differentKeyScrambled, 0600); err != nil {
		t.Fatalf("Failed to write different-key file: %v", err)
	}

	// Create config with key paths
	config := &SecurityConfig{
		TokenPoolSigningKeyFile: poolKeyFile,
		TokenSigningKeyDir:      namedKeyDir,
	}

	// Test POOL key loading (should be doubled)
	t.Run("POOLKey", func(t *testing.T) {
		key, err := auth.loadSigningKey("POOL", config)
		if err != nil {
			t.Errorf("Expected POOL key loading to succeed, got: %v", err)
		}
		// POOL keys are doubled, so expect 64 bytes
		if len(key) != 64 {
			t.Errorf("Expected 64-byte key (doubled), got %d bytes", len(key))
		}
		// Check that the key is the unscrambled key repeated twice
		expectedKey := make([]byte, 64)
		copy(expectedKey, poolKeyUnscrambled)
		copy(expectedKey[32:], poolKeyUnscrambled)
		if string(key) != string(expectedKey) {
			t.Error("Expected loaded key to match doubled unscrambled pool key")
		}
	})

	// Test named key loading (not doubled)
	t.Run("NamedKey", func(t *testing.T) {
		key1, err := auth.loadSigningKey("test-key-123", config)
		if err != nil {
			t.Errorf("Expected named key loading to succeed, got: %v", err)
		}
		if len(key1) != 32 {
			t.Errorf("Expected 32-byte key, got %d bytes", len(key1))
		}
		// Check that the key matches the unscrambled test key
		if string(key1) != string(testKey123Unscrambled) {
			t.Error("Expected loaded key to match unscrambled test key")
		}

		// Same key ID should produce same key
		key2, err := auth.loadSigningKey("test-key-123", config)
		if err != nil {
			t.Errorf("Expected second key loading to succeed, got: %v", err)
		}

		if !bytesEqual(key1, key2) {
			t.Error("Expected same key ID to produce same key")
		}

		// Different key ID should produce different key
		key3, err := auth.loadSigningKey("different-key", config)
		if err != nil {
			t.Errorf("Expected different key loading to succeed, got: %v", err)
		}

		if bytesEqual(key1, key3) {
			t.Error("Expected different key IDs to produce different keys")
		}
	})

	// Test error cases
	t.Run("MissingPoolKey", func(t *testing.T) {
		emptyConfig := &SecurityConfig{}
		_, err := auth.loadSigningKey("POOL", emptyConfig)
		if err == nil {
			t.Error("Expected error when pool key file not configured")
		}
	})

	t.Run("MissingNamedKeyDir", func(t *testing.T) {
		emptyConfig := &SecurityConfig{}
		_, err := auth.loadSigningKey("some-key", emptyConfig)
		if err == nil {
			t.Error("Expected error when signing key directory not configured")
		}
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		_, err := auth.loadSigningKey("../../../etc/passwd", config)
		if err == nil {
			t.Error("Expected error for key ID with path traversal")
		}
	})
}

// Helper function to check string contains
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(func() bool {
					for i := 0; i <= len(s)-len(substr); i++ {
						if s[i:i+len(substr)] == substr {
							return true
						}
					}
					return false
				}())))
}
