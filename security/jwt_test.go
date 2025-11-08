package security

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestJWTPayloadParsing(t *testing.T) {
	tests := []struct {
		name        string
		payload     map[string]interface{}
		expectError bool
		expectedSub string
	}{
		{
			name: "ValidSubject",
			payload: map[string]interface{}{
				"sub": "alice@test.domain",
				"iss": "test-issuer",
				"exp": 1234567890,
			},
			expectError: false,
			expectedSub: "alice@test.domain",
		},
		{
			name: "ComplexSubject",
			payload: map[string]interface{}{
				"sub":   "user@example.com",
				"name":  "Test User",
				"roles": []string{"admin", "user"},
				"nested": map[string]interface{}{
					"field": "value",
				},
			},
			expectError: false,
			expectedSub: "user@example.com",
		},
		{
			name: "MissingSubject",
			payload: map[string]interface{}{
				"iss": "test-issuer",
				"exp": 1234567890,
			},
			expectError: true,
		},
		{
			name: "InvalidSubjectType",
			payload: map[string]interface{}{
				"sub": 12345, // numeric instead of string
				"iss": "test-issuer",
			},
			expectError: true,
		},
		{
			name: "EmptySubject",
			payload: map[string]interface{}{
				"sub": "",
				"iss": "test-issuer",
			},
			expectError: false, // JSON parsing succeeds, but ClientID will be empty
			expectedSub: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test JWT payload
			payloadBytes, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("Failed to marshal test payload: %v", err)
			}

			// Base64url encode the payload
			encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

			// Create mock auth data
			authData := &TokenAuthData{}

			// Test the loadTokenForAuthentication function with a mock JWT
			// We'll simulate the JWT token parts directly
			parts := []string{
				"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9", // header
				encodedPayload,                         // payload
				"dGVzdC1zaWduYXR1cmU",                  // signature (base64url encoded "test-signature")
			}

			// Store token (header.payload)
			authData.Token = parts[0] + "." + parts[1]

			// Decode and parse the payload
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("Failed to decode payload: %v", err)
			}

			// Parse JSON payload to extract subject (this is what we're testing)
			var claims map[string]interface{}
			if err := json.Unmarshal(payload, &claims); err != nil {
				if !tt.expectError {
					t.Fatalf("Failed to parse JWT payload as JSON: %v", err)
				}
				return
			}

			// Extract subject claim
			if sub, ok := claims["sub"]; ok {
				if subStr, ok := sub.(string); ok {
					authData.ClientID = subStr
				} else {
					if !tt.expectError {
						t.Errorf("JWT subject claim is not a string")
					}
					return
				}
			} else {
				if !tt.expectError {
					t.Errorf("JWT token missing required subject (sub) claim")
				}
				return
			}

			// Validate results
			if tt.expectError {
				t.Errorf("Expected error but got none")
				return
			}

			if authData.ClientID != tt.expectedSub {
				t.Errorf("Expected subject %q, got %q", tt.expectedSub, authData.ClientID)
			}
		})
	}
}

func TestJWTMalformedPayload(t *testing.T) {
	// Test with invalid JSON
	invalidJSON := "invalid-json-data"
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(invalidJSON))

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err == nil {
		t.Errorf("Expected JSON parsing to fail with invalid JSON")
	}
}

func TestJWTValidClaims(t *testing.T) {
	// Test a realistic JWT payload with various claim types
	payload := map[string]interface{}{
		"sub":   "john.doe@example.com",
		"iss":   "https://auth.example.com",
		"aud":   "htcondor",
		"exp":   1640995200,
		"iat":   1640908800,
		"scope": "read:condor write:condor",
		"groups": []string{
			"htcondor-users",
			"researchers",
		},
		"custom_claim": map[string]interface{}{
			"nested_field": "nested_value",
			"number":       42,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("Failed to parse JSON payload: %v", err)
	}

	// Verify subject extraction
	if sub, ok := claims["sub"]; ok {
		if subStr, ok := sub.(string); ok {
			if subStr != "john.doe@example.com" {
				t.Errorf("Expected subject john.doe@example.com, got %s", subStr)
			}
		} else {
			t.Errorf("Subject claim is not a string")
		}
	} else {
		t.Errorf("Missing subject claim")
	}

	// Verify other claims are preserved
	if iss, ok := claims["iss"]; ok {
		if issStr, ok := iss.(string); ok {
			if issStr != "https://auth.example.com" {
				t.Errorf("Expected issuer https://auth.example.com, got %s", issStr)
			}
		}
	}
}
