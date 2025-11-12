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

// Package security provides TOKEN/IDTOKENS authentication implementation
// for CEDAR streams using the AKEP2 protocol.
//
// This file implements HTCondor's TOKEN authentication method based on
// JWT tokens and the AKEP2 (Authenticated Key Exchange Protocol 2) as
// documented in HTCondor's condor_auth_passwd.cpp.
package security

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"

	"github.com/bbockelm/cedar/message"
)

// ErrNetwork is a singleton error used to wrap network/communication errors
// from Message Put/Get operations
var ErrNetwork = errors.New("network communication error")

// Helper functions to wrap Message Put/Get operations with network error detection

func putInt(ctx context.Context, msg *message.Message, value int) error {
	if err := msg.PutInt(ctx, value); err != nil {
		return errors.Wrap(ErrNetwork, err.Error())
	}
	return nil
}

// putIDString sends a client/server ID string with length prefix
func putIDString(ctx context.Context, msg *message.Message, value string) error {
	// Send length first
	length := len(value)
	if err := putInt(ctx, msg, length); err != nil {
		return err // Already wrapped
	}

	// Then send the string itself
	if err := msg.PutString(ctx, value); err != nil {
		return errors.Wrap(ErrNetwork, err.Error())
	}
	return nil
}

// putToken sends a token string without separate length prefix
func putToken(ctx context.Context, msg *message.Message, value string) error {
	// Tokens use PutString directly which handles null termination
	// and prevents null character truncation
	if err := msg.PutString(ctx, value); err != nil {
		return errors.Wrap(ErrNetwork, err.Error())
	}
	return nil
}

func getInt(ctx context.Context, msg *message.Message) (int, error) {
	value, err := msg.GetInt(ctx)
	if err != nil {
		return 0, errors.Wrap(ErrNetwork, err.Error())
	}
	return value, nil
}

// Retrieve an ID string from the message with max size enforcement
// First reads expected length, then reads string with max size limit,
// and verifies the actual length matches the expected length
func getIDString(ctx context.Context, msg *message.Message) (string, error) {
	// First, read the expected length
	expectedLen, err := getInt(ctx, msg)
	if err != nil {
		return "", err // Already wrapped with ErrNetwork
	}

	// Check if expected length exceeds maximum
	if expectedLen > AUTH_PW_MAX_NAME_LEN {
		return "", fmt.Errorf("ID string length (%d) exceeds maximum (%d)", expectedLen, AUTH_PW_MAX_NAME_LEN)
	}

	// Read the string with max size enforcement
	data, err := msg.GetStringWithMaxSize(ctx, AUTH_PW_MAX_NAME_LEN)
	if err != nil {
		return "", errors.Wrap(ErrNetwork, err.Error())
	}

	// Verify the actual length matches the expected length
	actualLen := len(data)
	if actualLen != expectedLen {
		return "", fmt.Errorf("ID string length mismatch: expected %d bytes (including null), got %d bytes", expectedLen, actualLen)
	}

	return data, nil
}

func getToken(ctx context.Context, msg *message.Message) (string, error) {
	// Tokens use GetStringWithMaxSize to limit size to 64KB
	// Tokens are encoded to prevent null characters, but we still need size limits
	data, err := msg.GetStringWithMaxSize(ctx, AUTH_PW_MAX_TOKEN_LEN)
	if err != nil {
		return "", errors.Wrap(ErrNetwork, err.Error())
	}
	return data, nil
}

// TokenAuthState represents the current state in TOKEN authentication protocol
type TokenAuthState int

const (
	TokenStateInit             TokenAuthState = iota
	TokenStateSentRA                          // Client has sent RA
	TokenStateReceivedResponse                // Client has received server response
	TokenStateAuthComplete                    // Authentication complete
)

// AKEP2 protocol constants for TOKEN authentication
const (
	TokenKeyLength = 32 // 256-bit key length
)

// AUTH_PW protocol constants matching HTCondor
const (
	AUTH_PW_A_OK          = 0     // Authentication OK status
	AUTH_PW_ERROR         = -1    // Authentication error status
	AUTH_PW_ABORT         = 1     // Authentication abort status
	AUTH_PW_KEY_LEN       = 256   // Maximum key length in bytes
	AUTH_PW_MAX_NAME_LEN  = 1024  // Maximum length for client/server IDs
	AUTH_PW_MAX_TOKEN_LEN = 65536 // Maximum token length (64KB)
)

// TokenAuthData holds data for AKEP2 protocol
type TokenAuthData struct {
	ClientID    string // Client identity (username@domain or token subject)
	ServerID    string // Server identity
	RA          []byte // Client random nonce
	RB          []byte // Server random nonce
	Token       string // JWT token (header.payload)
	Signature   []byte // JWT signature (used as shared key)
	SharedKey   []byte // Derived shared key K
	SharedKeyK  []byte // HMAC key K
	SharedKeyKP []byte // Key derivation key K'
	SessionKey  []byte // Final session key W = h'K'(RB)
	State       TokenAuthState
	// Error handling for graceful handshake completion
	AuthError   error // Stored authentication error
	ErrorStatus int   // AUTH_PW status to send (AUTH_PW_A_OK or AUTH_PW_ERROR)
}

// performTokenAuthentication performs token-based authentication (TOKEN, SCITOKENS, IDTOKENS)
// Implements the AKEP2 protocol as described in HTCondor's condor_auth_passwd.cpp
func (a *Authenticator) performTokenAuthentication(ctx context.Context, method AuthMethod, negotiation *SecurityNegotiation) error {
	if negotiation.IsClient {
		return a.performTokenAuthenticationClient(ctx, method, negotiation)
	}
	return a.performTokenAuthenticationServer(ctx, method, negotiation)
}

// performTokenAuthenticationClient handles client side of TOKEN authentication
func (a *Authenticator) performTokenAuthenticationClient(ctx context.Context, method AuthMethod, negotiation *SecurityNegotiation) error {
	// Initialize token authentication data
	authData := &TokenAuthData{
		State:       TokenStateInit,
		ErrorStatus: AUTH_PW_A_OK, // Start with OK status
	}

	// Load token based on method type
	if err := a.loadTokenForAuthentication(method, authData, negotiation); err != nil {
		a.storeAuthError(authData, fmt.Errorf("failed to load token: %w", err))
	}

	// Derive shared keys from token signature using HKDF
	if authData.AuthError == nil {
		if err := a.deriveTokenKeys(authData); err != nil {
			a.storeAuthError(authData, fmt.Errorf("failed to derive keys from token: %w", err))
		}
	}

	// Step 1: Generate and send RA
	if err := a.sendClientTokenStep1(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		a.storeAuthError(authData, fmt.Errorf("failed to send token auth step 1: %w", err))
	}

	// Step 2: Receive server response and verify
	if err := a.receiveTokenStep2(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		fmt.Printf("Failed to receive token auth step 2: %v\n", err)
		a.storeAuthError(authData, fmt.Errorf("failed to receive token auth step 2: %w", err))
	}

	// Step 3: Send final response
	if err := a.sendClientTokenStep3(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		a.storeAuthError(authData, fmt.Errorf("failed to send token auth step 3: %w", err))
	}

	// Check if we had any authentication errors during the handshake
	if authData.AuthError != nil {
		return authData.AuthError
	}

	// Store session key in negotiation
	negotiation.SharedSecret = authData.SessionKey

	return nil
}

// performTokenAuthenticationServer handles server side of TOKEN authentication
func (a *Authenticator) performTokenAuthenticationServer(ctx context.Context, method AuthMethod, negotiation *SecurityNegotiation) error {
	// Initialize token authentication data
	authData := &TokenAuthData{
		State:       TokenStateInit,
		ErrorStatus: AUTH_PW_A_OK, // Start with OK status
	}

	// Step 1: Receive client RA and token
	if err := a.receiveServerTokenStep1(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		a.storeAuthError(authData, fmt.Errorf("failed to receive token auth step 1: %w", err))
	}

	// Validate token and derive keys
	if authData.AuthError == nil {
		if err := a.validateTokenAndDeriveKeys(authData, negotiation); err != nil {
			a.storeAuthError(authData, fmt.Errorf("failed to validate token: %w", err))
		}
	}

	// Step 2: Send server response
	if err := a.sendServerTokenStep2(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		a.storeAuthError(authData, fmt.Errorf("failed to send token auth step 2: %w", err))
	}

	// Step 3: Receive and verify client final response
	if err := a.receiveServerTokenStep3(ctx, authData, negotiation); err != nil {
		// Network errors should abort immediately
		if errors.Is(err, ErrNetwork) {
			return errors.Unwrap(err)
		}
		a.storeAuthError(authData, fmt.Errorf("failed to receive token auth step 3: %w", err))
	}

	// Check if we had any authentication errors during the handshake
	if authData.AuthError != nil {
		return authData.AuthError
	}

	// Store session key and authenticated user info
	negotiation.SharedSecret = authData.SessionKey
	if authData.ClientID != "" {
		// Parse user@domain from token subject
		parts := strings.Split(authData.ClientID, "@")
		if len(parts) >= 1 {
			negotiation.User = parts[0]
		}
	}

	return nil
}

// loadTokenForAuthentication loads and parses the JWT token for authentication
func (a *Authenticator) loadTokenForAuthentication(method AuthMethod, authData *TokenAuthData, negotiation *SecurityNegotiation) error {
	config := negotiation.ClientConfig

	// Try ClientConfig.TokenFile first if specified
	if config.TokenFile != "" {
		tokenStr, err := a.findCompatibleTokenInFile(config.TokenFile, config)
		if err == nil {
			// Found a compatible token, use it
			return a.loadSingleToken(tokenStr, authData)
		}
		// If file doesn't exist or has no compatible tokens, continue to directory
	}

	// Try tokens from TokenDir
	if config.TokenDir != "" {
		tokenPaths := a.scanTokenDirectory(config.TokenDir)
		for _, tokenPath := range tokenPaths {
			tokenStr, err := a.findCompatibleTokenInFile(tokenPath, config)
			if err == nil {
				// Found a compatible token, use it
				return a.loadSingleToken(tokenStr, authData)
			}
			// Continue to next file
		}
	}

	// No compatible token found
	return fmt.Errorf("no compatible tokens found (check TokenFile and TokenDir configuration)")
}

// loadSingleToken loads and parses a single JWT token string
func (a *Authenticator) loadSingleToken(tokenStr string, authData *TokenAuthData) error {
	// Parse JWT token (format: header.payload.signature)
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Store token (header.payload) and decode signature
	authData.Token = parts[0] + "." + parts[1]

	// Decode base64url signature to get shared secret
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWT signature: %w", err)
	}
	authData.Signature = signature

	// Parse payload to get subject (client ID)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON payload to extract subject
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("failed to parse JWT payload as JSON: %w", err)
	}

	// Extract subject claim
	if sub, ok := claims["sub"]; ok {
		if subStr, ok := sub.(string); ok {
			authData.ClientID = subStr
		} else {
			return fmt.Errorf("JWT subject claim is not a string")
		}
	}

	if authData.ClientID == "" {
		return fmt.Errorf("JWT token missing required subject (sub) claim")
	}

	return nil
}

// findCompatibleTokenInFile reads a token file and returns the first compatible token
// Reads line by line, skipping comments and empty lines, until finding a compatible token or EOF
func (a *Authenticator) findCompatibleTokenInFile(tokenPath string, config *SecurityConfig) (string, error) {
	// Read token file
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token file %s: %w", tokenPath, err)
	}

	// Process file line by line
	lines := strings.Split(string(tokenData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if this token is compatible
		if a.isTokenCompatibleString(line, config) {
			return line, nil
		}
		// Continue to next line if not compatible
	}

	// No compatible token found in file
	return "", fmt.Errorf("no compatible tokens found in %s", tokenPath)
}

// deriveTokenKeys derives HMAC and key derivation keys from JWT signature using HKDF
func (a *Authenticator) deriveTokenKeys(authData *TokenAuthData) error {
	// Use HKDF to derive K and K' from JWT signature
	// This follows HTCondor's approach in condor_auth_passwd.cpp

	// Create seeds for K and K' derivation
	seedKA := make([]byte, AUTH_PW_KEY_LEN+len(authData.Token))
	seedKB := make([]byte, AUTH_PW_KEY_LEN+len(authData.Token))

	// HTCondor-compatible seed constants from condor_auth_passwd.cpp setup_seed() function
	// These are the AUTH_PW_KEY_LEN (256) byte seed arrays used by HTCondor for AKEP2 key derivation
	// and ensure full compatibility with HTCondor's TOKEN authentication implementation.
	htcondorSeedKA := [256]byte{
		62, 74, 80, 32, 71, 213, 244, 229, 220, 124, 105, 187, 82, 16, 203, 182, 22, 122, 221, 128, 132, 247, 221, 158, 243, 173, 44, 202, 113, 210, 131, 221, 17, 74, 79, 187, 123, 30, 233, 10, 223, 168, 98, 196, 67, 4, 222, 84, 115, 163, 23, 47, 115, 92, 44, 187, 110, 119, 91, 93, 64, 211, 159, 172, 232, 115, 24, 37, 35, 249, 37, 43, 98, 59, 224, 212, 177, 103, 163, 168, 4, 12, 172, 254, 233, 238, 61, 160, 44, 10, 187, 244, 217, 216, 177, 31, 137, 0, 76, 148, 57, 35, 206, 93, 149, 8, 187, 63, 4, 188, 102, 163, 250, 32, 161, 58, 65, 108, 94, 111, 78, 13, 49, 135, 212, 95, 199, 131, 53, 197, 228, 133, 219, 44, 90, 55, 23, 151, 12, 194, 110, 123, 107, 157, 25, 101, 180, 122, 103, 223, 119, 163, 31, 34, 240, 138, 108, 11, 165, 112, 151, 162, 26, 156, 167, 198, 4, 36, 247, 39, 57, 171, 92, 185, 21, 164, 24, 91, 209, 9, 130, 142, 53, 228, 33, 8, 171, 133, 28, 8, 163, 223, 253, 224, 227, 176, 111, 61, 57, 56, 205, 173, 109, 246, 239, 154, 111, 109, 194, 203, 116, 240, 34, 133, 18, 235, 122, 61, 104, 35, 1, 6, 132, 176, 21, 193, 42, 195, 1, 76, 79, 159, 147, 142, 56, 77, 173, 30, 59, 215, 69, 255, 140, 20, 31, 215, 11, 70, 91, 168, 175, 93, 27, 152, 180, 177,
	}

	htcondorSeedKB := [256]byte{
		1, 0, 38, 173, 117, 223, 198, 193, 144, 165, 162, 102, 176, 209, 181, 216, 96, 247, 207, 163, 132, 103, 32, 85, 1, 205, 70, 13, 74, 136, 212, 115, 250, 82, 224, 179, 233, 20, 30, 51, 201, 125, 133, 30, 238, 45, 211, 54, 50, 243, 136, 103, 104, 239, 1, 14, 200, 223, 221, 102, 138, 222, 146, 213, 195, 67, 8, 187, 36, 56, 149, 216, 78, 215, 133, 226, 114, 104, 204, 94, 231, 86, 13, 228, 152, 40, 250, 183, 102, 194, 173, 140, 11, 44, 10, 251, 67, 92, 56, 45, 181, 210, 255, 54, 168, 174, 173, 88, 32, 71, 10, 154, 212, 93, 121, 133, 111, 94, 46, 206, 137, 75, 210, 80, 121, 41, 220, 242, 111, 125, 9, 240, 2, 143, 26, 196, 217, 113, 244, 130, 12, 95, 84, 113, 126, 157, 205, 171, 235, 33, 95, 97, 101, 93, 234, 212, 183, 44, 61, 59, 95, 102, 250, 75, 48, 184, 88, 136, 214, 47, 172, 212, 18, 156, 19, 4, 145, 159, 105, 173, 109, 140, 44, 67, 217, 206, 92, 219, 49, 212, 88, 3, 82, 199, 54, 43, 141, 128, 183, 239, 27, 186, 93, 103, 102, 96, 169, 68, 118, 69, 2, 249, 29, 29, 60, 84, 145, 12, 8, 139, 204, 183, 43, 17, 148, 138, 94, 26, 29, 205, 4, 54, 156, 23, 210, 152, 128, 76, 33, 110, 122, 38, 144, 184, 192, 233, 112, 54, 51, 0, 208, 146, 223, 36, 251, 140,
	}

	// Fill seeds with HTCondor seed data + token
	copy(seedKA[:AUTH_PW_KEY_LEN], htcondorSeedKA[:])
	copy(seedKA[AUTH_PW_KEY_LEN:], []byte(authData.Token))
	copy(seedKB[:AUTH_PW_KEY_LEN], htcondorSeedKB[:])
	copy(seedKB[AUTH_PW_KEY_LEN:], []byte(authData.Token))

	// Derive K (HMAC key) using HKDF
	hkdfKA := hkdf.New(sha256.New, authData.Signature, seedKA, []byte("master ka"))
	authData.SharedKeyK = make([]byte, TokenKeyLength)
	if _, err := io.ReadFull(hkdfKA, authData.SharedKeyK); err != nil {
		return fmt.Errorf("failed to derive shared key K: %w", err)
	}

	// Derive K' (key derivation key) using HKDF
	hkdfKB := hkdf.New(sha256.New, authData.Signature, seedKB, []byte("master kb"))
	authData.SharedKeyKP = make([]byte, TokenKeyLength)
	if _, err := io.ReadFull(hkdfKB, authData.SharedKeyKP); err != nil {
		return fmt.Errorf("failed to derive shared key K': %w", err)
	}

	return nil
}

// sendClientTokenStep1 sends RA (client random nonce) to server
// AKEP2 Step 1: A -> B : rA
func (a *Authenticator) sendClientTokenStep1(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Generate random nonce RA only if we don't have an error
	if authData.ErrorStatus == AUTH_PW_A_OK {
		authData.RA = make([]byte, AUTH_PW_KEY_LEN)
		if _, err := rand.Read(authData.RA); err != nil {
			return fmt.Errorf("failed to generate client nonce RA: %w", err)
		}
	}

	// Create message to send client data following HTCondor pattern:
	// client_status, send_a_len, send_a, init_token, send_b_len, send_b (put_bytes)
	msg := message.NewMessageForStream(a.stream)

	// Send client status (AUTH_PW_A_OK or AUTH_PW_ERROR)
	if err := putInt(ctx, msg, int(authData.ErrorStatus)); err != nil {
		return fmt.Errorf("failed to put client status: %w", err)
	}

	// Send client ID and token based on error status
	if authData.ErrorStatus == AUTH_PW_ERROR {
		// Send empty data when in error state
		if err := a.sendEmptyData(ctx, msg, "client ID"); err != nil {
			return err
		}
		if err := a.sendEmptyToken(ctx, msg); err != nil {
			return err
		}
		// Send empty RA
		if err := a.sendEmptyBytes(ctx, msg, "RA"); err != nil {
			return err
		}
	} else {
		// Send real data when OK
		// Send client ID (HTCondor: send_a_len = strlen(send_a))
		if err := putIDString(ctx, msg, authData.ClientID); err != nil {
			return fmt.Errorf("failed to put client ID: %w", err)
		}

		// Send token
		if err := putToken(ctx, msg, authData.Token); err != nil {
			return fmt.Errorf("failed to put token: %w", err)
		}

		// Send RA length then raw binary data (HTCondor uses code(len) + put_bytes pattern)
		if err := putInt(ctx, msg, len(authData.RA)); err != nil {
			return fmt.Errorf("failed to put RA length: %w", err)
		}
		// Write raw bytes directly to message buffer
		if err := a.putRawBytes(ctx, msg, authData.RA); err != nil {
			return fmt.Errorf("failed to put client nonce RA: %w", err)
		}
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	authData.State = TokenStateSentRA
	return nil
}

// receiveTokenStep2 receives and verifies server response
// AKEP2 Step 2: A <- B : T, hK(T) where T = (A, B, rA, rB)
func (a *Authenticator) receiveTokenStep2(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Receive server response following HTCondor pattern:
	// server_status, send_a_len, send_a, send_b_len, send_b, send_ra_len, send_ra (put_bytes), send_rb_len, send_rb (put_bytes), send_hkt_len, send_hkt (put_bytes)
	msg := message.NewMessageFromStream(a.stream)

	// Receive server status
	status, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive server status: %w", err)
	}

	if status == AUTH_PW_ERROR {
		// Server indicated error, store generic error and continue to read empty data
		a.storeAuthError(authData, fmt.Errorf("server authentication failed"))

		// Read empty data that server should send in error state
		// Client ID
		if _, err := getIDString(ctx, msg); err != nil {
			return fmt.Errorf("failed to receive client ID: %w", err)
		}

		// Server ID (getString handles length automatically)
		if _, err := getIDString(ctx, msg); err != nil {
			return fmt.Errorf("failed to receive server ID: %w", err)
		}

		// Read empty RA, RB, MAC fields
		for _, fieldName := range []string{"RA", "RB", "MAC"} {
			if fieldLen, err := getInt(ctx, msg); err != nil {
				return fmt.Errorf("failed to receive %s length: %w", fieldName, err)
			} else if fieldLen > 0 {
				if _, err := a.getRawBytes(ctx, msg, fieldLen); err != nil {
					return fmt.Errorf("failed to receive %s: %w", fieldName, err)
				}
			}
		}

		authData.State = TokenStateReceivedResponse
		return nil
	}

	if status != AUTH_PW_A_OK {
		return fmt.Errorf("server authentication error: status %d", status)
	}

	// Server status is OK, proceed with normal authentication
	// Receive client ID echo (should match what we sent)
	clientIDEcho, err := getIDString(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client ID echo: %w", err)
	}
	if clientIDEcho != authData.ClientID {
		return fmt.Errorf("client ID mismatch: sent %s, received %s", authData.ClientID, clientIDEcho)
	}

	// Receive server ID
	serverID, err := getIDString(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive server ID: %w", err)
	}
	authData.ServerID = serverID

	// Receive RA length
	raLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive RA length: %w", err)
	}
	if raLen > AUTH_PW_KEY_LEN {
		return fmt.Errorf("RA length (%d) exceeds maximum (%d)", raLen, AUTH_PW_KEY_LEN)
	}

	// Receive RA echo as raw binary data (should match what we sent)
	raEcho, err := a.getRawBytes(ctx, msg, raLen)
	if err != nil {
		return fmt.Errorf("failed to receive RA echo: %w", err)
	}
	if !bytesEqual(raEcho, authData.RA) {
		return fmt.Errorf("RA mismatch")
	}

	// Receive RB length
	rbLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive RB length: %w", err)
	}
	if rbLen > AUTH_PW_KEY_LEN {
		return fmt.Errorf("RB length (%d) exceeds maximum (%d)", rbLen, AUTH_PW_KEY_LEN)
	}

	// Receive server nonce RB as raw binary data
	authData.RB, err = a.getRawBytes(ctx, msg, rbLen)
	if err != nil {
		return fmt.Errorf("failed to receive server nonce RB: %w", err)
	}

	// Receive server MAC length
	macLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive server MAC length: %w", err)
	}

	// Receive server MAC as raw binary data
	serverMAC, err := a.getRawBytes(ctx, msg, macLen)
	if err != nil {
		return fmt.Errorf("failed to receive server MAC: %w", err)
	}

	// Verify server MAC: hK(A, B, rA, rB)
	if err := a.verifyTokenMAC(authData.SharedKeyK, authData.ClientID, authData.ServerID, authData.RA, authData.RB, serverMAC); err != nil {
		return fmt.Errorf("server MAC verification failed: %w", err)
	}

	authData.State = TokenStateReceivedResponse
	return nil
}

// sendClientTokenStep3 sends client's final response
// AKEP2 Step 3: A -> B : (A, rB), hK(A, rB)
func (a *Authenticator) sendClientTokenStep3(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Create message to send client response following HTCondor pattern:
	// client_status, send_a_len, send_a, send_b_len, send_b (put_bytes), send_c_len, send_c (put_bytes)
	msg := message.NewMessageForStream(a.stream)

	// Send client status (AUTH_PW_A_OK or AUTH_PW_ERROR)
	if err := putInt(ctx, msg, int(authData.ErrorStatus)); err != nil {
		return fmt.Errorf("failed to put client status: %w", err)
	}

	if authData.ErrorStatus == AUTH_PW_ERROR {
		// Send empty data when in error state
		if err := a.sendEmptyData(ctx, msg, "client ID"); err != nil {
			return err
		}
		// Send empty RB and MAC
		if err := a.sendEmptyBytes(ctx, msg, "RB"); err != nil {
			return err
		}
		if err := a.sendEmptyBytes(ctx, msg, "MAC"); err != nil {
			return err
		}
	} else {
		// Send real data when OK
		// Send client ID
		if err := putIDString(ctx, msg, authData.ClientID); err != nil {
			return fmt.Errorf("failed to put client ID: %w", err)
		}

		// Send RB length then raw binary data
		if err := putInt(ctx, msg, len(authData.RB)); err != nil {
			return fmt.Errorf("failed to put RB length: %w", err)
		}
		if err := a.putRawBytes(ctx, msg, authData.RB); err != nil {
			return fmt.Errorf("failed to put RB: %w", err)
		}

		// Compute client MAC: hK(A, rB)
		clientMAC := a.computeTokenMAC(authData.SharedKeyK, authData.ClientID, []byte{'\x00'}, authData.RB)

		// Send MAC length then raw binary data
		if err := putInt(ctx, msg, len(clientMAC)); err != nil {
			return fmt.Errorf("failed to put client MAC length: %w", err)
		}
		if err := a.putRawBytes(ctx, msg, clientMAC); err != nil {
			return fmt.Errorf("failed to put client MAC: %w", err)
		}

		// Only derive session key if we don't have an error
		if authData.AuthError == nil {
			// Derive session key: W = hkdf(rB, "session key", "htcondor")
			authData.SessionKey = a.deriveSessionKey(authData.RB)
		}
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	authData.State = TokenStateAuthComplete
	return nil
}

// receiveServerTokenStep1 receives client data in server mode
// AKEP2 Step 1: Server receives client ID, RA, and token
func (a *Authenticator) receiveServerTokenStep1(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Receive client message following HTCondor pattern:
	// client_status, send_a_len, send_a, init_token, send_b_len, send_b (put_bytes)
	msg := message.NewMessageFromStream(a.stream)

	// Receive client status
	status, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client status: %w", err)
	}

	if status == AUTH_PW_ERROR {
		// Client indicated error, store generic error and read empty data
		a.storeAuthError(authData, fmt.Errorf("client authentication failed"))

		// Read empty data that client should send in error state
		// Client ID
		if _, err := getIDString(ctx, msg); err != nil {
			return fmt.Errorf("failed to receive client ID: %w", err)
		}

		// Read token (should be empty)
		if _, err := getToken(ctx, msg); err != nil {
			return fmt.Errorf("failed to receive token: %w", err)
		}

		// Read RA length (should be 0)
		raLen, err := getInt(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to receive RA length: %w", err)
		}
		if raLen > 0 {
			if _, err := a.getRawBytes(ctx, msg, raLen); err != nil {
				return fmt.Errorf("failed to receive RA: %w", err)
			}
		}

		authData.State = TokenStateSentRA
		return nil
	}

	if status != AUTH_PW_A_OK {
		return fmt.Errorf("client authentication error: status %d", status)
	}

	// Client status is OK, proceed with normal authentication
	// Receive client ID
	clientID, err := getIDString(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client ID: %w", err)
	}
	authData.ClientID = clientID

	// Receive token
	token, err := getToken(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive token: %w", err)
	}
	authData.Token = token

	// Receive RA length
	raLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive RA length: %w", err)
	}
	if raLen > AUTH_PW_KEY_LEN {
		return fmt.Errorf("RA length (%d) exceeds maximum (%d)", raLen, AUTH_PW_KEY_LEN)
	}

	// Receive RA as raw binary data (HTCondor put_bytes pattern)
	authData.RA, err = a.getRawBytes(ctx, msg, raLen)
	if err != nil {
		return fmt.Errorf("failed to receive client nonce RA: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	// Try to read one more byte to trigger EOM detection - should get EOF
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("error checking for message completion: %w", err)
		}
		return fmt.Errorf("incomplete message: expected EOM but more data available")
	}

	authData.State = TokenStateSentRA
	return nil
}

// validateTokenAndDeriveKeys validates the received token and derives authentication keys
func (a *Authenticator) validateTokenAndDeriveKeys(authData *TokenAuthData, negotiation *SecurityNegotiation) error {
	// Validate token format
	if authData.Token == "" {
		return fmt.Errorf("empty token received")
	}

	// Parse JWT to get parts - token should be header.payload (signature sent separately in AKEP2)
	parts := strings.Split(authData.Token, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid JWT token format: expected 2 parts (header.payload), got %d", len(parts))
	}

	// Decode and parse header to extract key ID
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Extract key ID from header
	keyID := ""
	if kid, ok := header["kid"]; ok {
		if kidStr, ok := kid.(string); ok {
			keyID = kidStr
		} else {
			return fmt.Errorf("JWT key ID (kid) is not a string")
		}
	}
	// Empty key ID defaults to "POOL" like in HTCondor
	if keyID == "" {
		keyID = "POOL"
	}

	// Load signing key based on key ID (similar to HTCondor's getTokenSigningKey)
	signingKey, err := a.loadSigningKey(keyID, negotiation.ServerConfig)
	if err != nil {
		return fmt.Errorf("failed to load signing key for key ID %s: %w", keyID, err)
	}

	// Decode and parse payload for validation
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Validate token timing claims
	if err := a.validateTokenTiming(claims, negotiation.ServerConfig); err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}

	// Extract subject from claims
	if sub, ok := claims["sub"]; ok {
		if subStr, ok := sub.(string); ok {
			authData.ClientID = subStr
		} else {
			return fmt.Errorf("JWT subject claim is not a string")
		}
	}

	if authData.ClientID == "" {
		return fmt.Errorf("JWT token missing required subject (sub) claim")
	}

	// For AKEP2 protocol, we need to derive the signature from the signing key and token
	// This simulates HTCondor's token signature computation
	authData.Signature = a.computeTokenSignature(signingKey, authData.Token)

	// Set server ID based on trust domain
	serverDomain := negotiation.ServerConfig.TrustDomain
	if serverDomain == "" {
		serverDomain = "htcondor"
	}
	authData.ServerID = "server@" + serverDomain

	// Derive keys using the same method as client
	return a.deriveTokenKeys(authData)
}

// simple_scramble undoes HTCondor's simple scrambling (XOR with 0xdeadbeef)
// This matches the implementation in condor_utils/secure_file.cpp
func simple_scramble(scrambled []byte) []byte {
	deadbeef := []byte{0xde, 0xad, 0xbe, 0xef}
	unscrambled := make([]byte, len(scrambled))
	for i := 0; i < len(scrambled); i++ {
		unscrambled[i] = scrambled[i] ^ deadbeef[i%len(deadbeef)]
	}
	return unscrambled
}

// loadSigningKey loads the token signing key for the given key ID
// This follows HTCondor's getTokenSigningKey pattern from store_cred.cpp
func (a *Authenticator) loadSigningKey(keyID string, config *SecurityConfig) ([]byte, error) {
	// Get configuration from authenticator's security config
	var poolKeyFile, keyDir string
	var doubleTheKey bool
	if config != nil {
		poolKeyFile = config.TokenPoolSigningKeyFile
		keyDir = config.TokenSigningKeyDir
	}

	if keyID == "POOL" {
		// Pool signing key - read from SEC_TOKEN_POOL_SIGNING_KEY_FILE
		// Check environment variable first, then config
		if poolKeyFile == "" {
			poolKeyFile = os.Getenv("SEC_TOKEN_POOL_SIGNING_KEY_FILE")
		}
		if poolKeyFile == "" {
			return nil, fmt.Errorf("pool signing key file not configured (set TokenPoolSigningKeyFile or SEC_TOKEN_POOL_SIGNING_KEY_FILE)")
		}

		keyData, err := os.ReadFile(poolKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read pool signing key from %s: %w", poolKeyFile, err)
		}

		// For POOL keys, the contents are repeated twice (doubled)
		doubleTheKey = true

		// HTCondor does NOT trim whitespace - read full file contents
		// Apply simple_scramble to undo the obfuscation
		key := simple_scramble(keyData)
		if len(key) == 0 {
			return nil, fmt.Errorf("pool signing key file %s is empty", poolKeyFile)
		}

		// Double the key for POOL (concatenate with itself)
		if doubleTheKey {
			doubled := make([]byte, len(key)*2)
			copy(doubled, key)
			copy(doubled[len(key):], key)
			return doubled, nil
		}

		return key, nil
	}

	// Named signing keys - read from SEC_PASSWORD_DIRECTORY/{keyID}
	// Check environment variable first, then config
	if keyDir == "" {
		keyDir = os.Getenv("SEC_PASSWORD_DIRECTORY")
	}
	if keyDir == "" {
		return nil, fmt.Errorf("signing key directory not configured (set TokenSigningKeyDir or SEC_PASSWORD_DIRECTORY)")
	}

	// Sanitize key ID to prevent directory traversal
	if strings.Contains(keyID, "/") || strings.Contains(keyID, "..") {
		return nil, fmt.Errorf("invalid key ID: %s (contains invalid characters)", keyID)
	}

	keyPath := keyDir + "/" + keyID
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key from %s: %w", keyPath, err)
	}

	// HTCondor does NOT trim whitespace - read full file contents
	// Apply simple_scramble to undo the obfuscation
	key := simple_scramble(keyData)
	if len(key) == 0 {
		return nil, fmt.Errorf("signing key file %s is empty", keyPath)
	}

	return key, nil
}

// validateTokenTiming validates the expiration and issued-at times of a JWT
// This follows HTCondor's token timing validation in condor_auth_passwd.cpp
func (a *Authenticator) validateTokenTiming(claims map[string]interface{}, config *SecurityConfig) error {
	now := time.Now().Unix()

	// Check expiration time (exp claim)
	if exp, ok := claims["exp"]; ok {
		var expTime int64
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		default:
			return fmt.Errorf("JWT exp claim is not a valid timestamp")
		}

		if now >= expTime {
			expiredFor := now - expTime
			return fmt.Errorf("token has been expired for %d seconds", expiredFor)
		}
	}

	// Check issued-at time with max age (iat claim)
	// Get max age from config or environment, defaulting to 1 hour like HTCondor
	maxAge := int64(3600) // Default to 1 hour
	if config != nil && config.TokenMaxAge > 0 {
		maxAge = int64(config.TokenMaxAge)
	} else if envMaxAge := os.Getenv("SEC_TOKEN_MAX_AGE"); envMaxAge != "" {
		// Parse environment variable if set
		if parsed, err := time.ParseDuration(envMaxAge + "s"); err == nil {
			maxAge = int64(parsed.Seconds())
		}
	}
	if iat, ok := claims["iat"]; ok {
		var iatTime int64
		switch v := iat.(type) {
		case float64:
			iatTime = int64(v)
		case int64:
			iatTime = v
		case int:
			iatTime = int64(v)
		default:
			return fmt.Errorf("JWT iat claim is not a valid timestamp")
		}

		age := now - iatTime
		if maxAge > 0 && age > maxAge {
			return fmt.Errorf("token age (%d) is greater than max age (%d)", age, maxAge)
		}
	}

	return nil
}

// computeTokenSignature computes the JWT signature for AKEP2 protocol
// This uses HKDF to expand the variable-length signing key to 32 bytes,
// then computes HMAC-SHA256 of the token data.
// This follows HTCondor's pattern in condor_auth_passwd.cpp
func (a *Authenticator) computeTokenSignature(signingKey []byte, tokenData string) []byte {
	// First, use HKDF to expand the variable-length signing key to 32 bytes
	// This matches HTCondor's hkdf call:
	// hkdf(sk->shared_key, sk->len, "htcondor", 8, "master jwt", 10, &jwt_key[0], 32)
	const keyStrengthBytes = 32 // key_strength_bytes_v2() returns 32
	jwtKey := make([]byte, keyStrengthBytes)
	hkdfReader := hkdf.New(sha256.New, signingKey, []byte("htcondor"), []byte("master jwt"))
	if _, err := io.ReadFull(hkdfReader, jwtKey); err != nil {
		// This should never fail with a valid HKDF setup
		// Return a deterministic but invalid signature on error
		return make([]byte, keyStrengthBytes)
	}

	// Use HMAC-SHA256 with the expanded key to compute the signature
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(tokenData))
	signature := mac.Sum(nil)

	// Return first 32 bytes (full SHA256 output)
	if len(signature) >= 32 {
		return signature[:32]
	}
	// Pad if needed (shouldn't happen with SHA256)
	padded := make([]byte, 32)
	copy(padded, signature)
	return padded
}

// sendServerTokenStep2 sends server response to client
// AKEP2 Step 2: B -> A : T, hK(T) where T = (B, A, rA, rB)
func (a *Authenticator) sendServerTokenStep2(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Generate server nonce RB only if we don't have an error
	if authData.ErrorStatus == AUTH_PW_A_OK {
		authData.RB = make([]byte, AUTH_PW_KEY_LEN)
		if _, err := rand.Read(authData.RB); err != nil {
			return fmt.Errorf("failed to generate server nonce RB: %w", err)
		}
	}

	// Create message to send server response following HTCondor pattern:
	// server_status, send_a_len, send_a, send_b_len, send_b, send_ra_len, send_ra (put_bytes), send_rb_len, send_rb (put_bytes), send_hkt_len, send_hkt (put_bytes)
	msg := message.NewMessageForStream(a.stream)

	// Send server status (AUTH_PW_A_OK or AUTH_PW_ERROR)
	if err := putInt(ctx, msg, int(authData.ErrorStatus)); err != nil {
		return fmt.Errorf("failed to put server status: %w", err)
	}

	if authData.ErrorStatus == AUTH_PW_ERROR {
		// Send empty data when in error state
		if err := a.sendEmptyData(ctx, msg, "client ID"); err != nil {
			return err
		}
		if err := a.sendEmptyData(ctx, msg, "server ID"); err != nil {
			return err
		}
		// Send empty RA, RB, MAC
		for _, fieldName := range []string{"RA", "RB", "MAC"} {
			if err := a.sendEmptyBytes(ctx, msg, fieldName); err != nil {
				return err
			}
		}
	} else {
		// Send real data when OK
		// Send client ID echo
		if err := putIDString(ctx, msg, authData.ClientID); err != nil {
			return fmt.Errorf("failed to put client ID echo: %w", err)
		}

		// Send server ID
		if err := putIDString(ctx, msg, authData.ServerID); err != nil {
			return fmt.Errorf("failed to put server ID: %w", err)
		}

		// Send RA length then raw binary data (RA echo)
		if err := putInt(ctx, msg, len(authData.RA)); err != nil {
			return fmt.Errorf("failed to put RA length: %w", err)
		}
		if err := a.putRawBytes(ctx, msg, authData.RA); err != nil {
			return fmt.Errorf("failed to put RA echo: %w", err)
		}

		// Send RB length then raw binary data
		if err := putInt(ctx, msg, len(authData.RB)); err != nil {
			return fmt.Errorf("failed to put RB length: %w", err)
		}
		if err := a.putRawBytes(ctx, msg, authData.RB); err != nil {
			return fmt.Errorf("failed to put server nonce RB: %w", err)
		}

		// Compute server MAC: hK(A, B, rA, rB)
		serverMAC := a.computeTokenMAC(authData.SharedKeyK, authData.ClientID, []byte{' '}, authData.ServerID, []byte{'\x00'}, authData.RA, authData.RB)

		// Send MAC length then raw binary data
		if err := putInt(ctx, msg, len(serverMAC)); err != nil {
			return fmt.Errorf("failed to put server MAC length: %w", err)
		}
		if err := a.putRawBytes(ctx, msg, serverMAC); err != nil {
			return fmt.Errorf("failed to put server MAC: %w", err)
		}
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	return nil
}

// receiveServerTokenStep3 receives and verifies client final response
// AKEP2 Step 3: Server receives (A, rB), hK(A, rB)
func (a *Authenticator) receiveServerTokenStep3(ctx context.Context, authData *TokenAuthData, negotiation *SecurityNegotiation) error {

	// Receive client final message following HTCondor pattern:
	// client_status, send_a_len, send_a, send_b_len, send_b (put_bytes), send_c_len, send_c (put_bytes)
	msg := message.NewMessageFromStream(a.stream)

	// Receive client status
	status, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client status: %w", err)
	}

	if status == AUTH_PW_ERROR {
		// Client indicated error, store generic error and read empty data
		a.storeAuthError(authData, fmt.Errorf("client authentication failed"))

		// Read empty data that client should send in error state
		// Client ID
		if _, err := getIDString(ctx, msg); err != nil {
			return fmt.Errorf("failed to receive client ID: %w", err)
		}

		// Read empty RB and MAC
		for _, fieldName := range []string{"RB", "MAC"} {
			if fieldLen, err := getInt(ctx, msg); err != nil {
				return fmt.Errorf("failed to receive %s length: %w", fieldName, err)
			} else if fieldLen > 0 {
				if _, err := a.getRawBytes(ctx, msg, fieldLen); err != nil {
					return fmt.Errorf("failed to receive %s: %w", fieldName, err)
				}
			}
		}

		authData.State = TokenStateAuthComplete
		return nil
	}

	if status != AUTH_PW_A_OK {
		return fmt.Errorf("client authentication error: status %d", status)
	}

	// Client status is OK, proceed with normal authentication
	// Receive client ID (should match what we received before)
	clientID, err := getIDString(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client ID: %w", err)
	}
	if clientID != authData.ClientID {
		return fmt.Errorf("client ID mismatch in step 3: expected %s, got %s", authData.ClientID, clientID)
	}

	// Receive RB length
	rbLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive RB length: %w", err)
	}
	if rbLen > AUTH_PW_KEY_LEN {
		return fmt.Errorf("RB length (%d) exceeds maximum (%d)", rbLen, AUTH_PW_KEY_LEN)
	}

	// Receive RB as raw binary data (should match what we sent)
	rbEcho, err := a.getRawBytes(ctx, msg, rbLen)
	if err != nil {
		return fmt.Errorf("failed to receive RB echo: %w", err)
	}
	if !bytesEqual(rbEcho, authData.RB) {
		return fmt.Errorf("RB mismatch")
	}

	// Receive client MAC length
	macLen, err := getInt(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to receive client MAC length: %w", err)
	}

	// Receive client MAC as raw binary data
	clientMAC, err := a.getRawBytes(ctx, msg, macLen)
	if err != nil {
		return fmt.Errorf("failed to receive client MAC: %w", err)
	}

	// Verify client MAC: hK(A, rB)
	expectedMAC := a.computeTokenMAC(authData.SharedKeyK, authData.ClientID, []byte{'\x00'}, authData.RB)
	if !bytesEqual(clientMAC, expectedMAC) {
		return fmt.Errorf("client MAC verification failed")
	}

	// Verify we've received the complete message with EOM marker
	// Try to read one more byte to trigger EOM detection - should get EOF
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("error checking for message completion: %w", err)
		}
		return fmt.Errorf("incomplete message: expected EOM but more data available")
	}

	// Only derive session key if we don't have an error
	if authData.AuthError == nil {
		// Derive session key: W = hkdf(rB, "session key", "htcondor")
		authData.SessionKey = a.deriveSessionKey(authData.RB)
	}
	authData.State = TokenStateAuthComplete

	return nil
}

// Helper methods for TOKEN authentication

// storeAuthError stores an authentication error and sets error status
func (a *Authenticator) storeAuthError(authData *TokenAuthData, err error) {
	if authData.AuthError == nil { // Only store the first error
		authData.AuthError = err
		authData.ErrorStatus = AUTH_PW_ERROR
	}
}

// sendEmptyData sends zero-length ID strings when in error state
func (a *Authenticator) sendEmptyData(ctx context.Context, msg *message.Message, fieldName string) error {
	// Send empty ID string (putIDString handles length prefix automatically)
	if err := putIDString(ctx, msg, ""); err != nil {
		return fmt.Errorf("failed to put empty %s: %w", fieldName, err)
	}
	return nil
}

// sendEmptyToken sends zero-length token when in error state
func (a *Authenticator) sendEmptyToken(ctx context.Context, msg *message.Message) error {
	// Send empty token (putToken handles it without length prefix)
	if err := putToken(ctx, msg, ""); err != nil {
		return fmt.Errorf("failed to put empty token: %w", err)
	}
	return nil
}

// sendEmptyBytes sends zero-length binary data when in error state
func (a *Authenticator) sendEmptyBytes(ctx context.Context, msg *message.Message, fieldName string) error {
	// Send zero length
	if err := putInt(ctx, msg, 0); err != nil {
		return fmt.Errorf("failed to put %s length: %w", fieldName, err)
	}
	// No bytes to send for zero-length data
	return nil
}

// Helper methods for TOKEN authentication

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// verifyTokenMAC verifies HMAC-SHA256 MAC for AKEP2 protocol
func (a *Authenticator) verifyTokenMAC(key []byte, clientID, serverID string, ra, rb, expectedMAC []byte) error {
	computedMAC := a.computeTokenMAC(key, clientID, []byte{' '}, serverID, []byte{'\x00'}, ra, rb)
	if !bytesEqual(computedMAC, expectedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}

// computeTokenMAC computes HMAC-SHA1 MAC for AKEP2 protocol
func (a *Authenticator) computeTokenMAC(key []byte, parts ...interface{}) []byte {
	h := hmac.New(sha1.New, key)

	for _, part := range parts {
		switch v := part.(type) {
		case string:
			h.Write([]byte(v))
		case []byte:
			h.Write(v)
		}
	}

	// Return HMAC-SHA256
	return h.Sum(nil)
}

// deriveSessionKey derives the session key using HKDF
// This follows HTCondor's pattern:
// hkdf(rb, AUTH_PW_KEY_LEN, "session key", 11, "htcondor", 8, key, key_strength_bytes())
func (a *Authenticator) deriveSessionKey(rb []byte) []byte {
	// IKM: rb (server random nonce)
	// Salt: "session key"
	// Info: "htcondor"
	sessionKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, rb, []byte("session key"), []byte("htcondor"))
	_, _ = io.ReadFull(hkdfReader, sessionKey)
	return sessionKey
}

// putRawBytes writes raw bytes to message, matching HTCondor's put_bytes behavior
// Uses PutBytes to ensure null characters in data are not truncated
func (a *Authenticator) putRawBytes(ctx context.Context, msg *message.Message, data []byte) error {
	// Use PutBytes to write raw binary data directly
	// This ensures null characters within the data are preserved
	if err := msg.PutBytes(ctx, data); err != nil {
		return errors.Wrap(ErrNetwork, err.Error())
	}
	return nil
}

// getRawBytes reads raw bytes from message, matching HTCondor's get_bytes behavior
// Uses GetBytes to ensure null characters in data are not truncated
func (a *Authenticator) getRawBytes(ctx context.Context, msg *message.Message, length int) ([]byte, error) {
	// Use GetBytes to read raw binary data directly
	// This ensures null characters within the data are preserved
	data, err := msg.GetBytes(ctx, length)
	if err != nil {
		return nil, errors.Wrap(ErrNetwork, err.Error())
	}
	return data, nil
}

// hasCompatibleToken checks if any available token is compatible with the server
// Returns true if at least one token has:
// - issuer (iss claim) matching the server's TrustDomain
// - kid (key ID) appearing in the server's IssuerKeys list
// clientConfig provides TokenFile/TokenDir, serverConfig provides TrustDomain/IssuerKeys
func (a *Authenticator) hasCompatibleToken(clientConfig, serverConfig *SecurityConfig) bool {
	// Get all available token paths from client config (TokenFile + TokenDir)
	tokenPaths := a.getAvailableTokens(clientConfig)
	if len(tokenPaths) == 0 {
		return false
	}

	// Check each token for compatibility using server's requirements
	for _, tokenPath := range tokenPaths {
		if a.isTokenCompatible(tokenPath, serverConfig) {
			return true
		}
	}

	return false
}

// getAvailableTokens returns a list of all available token file paths
// Includes both TokenFile and tokens found in TokenDir
func (a *Authenticator) getAvailableTokens(config *SecurityConfig) []string {
	var tokenPaths []string

	// Add TokenFile if specified
	if config.TokenFile != "" {
		tokenPaths = append(tokenPaths, config.TokenFile)
	}

	// Scan TokenDir if specified
	if config.TokenDir != "" {
		dirTokens := a.scanTokenDirectory(config.TokenDir)
		tokenPaths = append(tokenPaths, dirTokens...)
	}

	return tokenPaths
}

// scanTokenDirectory scans a directory for token files
// Returns paths to all non-hidden files in the directory
// Skips lines starting with '#' (comments)
func (a *Authenticator) scanTokenDirectory(dirPath string) []string {
	var tokenPaths []string

	// Read directory contents
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		// Directory doesn't exist or can't be read - not an error, just no tokens
		return tokenPaths
	}

	// Collect non-hidden regular files
	for _, entry := range entries {
		// Skip directories and hidden files (starting with .)
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		// Add full path to token list
		tokenPath := dirPath + "/" + entry.Name()
		tokenPaths = append(tokenPaths, tokenPath)
	}

	return tokenPaths
}

// isTokenCompatible checks if a token file contains at least one compatible token
// Returns true if any token in the file matches the server's requirements
func (a *Authenticator) isTokenCompatible(tokenPath string, config *SecurityConfig) bool {
	tokenStr, err := a.findCompatibleTokenInFile(tokenPath, config)
	return err == nil && tokenStr != ""
}

// isTokenCompatibleString checks if a token string is compatible with the server's requirements
// Returns true if the token's issuer matches TrustDomain and kid is in IssuerKeys
func (a *Authenticator) isTokenCompatibleString(tokenStr string, config *SecurityConfig) bool {
	// Parse JWT structure (header.payload.signature)
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return false
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Parse JSON claims
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}

	// Extract issuer (iss) claim
	issuer, ok := claims["iss"].(string)
	if !ok {
		// If no issuer claim, only accept if TrustDomain is not configured
		return config.TrustDomain == ""
	}

	// Check if issuer matches TrustDomain (if TrustDomain is configured)
	if config.TrustDomain != "" && issuer != config.TrustDomain {
		return false
	}

	// If IssuerKeys is not configured, accept any token (backward compatibility)
	if len(config.IssuerKeys) == 0 {
		return true
	}

	// Extract key ID (kid) from header
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	var headerClaims map[string]any
	if err := json.Unmarshal(header, &headerClaims); err != nil {
		return false
	}

	kid, ok := headerClaims["kid"].(string)
	if !ok {
		// No kid in header - not compatible if IssuerKeys is configured
		return false
	}

	// Check if kid is in IssuerKeys list
	for _, acceptedKid := range config.IssuerKeys {
		if kid == acceptedKid {
			return true
		}
	}

	return false
}
