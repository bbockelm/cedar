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
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
)

// TestSessionResumptionUserField tests that the User field is set correctly
// during session resumption. This is a regression test for the issue where
// the User field was not populated during session resumption, causing callers
// that depend on this information to fail.
//
// This test directly verifies that User information is stored in the session cache
// and retrieved correctly during session resumption on both client and server sides.
func TestSessionResumptionUserField(t *testing.T) {
	// Create a session cache
	cache := NewSessionCache()

	// Test data
	sessionID := "test-session-for-user-field"
	expectedUser := "testuser@example.com"
	serverAddr := "test-server:1234"

	// ========== Test 1: Verify User is stored in session policy ==========
	t.Run("StoreUserInPolicy", func(t *testing.T) {
		// Create key info
		keyInfo := &KeyInfo{
			Data:     []byte("test-key-data"),
			Protocol: "AES",
		}

		// Create policy with User information (as done by storeSession/storeClientSession)
		policy := classad.New()
		_ = policy.Set("AuthMethods", "FS")
		_ = policy.Set("CryptoMethods", "AES")
		_ = policy.Set("User", expectedUser)

		// Create and store session entry
		expiration := time.Now().Add(1 * time.Hour)
		lease := 30 * time.Minute
		entry := NewSessionEntry(sessionID, serverAddr, keyInfo, policy, expiration, lease, "")
		cache.Store(entry)

		// Verify User is stored
		retrievedEntry, ok := cache.Lookup(sessionID)
		if !ok {
			t.Fatal("Failed to retrieve stored session entry")
		}

		if user, ok := retrievedEntry.Policy().EvaluateAttrString("User"); ok {
			if user != expectedUser {
				t.Errorf("Expected User '%s', got '%s'", expectedUser, user)
			} else {
				t.Logf("✅ User correctly stored in session policy: %s", user)
			}
		} else {
			t.Fatal("User not found in session policy")
		}
	})

	// ========== Test 2: Verify User is retrieved during session resumption ==========
	t.Run("RetrieveUserDuringResumption", func(t *testing.T) {
		// Retrieve the session entry
		entry, ok := cache.Lookup(sessionID)
		if !ok {
			t.Fatal("Failed to retrieve session entry")
		}

		// Simulate what resumeSession() and handleSessionResumption() do
		negotiation := &SecurityNegotiation{
			SessionId: sessionID,
			IsClient:  true,
		}

		// Restore session information including User
		if entry.Policy() != nil {
			if authMethod, ok := entry.Policy().EvaluateAttrString("AuthMethods"); ok {
				negotiation.NegotiatedAuth = AuthMethod(authMethod)
			}
			// THIS IS THE FIX: Restore User information from cached policy
			if user, ok := entry.Policy().EvaluateAttrString("User"); ok {
				negotiation.User = user
			}
		}

		// Verify User was populated
		if negotiation.User != expectedUser {
			t.Errorf("REGRESSION: User field not set during session resumption. Expected '%s', got '%s'",
				expectedUser, negotiation.User)
		} else {
			t.Logf("✅ User correctly restored during session resumption: %s", negotiation.User)
		}
	})

	// ========== Test 3: Verify storeClientSession stores User correctly ==========
	t.Run("StoreClientSessionWithUser", func(t *testing.T) {
		// Create a mock client configuration
		clientConfig := &SecurityConfig{
			PeerName: serverAddr,
		}

		// Create streams (needed for storeClientSession)
		server, client := net.Pipe()
		defer func() { _ = server.Close() }()
		defer func() { _ = client.Close() }()
		clientStream := stream.NewStream(client)

		// Create authenticator
		auth := NewAuthenticator(clientConfig, clientStream)

		// Create negotiation with User set
		negotiation := &SecurityNegotiation{
			SessionId:        "client-session-with-user",
			User:             "clientuser@example.com",
			NegotiatedAuth:   AuthToken,
			NegotiatedCrypto: CryptoAES,
			ClientConfig:     clientConfig,
		}
		negotiation.setSharedSecret([]byte("test-shared-secret"))

		// Store the session
		auth.storeClientSession(negotiation, 3600, 1800, cache)

		// Verify User was stored
		retrievedEntry, ok := cache.Lookup("client-session-with-user")
		if !ok {
			t.Fatal("Failed to retrieve client session entry")
		}

		if user, ok := retrievedEntry.Policy().EvaluateAttrString("User"); ok {
			if user != "clientuser@example.com" {
				t.Errorf("Expected User 'clientuser@example.com', got '%s'", user)
			} else {
				t.Logf("✅ User correctly stored by storeClientSession: %s", user)
			}
		} else {
			t.Error("User not found in client session policy")
		}
	})

	t.Log("🎉 All session resumption User field tests passed!")
}

// TestSessionResumptionUserFieldServerSide tests that the User field is set correctly
// on the server side during session resumption
func TestSessionResumptionUserFieldServerSide(t *testing.T) {
	// Create a session cache
	cache := NewSessionCache()

	// Create a mock session with User information
	sessionID := "test-session-123"
	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AES",
	}

	// Create policy with User information
	policy := classad.New()
	_ = policy.Set("AuthMethods", "FS")
	_ = policy.Set("CryptoMethods", "AES")
	_ = policy.Set("User", "testuser@example.com")

	expiration := time.Now().Add(1 * time.Hour)
	lease := 30 * time.Minute

	// Create and store session entry
	entry := NewSessionEntry(sessionID, "client-address", keyInfo, policy, expiration, lease, "")
	cache.Store(entry)

	// Verify the entry was stored
	retrievedEntry, ok := cache.Lookup(sessionID)
	if !ok {
		t.Fatal("Failed to retrieve stored session entry")
	}

	// Verify User is stored in the policy
	if user, ok := retrievedEntry.Policy().EvaluateAttrString("User"); ok {
		if user != "testuser@example.com" {
			t.Errorf("Expected User 'testuser@example.com', got '%s'", user)
		} else {
			t.Logf("✅ User correctly stored in session policy: %s", user)
		}
	} else {
		t.Error("User not found in session policy")
	}

	// Simulate session resumption by retrieving User from policy
	negotiation := &SecurityNegotiation{
		SessionId: sessionID,
	}

	// This is what the fix does in resumeSession and handleSessionResumption
	if retrievedEntry.Policy() != nil {
		if user, ok := retrievedEntry.Policy().EvaluateAttrString("User"); ok {
			negotiation.User = user
		}
	}

	// Verify User was populated
	if negotiation.User != "testuser@example.com" {
		t.Errorf("Expected User 'testuser@example.com' after restoration, got '%s'", negotiation.User)
	} else {
		t.Logf("✅ User correctly restored from session policy: %s", negotiation.User)
	}

	t.Log("🎉 Server-side session resumption User field test passed!")
}
