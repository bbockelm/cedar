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
	"testing"
)

func TestParseClaimID(t *testing.T) {
	tests := []struct {
		name            string
		claimID         string
		wantSessionID   string
		wantSessionInfo string
		wantSessionKey  string
	}{
		{
			name:            "full claim ID",
			claimID:         "session123#[Encryption=\"YES\";Integrity=\"YES\";]#abcdef123456",
			wantSessionID:   "session123",
			wantSessionInfo: "[Encryption=\"YES\";Integrity=\"YES\";]",
			wantSessionKey:  "abcdef123456",
		},
		{
			name:            "claim ID without session info",
			claimID:         "session456##keydata789",
			wantSessionID:   "session456",
			wantSessionInfo: "",
			wantSessionKey:  "keydata789",
		},
		{
			name:            "session ID only",
			claimID:         "session789",
			wantSessionID:   "session789",
			wantSessionInfo: "",
			wantSessionKey:  "",
		},
		{
			name:            "empty claim ID",
			claimID:         "",
			wantSessionID:   "",
			wantSessionInfo: "",
			wantSessionKey:  "",
		},
		{
			name:            "complex session ID with special chars",
			claimID:         "host.example.com:1234:1234567890:42#[CryptoMethods=\"AESGCM\";]#deadbeef",
			wantSessionID:   "host.example.com:1234:1234567890:42",
			wantSessionInfo: "[CryptoMethods=\"AESGCM\";]",
			wantSessionKey:  "deadbeef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ParseClaimID(tt.claimID)

			if c.SecSessionID() != tt.wantSessionID && tt.wantSessionInfo != "" {
				// SecSessionID returns empty if session info is empty
				t.Errorf("SecSessionID() = %q, want %q", c.SecSessionID(), tt.wantSessionID)
			}
			if c.sessionID != tt.wantSessionID {
				t.Errorf("sessionID = %q, want %q", c.sessionID, tt.wantSessionID)
			}
			if c.SecSessionInfo() != tt.wantSessionInfo {
				t.Errorf("SecSessionInfo() = %q, want %q", c.SecSessionInfo(), tt.wantSessionInfo)
			}
			if c.SecSessionKey() != tt.wantSessionKey {
				t.Errorf("SecSessionKey() = %q, want %q", c.SecSessionKey(), tt.wantSessionKey)
			}
		})
	}
}

func TestParseClaimID_SecSessionID_RequiresSessionInfo(t *testing.T) {
	// SecSessionID should return empty string when there's no session info
	c := ParseClaimID("session123##key456")
	if c.SecSessionID() != "" {
		t.Errorf("SecSessionID() should return empty when session info is empty, got %q", c.SecSessionID())
	}

	// But with session info, it should return the session ID
	c = ParseClaimID("session123#[info]#key456")
	if c.SecSessionID() != "session123" {
		t.Errorf("SecSessionID() = %q, want %q", c.SecSessionID(), "session123")
	}
}

func TestParseClaimID_PublicClaimID(t *testing.T) {
	c := ParseClaimID("session123#[info]#secretkey")
	public := c.PublicClaimID()
	if public != "session123#..." {
		t.Errorf("PublicClaimID() = %q, want %q", public, "session123#...")
	}
}

func TestParseCondorInherit(t *testing.T) {
	tests := []struct {
		name          string
		inherit       string
		wantPPID      int
		wantAddr      string
		wantRemaining int
	}{
		{
			name:          "typical inherit string",
			inherit:       "12345 <192.168.1.1:9618> sock1 sock2",
			wantPPID:      12345,
			wantAddr:      "<192.168.1.1:9618>",
			wantRemaining: 2,
		},
		{
			name:          "only ppid and addr",
			inherit:       "9999 <host:9618>",
			wantPPID:      9999,
			wantAddr:      "<host:9618>",
			wantRemaining: 0,
		},
		{
			name:          "only ppid",
			inherit:       "1234",
			wantPPID:      1234,
			wantAddr:      "",
			wantRemaining: 0,
		},
		{
			name:          "empty string",
			inherit:       "",
			wantPPID:      0,
			wantAddr:      "",
			wantRemaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppid, addr, remaining := ParseCondorInherit(tt.inherit)

			if ppid != tt.wantPPID {
				t.Errorf("ppid = %d, want %d", ppid, tt.wantPPID)
			}
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if len(remaining) != tt.wantRemaining {
				t.Errorf("len(remaining) = %d, want %d", len(remaining), tt.wantRemaining)
			}
		})
	}
}

func TestParseCondorPrivateInherit(t *testing.T) {
	tests := []struct {
		name            string
		privateInherit  string
		wantNormalCount int
		wantFamilyCount int
	}{
		{
			name:            "both session types",
			privateInherit:  "SessionKey:session1#[info1]#key1 FamilySessionKey:family1#[info2]#key2",
			wantNormalCount: 1,
			wantFamilyCount: 1,
		},
		{
			name:            "only normal session",
			privateInherit:  "SessionKey:parent#[CryptoMethods=\"AESGCM\";]#secretkey",
			wantNormalCount: 1,
			wantFamilyCount: 0,
		},
		{
			name:            "only family session",
			privateInherit:  "FamilySessionKey:sibling#[info]#familykey",
			wantNormalCount: 0,
			wantFamilyCount: 1,
		},
		{
			name:            "multiple sessions",
			privateInherit:  "SessionKey:s1#i1#k1 SessionKey:s2#i2#k2 FamilySessionKey:f1#i3#k3",
			wantNormalCount: 2,
			wantFamilyCount: 1,
		},
		{
			name:            "empty string",
			privateInherit:  "",
			wantNormalCount: 0,
			wantFamilyCount: 0,
		},
		{
			name:            "unknown prefixes ignored",
			privateInherit:  "SessionKey:s1#i1#k1 OtherKey:ignored FamilySessionKey:f1#i2#k2",
			wantNormalCount: 1,
			wantFamilyCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := ParseCondorPrivateInherit(tt.privateInherit)

			normalCount := 0
			familyCount := 0
			for _, sess := range sessions {
				switch sess.Type {
				case SessionTypeNormal:
					normalCount++
				case SessionTypeFamily:
					familyCount++
				}
			}

			if normalCount != tt.wantNormalCount {
				t.Errorf("normal session count = %d, want %d", normalCount, tt.wantNormalCount)
			}
			if familyCount != tt.wantFamilyCount {
				t.Errorf("family session count = %d, want %d", familyCount, tt.wantFamilyCount)
			}
		})
	}
}

func TestImportSessionInfoAttributes(t *testing.T) {
	tests := []struct {
		name        string
		sessionInfo string
		wantAttrs   map[string]string
		wantErr     bool
	}{
		{
			name:        "typical session info",
			sessionInfo: "[Encryption=\"YES\";Integrity=\"YES\";CryptoMethods=\"AESGCM\";]",
			wantAttrs: map[string]string{
				"Encryption":    "YES",
				"Integrity":     "YES",
				"CryptoMethods": "AESGCM",
			},
			wantErr: false,
		},
		{
			name:        "without brackets",
			sessionInfo: "Encryption=\"YES\";Integrity=\"NO\"",
			wantAttrs: map[string]string{
				"Encryption": "YES",
				"Integrity":  "NO",
			},
			wantErr: false,
		},
		{
			name:        "empty string",
			sessionInfo: "",
			wantAttrs:   map[string]string{},
			wantErr:     false,
		},
		{
			name:        "session expires attribute",
			sessionInfo: "[SecSessionExpires=1735689600;CryptoMethods=\"AESGCM,BLOWFISH\";]",
			wantAttrs: map[string]string{
				"SecSessionExpires": "1735689600",
				"CryptoMethods":     "AESGCM,BLOWFISH",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := ImportSessionInfoAttributes(tt.sessionInfo)

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
				return
			}

			for key, wantValue := range tt.wantAttrs {
				if gotValue, ok := attrs[key]; !ok {
					t.Errorf("missing attribute %q", key)
				} else if gotValue != wantValue {
					t.Errorf("attrs[%q] = %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

func TestExportClaimID(t *testing.T) {
	claimID := ExportClaimID("session123", "[info]", "key456")
	want := "session123#[info]#key456"
	if claimID != want {
		t.Errorf("ExportClaimID() = %q, want %q", claimID, want)
	}

	// Round-trip test
	parsed := ParseClaimID(claimID)
	if parsed.sessionID != "session123" {
		t.Errorf("round-trip sessionID = %q, want %q", parsed.sessionID, "session123")
	}
	if parsed.sessionInfo != "[info]" {
		t.Errorf("round-trip sessionInfo = %q, want %q", parsed.sessionInfo, "[info]")
	}
	if parsed.sessionKey != "key456" {
		t.Errorf("round-trip sessionKey = %q, want %q", parsed.sessionKey, "key456")
	}
}

func TestGenerateSecuritySessionKey(t *testing.T) {
	key1, err := GenerateSecuritySessionKey()
	if err != nil {
		t.Fatalf("GenerateSecuritySessionKey() error = %v", err)
	}

	// Should be 64 hex characters (32 bytes * 2)
	if len(key1) != 64 {
		t.Errorf("key length = %d, want 64", len(key1))
	}

	// Should generate different keys each time
	key2, err := GenerateSecuritySessionKey()
	if err != nil {
		t.Fatalf("GenerateSecuritySessionKey() error = %v", err)
	}

	if key1 == key2 {
		t.Error("generated keys should be different")
	}
}

func TestCreateNonNegotiatedSession(t *testing.T) {
	session := &InheritedSession{
		Type:        SessionTypeFamily,
		SessionID:   "test-session-123",
		SessionInfo: "[CryptoMethods=\"AESGCM\";Encryption=\"YES\";]",
		SessionKey:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	entry, err := CreateNonNegotiatedSession(session, "<192.168.1.1:9618>")
	if err != nil {
		t.Fatalf("CreateNonNegotiatedSession() error = %v", err)
	}

	if entry.ID() != "test-session-123" {
		t.Errorf("ID() = %q, want %q", entry.ID(), "test-session-123")
	}

	if entry.Addr() != "<192.168.1.1:9618>" {
		t.Errorf("Addr() = %q, want %q", entry.Addr(), "<192.168.1.1:9618>")
	}

	if entry.KeyInfo() == nil {
		t.Error("KeyInfo() should not be nil")
	} else {
		if entry.KeyInfo().Protocol != "AESGCM" {
			t.Errorf("KeyInfo().Protocol = %q, want %q", entry.KeyInfo().Protocol, "AESGCM")
		}
		if len(entry.KeyInfo().Data) != 32 {
			t.Errorf("KeyInfo().Data length = %d, want 32", len(entry.KeyInfo().Data))
		}
	}

	if entry.Policy() == nil {
		t.Error("Policy() should not be nil")
	}
}

func TestCreateNonNegotiatedSession_Errors(t *testing.T) {
	// Nil session
	_, err := CreateNonNegotiatedSession(nil, "<addr>")
	if err == nil {
		t.Error("expected error for nil session")
	}

	// Empty session ID
	_, err = CreateNonNegotiatedSession(&InheritedSession{
		SessionID:  "",
		SessionKey: "key",
	}, "<addr>")
	if err == nil {
		t.Error("expected error for empty session ID")
	}
}
