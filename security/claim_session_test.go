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
	"fmt"
	"testing"
	"time"
)

// buildStartdClaimID assembles a claim id in the exact wire form a startd
// produces (src/condor_startd.V6/claim.cpp newIdString + setSecSessionInfo):
//
//	<sinful>#startd_bday#sequence_num#[session_info]session_key
func buildStartdClaimID(sinful, bday, seq, sessionInfo, key string) string {
	return fmt.Sprintf("%s#%s#%s#%s%s", sinful, bday, seq, sessionInfo, key)
}

func TestParseClaimIDStrict_StartdFormat(t *testing.T) {
	const (
		sinful = "<127.0.0.1:9618>"
		bday   = "1700000000"
		seq    = "7"
		info   = `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`
		key    = "0123456789abcdef0123456789abcdef"
	)
	claimID := buildStartdClaimID(sinful, bday, seq, info, key)

	c := ParseClaimIDStrict(claimID)

	wantID := sinful + "#" + bday + "#" + seq
	if got := c.SecSessionID(); got != wantID {
		t.Errorf("SecSessionID() = %q, want %q", got, wantID)
	}
	if got := c.SecSessionInfo(); got != info {
		t.Errorf("SecSessionInfo() = %q, want %q", got, info)
	}
	if got := c.SecSessionKey(); got != key {
		t.Errorf("SecSessionKey() = %q, want %q", got, key)
	}
}

func TestParseClaimIDStrict_NoSessionInfo(t *testing.T) {
	// A claim id whose last '#' is not followed by '[' has no security session.
	c := ParseClaimIDStrict("<127.0.0.1:9618>#1700000000#7#deadbeef")
	if got := c.SecSessionID(); got != "" {
		t.Errorf("SecSessionID() = %q, want empty (no session info)", got)
	}
	if got := c.SecSessionInfo(); got != "" {
		t.Errorf("SecSessionInfo() = %q, want empty", got)
	}
	// The key is still everything after the last '#' (matches C++ secSessionKey).
	if got := c.SecSessionKey(); got != "deadbeef" {
		t.Errorf("SecSessionKey() = %q, want deadbeef", got)
	}
}

func TestImportSecSessionInfo(t *testing.T) {
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="AES";SessionExpires=1700000123;ValidCommands="443,444";ShortVersion="25.4.0";]`

	policy, err := ImportSecSessionInfo(info)
	if err != nil {
		t.Fatalf("ImportSecSessionInfo: %v", err)
	}

	checks := map[string]string{
		"Encryption":     "YES",
		"Integrity":      "YES",
		"CryptoMethods":  "AES",
		"SessionExpires": "1700000123",
		"ValidCommands":  "443,444",
		"RemoteVersion":  "25.4.0", // ShortVersion -> RemoteVersion
	}
	for attr, want := range checks {
		got, ok := policy.EvaluateAttrString(attr)
		if !ok {
			t.Errorf("policy missing %s", attr)
			continue
		}
		if got != want {
			t.Errorf("policy[%s] = %q, want %q", attr, got, want)
		}
	}
}

func TestImportSecSessionInfo_CryptoMethodsListOverride(t *testing.T) {
	// CryptoMethodsList (dot-delimited) overrides the legacy CryptoMethods and
	// the '.' is converted back to ','.
	info := `[CryptoMethods="BLOWFISH";CryptoMethodsList="AES.BLOWFISH";]`

	policy, err := ImportSecSessionInfo(info)
	if err != nil {
		t.Fatalf("ImportSecSessionInfo: %v", err)
	}
	got, _ := policy.EvaluateAttrString("CryptoMethods")
	if got != "AES,BLOWFISH" {
		t.Errorf("CryptoMethods = %q, want %q", got, "AES,BLOWFISH")
	}
}

func TestImportSecSessionInfo_Errors(t *testing.T) {
	if _, err := ImportSecSessionInfo(""); err != nil {
		t.Errorf("empty session info should be OK, got %v", err)
	}
	if _, err := ImportSecSessionInfo(`Encryption="YES"`); err == nil {
		t.Error("unbracketed session info should be an error")
	}
}

func TestImportClaimSession(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="AES";ValidCommands="443";]`
	claimID := buildStartdClaimID("<127.0.0.1:9618>", "1700000000", "7", info, key)

	cache := NewSessionCache()
	sesid, err := ImportClaimSession(cache, claimID, ClaimSessionOptions{
		PeerAddr:           "<127.0.0.1:9618>",
		ExtraValidCommands: []int{444},
	})
	if err != nil {
		t.Fatalf("ImportClaimSession: %v", err)
	}
	if sesid != "<127.0.0.1:9618>#1700000000#7" {
		t.Errorf("session id = %q", sesid)
	}

	entry, ok := cache.Lookup(sesid)
	if !ok {
		t.Fatal("session not stored in cache")
	}
	if entry.KeyInfo() == nil || len(entry.KeyInfo().Data) != 32 {
		t.Fatalf("expected 32-byte AES key, got %v", entry.KeyInfo())
	}
	if entry.KeyInfo().Protocol != "AESGCM" {
		t.Errorf("protocol = %q, want AESGCM", entry.KeyInfo().Protocol)
	}
	// Key must equal HKDF(secret) so it interoperates with C++.
	wantKey, _ := deriveSessionKey(key, 32)
	if string(entry.KeyInfo().Data) != string(wantKey) {
		t.Error("derived key does not match HKDF(secret)")
	}
	if user, _ := entry.Policy().EvaluateAttrString("User"); user != ExecuteSideMatchSessionFQU {
		t.Errorf("User = %q, want %q", user, ExecuteSideMatchSessionFQU)
	}
	// A claim session is authenticated by possession of the claim secret; the
	// policy must record it so a resumed session is not treated as anonymous and
	// refused by the per-command security check (regression: REQUEST_CLAIM /
	// ACTIVATE_CLAIM to the startd were refused as not meeting the command level).
	if authed, ok := entry.Policy().EvaluateAttrBool("Authenticated"); !ok || !authed {
		t.Errorf("Authenticated = (%v, ok=%v), want true", authed, ok)
	}

	// Both the session_info ValidCommands (443) and ExtraValidCommands (444)
	// map to the session for the peer address.
	for _, cmd := range []string{"443", "444"} {
		if _, ok := cache.LookupByCommand("", "<127.0.0.1:9618>", cmd); !ok {
			t.Errorf("command %s not mapped to session", cmd)
		}
	}
}

func TestImportClaimSession_SessionExpires(t *testing.T) {
	const key = "abcdef0123456789abcdef0123456789"
	future := time.Now().Add(time.Hour).Unix()
	info := fmt.Sprintf(`[CryptoMethods="AES";SessionExpires=%d;]`, future)
	claimID := buildStartdClaimID("<10.0.0.1:9618>", "1", "1", info, key)

	cache := NewSessionCache()
	sesid, err := ImportClaimSession(cache, claimID, ClaimSessionOptions{})
	if err != nil {
		t.Fatalf("ImportClaimSession: %v", err)
	}
	entry, ok := cache.Lookup(sesid)
	if !ok {
		t.Fatal("session not stored")
	}
	if got := entry.Expiration().Unix(); got != future {
		t.Errorf("expiration = %d, want %d", got, future)
	}
}

func TestImportClaimSession_RejectsNonAES(t *testing.T) {
	const key = "abcdef0123456789abcdef0123456789"
	info := `[CryptoMethods="BLOWFISH";]`
	claimID := buildStartdClaimID("<10.0.0.1:9618>", "1", "1", info, key)

	cache := NewSessionCache()
	if _, err := ImportClaimSession(cache, claimID, ClaimSessionOptions{}); err == nil {
		t.Error("expected error for non-AES claim session")
	}
}

func TestImportClaimSession_NoSessionInfo(t *testing.T) {
	cache := NewSessionCache()
	if _, err := ImportClaimSession(cache, "<10.0.0.1:9618>#1#1#justakey", ClaimSessionOptions{}); err == nil {
		t.Error("expected error for claim id without session info")
	}
}

func TestImportFileTransferSession(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	info := `[Encryption="YES";CryptoMethods="AES";]`
	claimID := buildStartdClaimID("<127.0.0.1:9618>", "1700000000", "7", info, key)

	cache := NewSessionCache()
	ftID, err := ImportFileTransferSession(cache, claimID, ClaimSessionOptions{})
	if err != nil {
		t.Fatalf("ImportFileTransferSession: %v", err)
	}
	if ftID != "filetrans.<127.0.0.1:9618>#1700000000#7" {
		t.Errorf("file-transfer session id = %q", ftID)
	}

	entry, ok := cache.Lookup(ftID)
	if !ok {
		t.Fatal("file-transfer session not stored")
	}
	// Same key material as the claim session (derived from the same secret).
	wantKey, _ := deriveSessionKey(key, 32)
	if string(entry.KeyInfo().Data) != string(wantKey) {
		t.Error("file-transfer key does not match HKDF(secret)")
	}
	// Uses the importer's own WRITE policy: encryption + integrity on.
	if enc, _ := entry.Policy().EvaluateAttrString("Encryption"); enc != "YES" {
		t.Errorf("Encryption = %q, want YES", enc)
	}
	if integ, _ := entry.Policy().EvaluateAttrString("Integrity"); integ != "YES" {
		t.Errorf("Integrity = %q, want YES", integ)
	}
}
