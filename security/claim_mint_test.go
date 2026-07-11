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
	"regexp"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// minted claim ids must match the exact startd wire grammar.
var mintedClaimRe = regexp.MustCompile(`^<[^>]+>#\d+#\d+#\[.*\]\w+$`)

func TestMintClaimSession_RoundTripParse(t *testing.T) {
	cache := NewSessionCache()
	mc, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:      "<127.0.0.1:9618>",
		Birthdate:   1700000000,
		SequenceNum: 7,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}

	if !mintedClaimRe.MatchString(mc.ClaimID()) {
		t.Errorf("minted claim id %q does not match golden format %s", mc.ClaimID(), mintedClaimRe)
	}

	wantSID := "<127.0.0.1:9618>#1700000000#7"
	if mc.SessionID() != wantSID {
		t.Errorf("SessionID() = %q, want %q", mc.SessionID(), wantSID)
	}
	if mc.PublicClaimID() != wantSID+"#..." {
		t.Errorf("PublicClaimID() = %q, want %q", mc.PublicClaimID(), wantSID+"#...")
	}

	// Parse the minted id back with the C++-faithful parser.
	c := ParseClaimIDStrict(mc.ClaimID())
	if c.SecSessionID() != wantSID {
		t.Errorf("parsed SecSessionID = %q, want %q", c.SecSessionID(), wantSID)
	}
	if c.SecSessionInfo() == "" {
		t.Error("parsed SecSessionInfo is empty")
	}
	// The session key is 64 hex chars (SEC_SESSION_KEY_LENGTH_V9 == 32 bytes).
	if got := c.SecSessionKey(); len(got) != 2*secSessionKeyLengthV9 {
		t.Errorf("session key length = %d, want %d", len(got), 2*secSessionKeyLengthV9)
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(c.SecSessionKey()) {
		t.Errorf("session key %q is not lowercase hex", c.SecSessionKey())
	}

	// A stock mint must carry the crypto attrs a C++ peer requires to import.
	info := c.SecSessionInfo()
	for _, want := range []string{`CryptoMethods="AES"`, `Encryption="YES"`, `Integrity="YES"`} {
		if !bytes.Contains([]byte(info), []byte(want)) {
			t.Errorf("session_info %q missing %q", info, want)
		}
	}
}

func TestMintClaimSession_RegistersUsableSession(t *testing.T) {
	cache := NewSessionCache()
	mc, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:      "<10.0.0.5:9618>",
		Birthdate:   1,
		SequenceNum: 1,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}

	entry, ok := cache.Lookup(mc.SessionID())
	if !ok {
		t.Fatal("minted session not stored in cache")
	}
	if entry.KeyInfo() == nil || len(entry.KeyInfo().Data) != 32 {
		t.Fatalf("expected 32-byte AES key, got %v", entry.KeyInfo())
	}
	if entry.KeyInfo().Protocol != "AESGCM" {
		t.Errorf("protocol = %q, want AESGCM", entry.KeyInfo().Protocol)
	}
	// The startd attributes the SUBMIT side identity to its peer (the schedd).
	if user, _ := entry.Policy().EvaluateAttrString("User"); user != SubmitSideMatchSessionFQU {
		t.Errorf("User = %q, want %q", user, SubmitSideMatchSessionFQU)
	}
	if !entry.IsInherited() {
		t.Error("minted session should be marked inherited (never persisted)")
	}
}

// The crux: mint on one cache (the "startd"), import on a second (the "schedd"),
// and confirm both derive the SAME key material -- i.e. the claim id truly
// carries an interoperable pre-shared session.
func TestMintClaimSession_ImportDerivesSameKey(t *testing.T) {
	startdCache := NewSessionCache()
	mc, err := MintClaimSession(startdCache, MintClaimOptions{
		Sinful:      "<192.168.1.10:9618>",
		Birthdate:   1700001234,
		SequenceNum: 42,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}

	scheddCache := NewSessionCache()
	sesid, err := ImportClaimSession(scheddCache, mc.ClaimID(), ClaimSessionOptions{
		PeerAddr: "<192.168.1.10:9618>",
	})
	if err != nil {
		t.Fatalf("ImportClaimSession of minted id: %v", err)
	}
	if sesid != mc.SessionID() {
		t.Fatalf("imported session id %q != minted %q", sesid, mc.SessionID())
	}

	startdEntry, ok := startdCache.Lookup(mc.SessionID())
	if !ok {
		t.Fatal("startd session missing")
	}
	scheddEntry, ok := scheddCache.Lookup(sesid)
	if !ok {
		t.Fatal("schedd session missing")
	}

	if !bytes.Equal(startdEntry.KeyInfo().Data, scheddEntry.KeyInfo().Data) {
		t.Error("mint and import derived different AES keys; sessions are not interoperable")
	}
	if startdEntry.KeyInfo().Protocol != scheddEntry.KeyInfo().Protocol {
		t.Errorf("protocol mismatch: startd=%q schedd=%q",
			startdEntry.KeyInfo().Protocol, scheddEntry.KeyInfo().Protocol)
	}
	// The two sides attribute mirror-image identities to each other.
	su, _ := startdEntry.Policy().EvaluateAttrString("User")
	if su != SubmitSideMatchSessionFQU {
		t.Errorf("startd User = %q, want %q", su, SubmitSideMatchSessionFQU)
	}
	eu, _ := scheddEntry.Policy().EvaluateAttrString("User")
	if eu != ExecuteSideMatchSessionFQU {
		t.Errorf("schedd User = %q, want %q", eu, ExecuteSideMatchSessionFQU)
	}
}

func TestMintClaimSession_SinfulWithHash(t *testing.T) {
	// 8.9+ sinfuls can contain '#'; the parser recovers the sinful by scanning to
	// the first '>', and the session split still keys on the LAST '#'.
	sinful := "<127.0.0.1:9618?sock=slot1#1>"
	cache := NewSessionCache()
	mc, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:      sinful,
		Birthdate:   5,
		SequenceNum: 9,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}

	c := ParseClaimIDStrict(mc.ClaimID())
	wantSID := sinful + "#5#9"
	if c.SecSessionID() != wantSID {
		t.Errorf("SecSessionID = %q, want %q", c.SecSessionID(), wantSID)
	}
	// Import must still round-trip despite the '#' in the sinful.
	scheddCache := NewSessionCache()
	if _, err := ImportClaimSession(scheddCache, mc.ClaimID(), ClaimSessionOptions{}); err != nil {
		t.Fatalf("ImportClaimSession with '#' sinful: %v", err)
	}
}

func TestMintClaimSession_Lifetime(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cache := NewSessionCache()
	mc, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:      "<10.0.0.1:9618>",
		Birthdate:   1,
		SequenceNum: 1,
		Lifetime:    time.Hour,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}

	// SessionExpires must be embedded so the importing peer expires in lockstep.
	c := ParseClaimIDStrict(mc.ClaimID())
	policy, err := ImportSecSessionInfo(c.SecSessionInfo())
	if err != nil {
		t.Fatalf("ImportSecSessionInfo: %v", err)
	}
	if _, ok := policy.EvaluateAttrString("SessionExpires"); !ok {
		t.Error("minted session_info missing SessionExpires for a bounded lifetime")
	}

	entry, _ := cache.Lookup(mc.SessionID())
	if got := entry.Expiration(); got.Before(future.Add(-time.Minute)) || got.After(future.Add(time.Minute)) {
		t.Errorf("local expiration = %v, want ~%v", got, future)
	}
}

func TestMintClaimSession_ExtraValidCommands(t *testing.T) {
	cache := NewSessionCache()
	peer := "<10.0.0.9:9618>"
	mc, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:             "<10.0.0.1:9618>",
		Birthdate:          1,
		SequenceNum:        1,
		PeerAddr:           peer,
		ExtraValidCommands: []int{60021}, // ALIVE
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}
	if _, ok := cache.LookupByCommand("", peer, "60021"); !ok {
		t.Error("ExtraValidCommands not mapped to session for outbound dial")
	}
	_ = mc
}

func TestMintClaimSession_RejectsNonAES(t *testing.T) {
	cache := NewSessionCache()
	if _, err := MintClaimSession(cache, MintClaimOptions{
		Sinful:        "<10.0.0.1:9618>",
		CryptoMethods: "BLOWFISH",
	}); err == nil {
		t.Error("expected error minting a non-AES claim session")
	}
}

func TestMintClaimSession_NoSinful(t *testing.T) {
	cache := NewSessionCache()
	if _, err := MintClaimSession(cache, MintClaimOptions{}); err == nil {
		t.Error("expected error minting without a sinful")
	}
}

// --- ExportSecSessionInfo <-> ImportSecSessionInfo round-trip ---

func TestExportImportSecSessionInfo_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		set  map[string]any
		want map[string]string // expected imported policy attrs
	}{
		{
			name: "stock-aes",
			set:  map[string]any{"Encryption": "YES", "Integrity": "YES", "CryptoMethods": "AES"},
			want: map[string]string{"Encryption": "YES", "Integrity": "YES", "CryptoMethods": "AES"},
		},
		{
			name: "integrity-only-plaintext",
			set:  map[string]any{"Encryption": "NO", "Integrity": "YES", "CryptoMethods": "AES"},
			want: map[string]string{"Encryption": "NO", "Integrity": "YES", "CryptoMethods": "AES"},
		},
		{
			name: "multi-method-list",
			set:  map[string]any{"CryptoMethods": "AES,BLOWFISH", "Encryption": "YES"},
			// list override restores the full comma list on import.
			want: map[string]string{"CryptoMethods": "AES,BLOWFISH", "Encryption": "YES"},
		},
		{
			name: "with-commands-and-version",
			set:  map[string]any{"CryptoMethods": "AES", "ValidCommands": "443,444", "RemoteVersion": "$CondorVersion: 25.4.0 Jan 01 2026 $"},
			want: map[string]string{"CryptoMethods": "AES", "ValidCommands": "443,444", "RemoteVersion": "25.4.0"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := classad.New()
			for k, v := range tc.set {
				_ = src.Set(k, v)
			}
			info, err := ExportSecSessionInfo(src)
			if err != nil {
				t.Fatalf("ExportSecSessionInfo: %v", err)
			}
			if len(info) < 2 || info[0] != '[' || info[len(info)-1] != ']' {
				t.Fatalf("exported info not bracketed: %q", info)
			}

			got, err := ImportSecSessionInfo(info)
			if err != nil {
				t.Fatalf("ImportSecSessionInfo(%q): %v", info, err)
			}
			for attr, want := range tc.want {
				g, ok := got.EvaluateAttrString(attr)
				if !ok {
					t.Errorf("imported policy missing %s (info=%q)", attr, info)
					continue
				}
				if g != want {
					t.Errorf("imported %s = %q, want %q (info=%q)", attr, g, want, info)
				}
			}
		})
	}
}

func TestExportSecSessionInfo_SortedDeterministic(t *testing.T) {
	src := classad.New()
	_ = src.Set("Integrity", "YES")
	_ = src.Set("Encryption", "YES")
	_ = src.Set("CryptoMethods", "AES")
	info, err := ExportSecSessionInfo(src)
	if err != nil {
		t.Fatalf("ExportSecSessionInfo: %v", err)
	}
	// Alphabetical attribute order matches a C++ ClassAd's iteration order.
	want := `[CryptoMethods="AES";Encryption="YES";Integrity="YES";]`
	if info != want {
		t.Errorf("exported info = %q, want %q", info, want)
	}
}

func TestExportSecSessionInfo_SessionExpiresBare(t *testing.T) {
	src := classad.New()
	_ = src.Set("CryptoMethods", "AES")
	_ = src.Set("SessionExpires", int64(1700000123))
	info, err := ExportSecSessionInfo(src)
	if err != nil {
		t.Fatalf("ExportSecSessionInfo: %v", err)
	}
	// Integer, unquoted, as ExprTreeToString renders it.
	if !bytes.Contains([]byte(info), []byte("SessionExpires=1700000123;")) {
		t.Errorf("SessionExpires not rendered bare: %q", info)
	}
}
