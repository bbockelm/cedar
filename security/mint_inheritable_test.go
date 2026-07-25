package security

import (
	"bytes"
	"strings"
	"testing"
)

// TestMintInheritableSession verifies the minted session is registered in the global cache as
// a non-persistent, non-expiring condor@parent session, and that its CONDOR_PRIVATE_INHERIT
// token round-trips so a child re-deriving the session (as the inherit importer does) arrives
// at the SAME key -- which is what lets the child resume the session against this server.
func TestMintInheritableSession(t *testing.T) {
	const cmd = 74000
	sid, token, err := MintInheritableSession("<127.0.0.1:9999>", cmd)
	if err != nil {
		t.Fatalf("MintInheritableSession: %v", err)
	}
	if sid == "" || token == "" {
		t.Fatalf("empty sid/token: %q %q", sid, token)
	}
	if !strings.HasPrefix(token, "SessionKey:") {
		t.Errorf("token missing SessionKey: prefix: %q", token)
	}

	// Registered in the global cache, non-persistent, non-expiring, identity condor@parent.
	entry, ok := GetSessionCache().LookupNonExpired(sid)
	if !ok {
		t.Fatalf("minted session %s not found in the global cache", redactSessionID(sid))
	}
	if !entry.IsInherited() {
		t.Error("minted session should be marked inherited (non-persistent)")
	}
	if !entry.Expiration().IsZero() {
		t.Errorf("minted session should not expire, got expiration %v", entry.Expiration())
	}
	if u, _ := entry.Policy().EvaluateAttrString("User"); u != "condor@parent" {
		t.Errorf("minted session identity = %q, want condor@parent", u)
	}
	if a, ok := entry.Policy().EvaluateAttrBool("Authenticated"); !ok || !a {
		t.Error("minted session should be Authenticated")
	}

	// The token is exactly what the parent puts in CONDOR_PRIVATE_INHERIT; a child parses it
	// and re-derives the session. Parsing must recover the same id, and re-creating the session
	// (the child side) must derive the identical key -- proving parent and child agree.
	sessions := ParseCondorPrivateInherit(token)
	if len(sessions) != 1 {
		t.Fatalf("token parsed to %d sessions, want 1", len(sessions))
	}
	child := sessions[0]
	if child.Type != SessionTypeNormal || child.SessionID != sid {
		t.Errorf("parsed session id/type = %s/%d, want %s/normal", child.SessionID, child.Type, sid)
	}
	childEntry, err := CreateNonNegotiatedSession(child, "<127.0.0.1:9999>")
	if err != nil {
		t.Fatalf("child CreateNonNegotiatedSession: %v", err)
	}
	if !bytes.Equal(childEntry.KeyInfo().Data, entry.KeyInfo().Data) {
		t.Error("child-derived session key differs from the minted key; resume would fail to decrypt")
	}

	// The session is scoped to the requested command.
	if vc, _ := entry.Policy().EvaluateAttrString("ValidCommands"); vc != "74000" {
		t.Errorf("ValidCommands = %q, want 74000", vc)
	}
}

// TestMintInheritableSessionUnique verifies successive mints produce distinct session ids/keys.
func TestMintInheritableSessionUnique(t *testing.T) {
	sid1, tok1, err := MintInheritableSession("<x>", 74000)
	if err != nil {
		t.Fatal(err)
	}
	sid2, tok2, err := MintInheritableSession("<x>", 74000)
	if err != nil {
		t.Fatal(err)
	}
	if sid1 == sid2 {
		t.Errorf("session ids collided: %s", sid1)
	}
	if tok1 == tok2 {
		t.Error("tokens should differ (distinct keys)")
	}
}
