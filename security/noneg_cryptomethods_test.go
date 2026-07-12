package security

import "testing"

// TestCreateNonNegotiatedSessionOverridesLegacyCryptoMethods pins that an
// inherited/non-negotiated session advertises the AES-GCM cipher it is actually
// keyed on, not the legacy back-compat CryptoMethods HTCondor's
// ExportSecSessionInfo emits (e.g. BLOWFISH via getPreferredOldCryptProtocol).
// Regression for the condor_ssh_to_job START_SSHD break: a session keyed AES-GCM
// but advertising BLOWFISH makes the peer decrypt the first frame with the wrong
// cipher.
func TestCreateNonNegotiatedSessionOverridesLegacyCryptoMethods(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Legacy single CryptoMethods is a non-AES old-preferred value; the modern
	// list leads with AES.
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="BLOWFISH";CryptoMethodsList="AES.BLOWFISH.3DES"]`

	entry, err := CreateNonNegotiatedSession(&InheritedSession{
		Type:        SessionTypeNormal,
		SessionID:   "<127.0.0.1:9999>#100#1",
		SessionInfo: info,
		SessionKey:  key,
	}, "<127.0.0.1:9999>")
	if err != nil {
		t.Fatalf("CreateNonNegotiatedSession: %v", err)
	}

	cm, _ := entry.Policy().EvaluateAttrString("CryptoMethods")
	if cm != "AES" && cm != "AESGCM" {
		t.Errorf("policy CryptoMethods = %q, want AES/AESGCM (legacy value must not leak through)", cm)
	}
	if got := len(entry.KeyInfo().Data); got != 32 {
		t.Errorf("derived key length = %d, want 32", got)
	}
}
