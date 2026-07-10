package security

import (
	"strings"
	"testing"
	"time"
)

func TestVerifyIDTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const keyID = "testpool"
	tok, err := GenerateTestJWT(dir, keyID, "worker@pool.example", "pool.example", time.Hour, []string{"READ", "DAEMON"})
	if err != nil {
		t.Fatalf("GenerateTestJWT: %v", err)
	}

	cfg := &SecurityConfig{TokenSigningKeyDir: dir}
	claims, err := VerifyIDToken(tok, cfg)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "worker@pool.example" {
		t.Errorf("subject = %q", claims.Subject)
	}
	if claims.Issuer != "pool.example" {
		t.Errorf("issuer = %q", claims.Issuer)
	}
	if !strings.Contains(claims.Scope, "condor:/DAEMON") {
		t.Errorf("scope = %q, want a condor:/DAEMON scope", claims.Scope)
	}
}

func TestVerifyIDTokenRejectsTamperedSignature(t *testing.T) {
	dir := t.TempDir()
	tok, err := GenerateTestJWT(dir, "k1", "sub@d", "d", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character in the signature segment.
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	cfg := &SecurityConfig{TokenSigningKeyDir: dir}
	if _, err := VerifyIDToken(tampered, cfg); err == nil {
		t.Fatal("expected verification to fail on a tampered signature")
	}
}

func TestVerifyIDTokenRejectsWrongKey(t *testing.T) {
	signDir := t.TempDir()
	tok, err := GenerateTestJWT(signDir, "k1", "sub@d", "d", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Verify against a DIFFERENT key directory (a different "k1" key).
	otherDir := t.TempDir()
	if _, err := GenerateTestJWT(otherDir, "k1", "x@y", "y", time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	cfg := &SecurityConfig{TokenSigningKeyDir: otherDir}
	if _, err := VerifyIDToken(tok, cfg); err == nil {
		t.Fatal("expected verification to fail against a different signing key")
	}
}

func TestVerifyIDTokenRejectsExpired(t *testing.T) {
	dir := t.TempDir()
	tok, err := GenerateTestJWT(dir, "k1", "sub@d", "d", -time.Minute, nil) // already expired
	if err != nil {
		t.Fatal(err)
	}
	cfg := &SecurityConfig{TokenSigningKeyDir: dir}
	if _, err := VerifyIDToken(tok, cfg); err == nil {
		t.Fatal("expected verification to fail on an expired token")
	}
}
