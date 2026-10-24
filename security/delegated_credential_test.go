package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// createTestSciToken builds something IsSciToken accepts: a JWT whose
// algorithm is not HMAC. The signature is never verified on this path
// -- the header alone decides -- so it does not have to be real, but it
// does have to decode: ParseUnverified base64-decodes the signature
// segment and rejects the token outright when that fails.
func createTestSciToken(t *testing.T) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","iss":"https://issuer.example"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not-verified-here"))
	return header + "." + payload + "." + signature
}

// A client config holding somebody else's token, plus this host's own
// tokens sitting on disk where discovery would find them.
func delegatedSetup(t *testing.T, callerToken string) (*SecurityConfig, *SecurityConfig) {
	t.Helper()
	dir := t.TempDir()
	// What a daemon has lying about: a token of its own, valid for the
	// peer, which discovery would happily offer.
	own := createTestJWT("SCHEDD_ap.example.edu@cm.example.edu", "cm.example.edu", 3600)
	if err := os.WriteFile(filepath.Join(dir, "ownhost"), []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthToken},
		Token:       callerToken,
		TokenDir:    dir,
	}
	server := &SecurityConfig{
		TrustDomain: "cm.example.edu",
		IssuerKeys:  []string{"POOL"},
	}
	return client, server
}

// The behaviour being guarded against, stated as a test: without the
// flag, a caller's token that this peer will not accept is quietly
// replaced by one of this host's own, and the connection authenticates
// as the host. This test documents today's default and exists so the
// one below is known to be testing the flag and not the setup.
func TestDiscoveryReplacesAnUnusableTokenByDefault(t *testing.T) {
	a := &Authenticator{}
	client, server := delegatedSetup(t, createTestJWT("alice", "some.other.pool", 3600))

	if !a.hasCompatibleToken(client, server) {
		t.Fatal("expected discovery to find this host's own token and offer TOKEN")
	}
}

// With the credential marked as somebody else's, nothing on this host
// counts. A server that cannot use a caller's token must not
// authenticate to the peer as itself.
func TestADelegatedCredentialIsNotReplacedByThisHostsOwn(t *testing.T) {
	a := &Authenticator{}
	client, server := delegatedSetup(t, createTestJWT("alice", "some.other.pool", 3600))
	client.DelegatedCredential = true

	if a.hasCompatibleToken(client, server) {
		t.Error("a token on this host was offered in place of the caller's")
	}
	if paths := a.getAvailableTokens(client); len(paths) != 0 {
		t.Errorf("discovery returned %v for a delegated credential; it must return nothing", paths)
	}
}

// A delegated credential the peer does accept is still used -- the flag
// pins the credential, it does not refuse the connection.
func TestAUsableDelegatedCredentialIsStillOffered(t *testing.T) {
	a := &Authenticator{}
	client, server := delegatedSetup(t, createTestJWT("alice", "cm.example.edu", 3600))
	client.DelegatedCredential = true

	if !a.hasCompatibleToken(client, server) {
		t.Error("a delegated token the peer accepts should still be offered")
	}
}

// And the failure says which of the two things went wrong, because the
// fix differs: a token this peer will not accept is a trust-domain or
// signing-key mismatch, while no token at all is a server that lost
// the caller's credential somewhere upstream.
func TestARefusedDelegatedCredentialSaysWhy(t *testing.T) {
	a := &Authenticator{}
	negotiationFor := func(client, server *SecurityConfig) *SecurityNegotiation {
		return &SecurityNegotiation{ClientConfig: client, ServerConfig: server}
	}

	client, server := delegatedSetup(t, createTestJWT("alice", "some.other.pool", 3600))
	client.DelegatedCredential = true
	err := a.loadTokenForAuthentication(AuthToken, &TokenAuthData{}, negotiationFor(client, server))
	if err == nil {
		t.Fatal("expected a refusal rather than a token from this host")
	}
	if !strings.Contains(err.Error(), "not one this peer accepts") {
		t.Errorf("the refusal does not say the token was rejected: %v", err)
	}
	if !strings.Contains(err.Error(), "may not be used in its place") {
		t.Errorf("the refusal does not say what it declined to do: %v", err)
	}

	missing, serverCfg := delegatedSetup(t, "")
	missing.DelegatedCredential = true
	err = a.loadTokenForAuthentication(AuthToken, &TokenAuthData{}, negotiationFor(missing, serverCfg))
	if err == nil {
		t.Fatal("expected a refusal when there is no delegated token at all")
	}
	if !strings.Contains(err.Error(), "no delegated token") {
		t.Errorf("the refusal does not distinguish an absent credential: %v", err)
	}
}

// Without the flag the same call falls through to the host's token, so
// the test above is measuring the flag.
func TestWithoutTheFlagTheHostsTokenIsLoaded(t *testing.T) {
	a := &Authenticator{}
	client, server := delegatedSetup(t, createTestJWT("alice", "some.other.pool", 3600))

	authData := &TokenAuthData{}
	if err := a.loadTokenForAuthentication(AuthToken, authData,
		&SecurityNegotiation{ClientConfig: client, ServerConfig: server}); err != nil {
		t.Fatalf("expected discovery to load this host's own token: %v", err)
	}
}

// SciToken discovery reads the same files by a different route, so it
// needs the same answer: a delegated credential that is not itself a
// SciToken must not be replaced by one found on this host.
func TestDelegatedCredentialDoesNotDiscoverASciToken(t *testing.T) {
	a := &Authenticator{}
	dir := t.TempDir()
	// A SciToken of this host's, where discovery looks.
	sci := createTestSciToken(t)
	if err := os.WriteFile(filepath.Join(dir, "scitoken"), []byte(sci), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &SecurityConfig{
		AuthMethods: []AuthMethod{AuthSciTokens},
		Token:       createTestJWT("alice", "cm.example.edu", 3600),
		TokenDir:    dir,
	}

	// Without the flag, this host's SciToken is found and offered.
	if _, err := a.discoverSciToken(config); err != nil {
		t.Fatalf("expected discovery to find this host's SciToken: %v", err)
	}

	config.DelegatedCredential = true
	got, err := a.discoverSciToken(config)
	if err == nil {
		t.Fatalf("a SciToken on this host was offered in place of the caller's: %q", got)
	}
	if !strings.Contains(err.Error(), "may not be used in its place") {
		t.Errorf("the refusal does not say what it declined to do: %v", err)
	}
}

// The refusal is recognisable to a caller that has to decide what
// status to answer with. Matching on the message would break the
// first time the wording improves.
func TestADelegatedRefusalIsTyped(t *testing.T) {
	a := &Authenticator{}
	client, server := delegatedSetup(t, createTestJWT("alice", "some.other.pool", 3600))
	client.DelegatedCredential = true

	err := a.loadTokenForAuthentication(AuthToken, &TokenAuthData{},
		&SecurityNegotiation{ClientConfig: client, ServerConfig: server})

	if !IsDelegatedCredentialRefused(err) {
		t.Errorf("the refusal is not recognisable as one: %#v", err)
	}
	if IsDelegatedCredentialRefused(nil) {
		t.Error("no error is not a refusal")
	}
}
