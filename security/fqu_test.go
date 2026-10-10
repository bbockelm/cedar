package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// Each authentication method reports the peer as the fully-qualified user C++
// HTCondor gives it (Condor_Auth_Base::getRemoteFQU), not a bare user name.

func TestTokenFQUIsTheSubject(t *testing.T) {
	for _, tc := range []struct{ sub, want string }{
		{"condor@pool", "condor@pool"},
		{"alice@Pool.Example", "alice@pool.example"}, // setRemoteDomain lowercases
		{"alice", "alice"},                           // no '@': no domain, as in C++
		{"a@b@c", "a@b@c"},                           // split at the last '@'
	} {
		t.Run(tc.sub, func(t *testing.T) {
			_, server := runTokenHandshake(t, SecurityRequired, SecurityRequired,
				createTestJWT(tc.sub, "example.com", 3600), []string{"POOL"})
			if server.err != nil {
				t.Fatalf("server handshake: %v", server.err)
			}
			if server.neg.User != tc.want {
				t.Errorf("server authenticated %q, want %q", server.neg.User, tc.want)
			}
		})
	}
}

// fsServerUser runs an FS handshake between cedar's client and server and
// returns the identity the server recorded.
func fsServerUser(t *testing.T, uidDomain string) string {
	t.Helper()
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientConfig := &SecurityConfig{AuthMethods: []AuthMethod{AuthFS}, Command: commands.DC_AUTHENTICATE}
	serverConfig := &SecurityConfig{AuthMethods: []AuthMethod{AuthFS}, UIDDomain: uidDomain}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ServerConfig: serverConfig}
	clientNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ClientConfig: clientConfig, IsClient: true}
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
			performFSAuthenticationServer(ctx, serverNeg, false)
	}()
	if err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).
		performFSAuthenticationClient(ctx, clientNeg, false); err != nil {
		t.Fatalf("client FS auth failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server FS auth failed: %v", err)
	}
	return serverNeg.User
}

func TestFSFQUIsUserAtUIDDomain(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fsServerUser(t, "UID.Example"), cur.Username+"@uid.example"; got != want {
		t.Errorf("FS authenticated %q, want %q", got, want)
	}
	// UID_DOMAIN defaults to the host's name.
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fsServerUser(t, ""), cur.Username+"@"+strings.ToLower(host); got != want {
		t.Errorf("FS with no UIDDomain authenticated %q, want %q", got, want)
	}
}

// claimToBeServerUser sends claimed as a CLAIMTOBE client and returns the
// identity cedar's server recorded.
func claimToBeServerUser(t *testing.T, claimed, uidDomain string) string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConfig := &SecurityConfig{UIDDomain: uidDomain}
	serverNeg := &SecurityNegotiation{ServerConfig: serverConfig}
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
			performClaimToBeAuthenticationServer(ctx, serverNeg)
	}()
	cs := stream.NewStream(clientConn)
	msg := message.NewMessageForStream(cs)
	if err := msg.PutInt(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := msg.PutString(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatal(err)
	}
	ack := message.NewMessageFromStream(cs)
	if v, err := ack.GetInt(ctx); err != nil || v != 1 {
		t.Fatalf("server ack = %d, %v", v, err)
	}
	if _, err := ack.GetChar(ctx); err != io.EOF {
		t.Fatalf("ack not terminated: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server CLAIMTOBE: %v", err)
	}
	return serverNeg.User
}

func TestClaimToBeFQU(t *testing.T) {
	for _, tc := range []struct{ claimed, want string }{
		{"bob@Other.Domain", "bob@other.domain"},
		{"bob", "bob@uid.example"},  // no domain: ours
		{"bob@", "bob@uid.example"}, // empty domain: ours
		{"a@b@c", "a@b@c"},
	} {
		if got := claimToBeServerUser(t, tc.claimed, "UID.Example"); got != tc.want {
			t.Errorf("CLAIMTOBE %q authenticated %q, want %q", tc.claimed, got, tc.want)
		}
	}
}

func TestKerberosFQU(t *testing.T) {
	for _, tc := range []struct {
		name  []string
		realm string
		want  string
	}{
		{[]string{"host", "node.example.com"}, "EXAMPLE.COM", "condor@example.com"},
		{[]string{"alice"}, "EXAMPLE.COM", "alice@example.com"},
		{[]string{"alice", "admin"}, "EXAMPLE.COM", "alice@example.com"},
	} {
		if got := kerberosFQU(tc.name, tc.realm); got != tc.want {
			t.Errorf("kerberosFQU(%q, %q) = %q, want %q", tc.name, tc.realm, got, tc.want)
		}
	}
}

// TestSSLFQU: an SSL client is ssl@unmapped, or unauthenticated@unmapped
// without a certificate -- never "", which an authorizer reads as anyone.
func TestSSLFQU(t *testing.T) {
	if got := sslPeerFQU(tls.ConnectionState{}); got != "unauthenticated@unmapped" {
		t.Errorf("no client certificate: %q, want unauthenticated@unmapped", got)
	}
	withCert := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if got := sslPeerFQU(withCert); got != "ssl@unmapped" {
		t.Errorf("client certificate: %q, want ssl@unmapped", got)
	}
}

func TestFQUHelpers(t *testing.T) {
	for _, tc := range []struct{ fqu, user, domain string }{
		{"condor@pool", "condor", "pool"},
		{"a@b@c", "a@b", "c"},
		{"alice", "alice", ""},
		{"", "", ""},
	} {
		neg := &SecurityNegotiation{User: tc.fqu}
		if neg.UserName() != tc.user || neg.UserDomain() != tc.domain {
			t.Errorf("%q: UserName %q UserDomain %q, want %q %q", tc.fqu, neg.UserName(), neg.UserDomain(), tc.user, tc.domain)
		}
	}
	cfg := &SecurityConfig{UIDDomain: "UID.Example"}
	for name, want := range map[string]string{
		"admin":      "admin@uid.example",
		"admin@Pool": "admin@pool",
	} {
		if got := cfg.CanonicalUser(name); got != want {
			t.Errorf("CanonicalUser(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestClaimToBeClientClaimsUIDDomain: the CLAIMTOBE client claims
// user@UID_DOMAIN, as condor_auth_claim.cpp does, not the trust domain.
func TestClaimToBeClientClaimsUIDDomain(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &SecurityConfig{UIDDomain: "uid.example", TrustDomain: "trust.example"}
	got := claimToBeServerUserFrom(t, clientConfig, "server.example")
	if want := cur.Username + "@uid.example"; got != want {
		t.Errorf("client claimed %q, want %q", got, want)
	}
}

// claimToBeServerUserFrom runs cedar's CLAIMTOBE client and server and returns
// the identity the server recorded.
func claimToBeServerUserFrom(t *testing.T, clientConfig *SecurityConfig, serverUIDDomain string) string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConfig := &SecurityConfig{UIDDomain: serverUIDDomain}
	serverNeg := &SecurityNegotiation{ServerConfig: serverConfig}
	srvErr := make(chan error, 1)
	go func() {
		srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
			performClaimToBeAuthenticationServer(ctx, serverNeg)
	}()
	clientNeg := &SecurityNegotiation{ClientConfig: clientConfig, IsClient: true}
	if err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).
		performClaimToBeAuthenticationClient(ctx, clientNeg); err != nil {
		t.Fatalf("client CLAIMTOBE: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server CLAIMTOBE: %v", err)
	}
	return serverNeg.User
}
