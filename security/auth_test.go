package security

import (
	"log"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/stream"
)

func TestSecurityHandshake(t *testing.T) {
	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration - matches the example from the user request
	clientConfig := &SecurityConfig{
		AuthMethods:     []AuthMethod{AuthFS, AuthToken, AuthSSL},
		Authentication:  SecurityOptional,
		CryptoMethods:   []CryptoMethod{CryptoAES, CryptoBlowfish, Crypto3DES},
		Encryption:      SecurityOptional,
		Integrity:       SecurityOptional,
		RemoteVersion:   "$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 PackageID: 25.4.0-0.847437 GitSHA: a6507f91 RC $",
		ConnectSinful:   "<192.170.231.12:9618?alias=cm-2.ospool.osg-htc.org>",
		TrustDomain:     "flock.opensciencegrid.org",
		Subsystem:       "TOOL",
		ServerPid:       1020614,
		SessionDuration: 60,
		SessionLease:    3600,
		ECDHPublicKey:   "BK3KBDM3/jWErtDthhy6PZNAlX2ILu3bM5HGRUylauDgNrUDa/C9uFyJPFaaJ6Ny3GrjHbrc3DV3r4sR5rdh5Uw=",
	}

	// Server configuration - matches the example response
	serverConfig := &SecurityConfig{
		AuthMethods:     []AuthMethod{AuthToken, AuthSSL, AuthFS},
		Authentication:  SecurityNever,
		CryptoMethods:   []CryptoMethod{CryptoAES, CryptoBlowfish, Crypto3DES},
		Encryption:      SecurityOptional,
		Integrity:       SecurityOptional,
		RemoteVersion:   "$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 PackageID: 25.4.0-0.847437 GitSHA: a6507f91 RC $",
		TrustDomain:     "flock.opensciencegrid.org",
		SessionDuration: 60,
		SessionLease:    3600,
		ECDHPublicKey:   "BAZ1s1V4p2zeZ+FjM6aa3AahivmQJ5NaJ9t2tp+Y1d8aXObfW5Zy81BV5N0F5qQY+tiQh3NaW28/Q6dMMe74lSU=",
	}

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake()
		if err != nil {
			log.Printf("Server handshake failed: %v", err)
			serverErrChan <- err
		} else {
			log.Printf("Server handshake succeeded")
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(2 * time.Second)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake()
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server handshake result
	var serverNegotiation *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNegotiation = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify negotiation results
	t.Logf("Client negotiation result:")
	t.Logf("  Command: %d", clientNegotiation.Command)
	t.Logf("  Negotiated Auth: %s", clientNegotiation.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", clientNegotiation.NegotiatedCrypto)
	t.Logf("  Enact: %v", clientNegotiation.Enact)

	t.Logf("Server negotiation result:")
	t.Logf("  Command: %d", serverNegotiation.Command)
	t.Logf("  Negotiated Auth: %s", serverNegotiation.NegotiatedAuth)
	t.Logf("  Negotiated Crypto: %s", serverNegotiation.NegotiatedCrypto)
	t.Logf("  Enact: %v", serverNegotiation.Enact)

	// Both sides should agree on the negotiation
	if clientNegotiation.Command != serverNegotiation.Command {
		t.Errorf("Command mismatch: client=%d, server=%d",
			clientNegotiation.Command, serverNegotiation.Command)
	}

	if clientNegotiation.NegotiatedAuth != serverNegotiation.NegotiatedAuth {
		t.Errorf("Auth method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedAuth, serverNegotiation.NegotiatedAuth)
	}

	if clientNegotiation.NegotiatedCrypto != serverNegotiation.NegotiatedCrypto {
		t.Errorf("Crypto method mismatch: client=%s, server=%s",
			clientNegotiation.NegotiatedCrypto, serverNegotiation.NegotiatedCrypto)
	}

	// Verify we negotiated TOKEN auth (first common method)
	expectedAuth := AuthToken // First method in server list that client supports
	if clientNegotiation.NegotiatedAuth != expectedAuth {
		t.Errorf("Expected negotiated auth %s, got %s", expectedAuth, clientNegotiation.NegotiatedAuth)
	}

	// Verify we negotiated AES crypto (first common method)
	expectedCrypto := CryptoAES // First method in both lists
	if clientNegotiation.NegotiatedCrypto != expectedCrypto {
		t.Errorf("Expected negotiated crypto %s, got %s", expectedCrypto, clientNegotiation.NegotiatedCrypto)
	}

	// Both should enact since we have skipped auth
	if clientNegotiation.Enact || serverNegotiation.Enact {
		t.Error("Expected both sides to NOT enact security session")
	}
}

func TestSecurityHandshakeNoCommonMethods(t *testing.T) {
	// Create a pair of connected sockets for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create streams
	serverStream := stream.NewStream(server)
	clientStream := stream.NewStream(client)

	// Client configuration - only SSL
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
	}

	// Server configuration - only FS (no common auth method)
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		CryptoMethods:  []CryptoMethod{CryptoBlowfish}, // No common crypto either
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
	}

	// Create authenticators
	clientAuth := NewAuthenticator(clientConfig, clientStream)
	serverAuth := NewAuthenticator(serverConfig, serverStream)

	// Channel to coordinate the handshake
	serverResultChan := make(chan *SecurityNegotiation, 1)
	serverErrChan := make(chan error, 1)

	// Start server handshake in a goroutine
	go func() {
		result, err := serverAuth.ServerHandshake()
		if err != nil {
			serverErrChan <- err
		} else {
			serverResultChan <- result
		}
	}()

	// Give server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Perform client handshake
	clientNegotiation, err := clientAuth.ClientHandshake()
	if err != nil {
		t.Fatalf("Client handshake failed: %v", err)
	}

	// Wait for server handshake result
	var serverNegotiation *SecurityNegotiation
	select {
	case result := <-serverResultChan:
		serverNegotiation = result
	case err := <-serverErrChan:
		t.Fatalf("Server handshake failed: %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("Server handshake timed out")
	}

	// Verify no common methods were found
	if clientNegotiation.NegotiatedAuth != AuthNone {
		t.Errorf("Expected no common auth method, got %s", clientNegotiation.NegotiatedAuth)
	}

	if clientNegotiation.NegotiatedCrypto != "" {
		t.Errorf("Expected no common crypto method, got %s", clientNegotiation.NegotiatedCrypto)
	}

	// Should not enact without common methods
	if clientNegotiation.Enact || serverNegotiation.Enact {
		t.Error("Expected not to enact security session without common methods")
	}
}
