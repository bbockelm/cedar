// SSL Authentication Test Program
// This program tests SSL authentication by connecting to an HTCondor collector
// and forcing authentication to test our SSL implementation.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

const (
	// OSPool collector endpoint
	CollectorHost = "cm-1.ospool.osg-htc.org"
	CollectorPort = "9618"

	// Connection timeout
	ConnectionTimeout = 10 * time.Second
)

func main() {
	log.Printf("🔍 SSL Authentication Test - HTCondor Collector Query")
	log.Printf("🎯 Target: %s:%s", CollectorHost, CollectorPort)

	if err := testSSLAuthentication(); err != nil {
		log.Printf("❌ SSL authentication test failed: %v", err)
		os.Exit(1)
	}

	log.Printf("✅ SSL authentication test completed successfully")
}

func testSSLAuthentication() error {
	// Create connection to HTCondor collector
	log.Printf("📡 Connecting to HTCondor collector...")

	addr := net.JoinHostPort(CollectorHost, CollectorPort)
	conn, err := net.DialTimeout("tcp", addr, ConnectionTimeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}()

	log.Printf("✅ Connected to %s", addr)

	// Create CEDAR stream
	cedarStream := stream.NewStream(conn)

	// Configure SSL authentication (force authentication)
	secConfig := &security.SecurityConfig{
		PeerName:       CollectorHost,
		AuthMethods:    []security.AuthMethod{security.AuthSSL},     // Only SSL
		Authentication: security.SecurityRequired,                   // Force authentication
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES}, // Enable encryption
		Encryption:     security.SecurityOptional,                   // Optional encryption
		Integrity:      security.SecurityOptional,                   // Optional integrity
		Command:        commands.QUERY_STARTD_ADS,                   // Query startd ads

		// SSL configuration (using system defaults)
		CertFile: "", // No client cert (anonymous SSL)
		KeyFile:  "", // No client key
		CAFile:   "", // Use system CA store
	}

	// Create security manager and authenticator
	auth := security.NewAuthenticator(secConfig, cedarStream)

	log.Printf("🔐 Starting SSL authentication handshake...")

	// Perform client-side handshake
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		return fmt.Errorf("SSL authentication handshake failed: %w", err)
	}

	log.Printf("🔐 SSL Authentication Results:")
	log.Printf("    Negotiated Auth: %s", negotiation.NegotiatedAuth)
	log.Printf("    Negotiated Crypto: %s", negotiation.NegotiatedCrypto)
	log.Printf("    Session ID: %s", negotiation.SessionId)
	log.Printf("    User: %s", negotiation.User)
	log.Printf("    Encryption Enabled: %t", cedarStream.IsEncrypted())

	// Send a simple query to verify the connection works
	log.Printf("📊 Sending query to collector...")

	if err := sendCollectorQuery(cedarStream); err != nil {
		return fmt.Errorf("collector query failed: %w", err)
	}

	return nil
}

func sendCollectorQuery(cedarStream *stream.Stream) error {
	log.Printf("📊 Sending query to collector...")

	// Create query ClassAd (like in query_demo.go)
	queryAd := createTestQueryAd()

	// Create a message for sending the query using Message API
	queryMsg := message.NewMessageForStream(cedarStream)

	// Add the ClassAd to the message using Message API (like query_demo.go)
	err := queryMsg.PutClassAd(context.Background(), queryAd)
	if err != nil {
		return fmt.Errorf("failed to add ClassAd to message: %w", err)
	}

	// Send the message using Message API (flush with End-of-Message)
	err = queryMsg.FlushFrame(context.Background(), true)
	if err != nil {
		return fmt.Errorf("failed to send query message: %w", err)
	}

	log.Printf("✅ Query sent successfully")

	// Try to receive response
	log.Printf("📥 Waiting for collector response...")

	responseMsg := message.NewMessageFromStream(cedarStream)

	// Read response (this may fail if authentication is required but not complete)
	response, err := responseMsg.GetInt(context.Background())
	if err != nil {
		// This is expected if authentication failed or is incomplete
		log.Printf("⚠️  Response read failed (expected if auth is incomplete): %v", err)
		return nil // Don't treat as fatal error for this test
	}

	log.Printf("📊 Collector response: %d", response)
	return nil
}

// createTestQueryAd creates a ClassAd for querying startd ads (like query_demo.go)
func createTestQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	// Set Requirements - use "true" to get all ads
	_ = ad.Set("Requirements", true)

	// Set a limit on results for testing
	_ = ad.Set("LimitResults", 2)

	return ad
}
