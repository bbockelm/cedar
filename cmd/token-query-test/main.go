// Token Authentication Query Test Program
// This program tests TOKEN authentication by connecting to an HTCondor collector
// and querying for startd ads using token-based authentication.
//
// Usage:
//   go run main.go [--token-file <path>] [--token-dir <path>]
//
// Environment variables:
//   TOKEN_FILE - Path to token file (alternative to --token-file)
//   TOKEN_DIR  - Path to token directory (alternative to --token-dir)
//
// The program will:
// 1. Connect to the OSPool collector
// 2. Perform TOKEN authentication
// 3. Query for startd ads
// 4. Display results

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
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

	// OSPool trust domain (use flock.opensciencegrid.org for OSPool)
	TrustDomain = "flock.opensciencegrid.org"
)

var (
	tokenFile = flag.String("token-file", "", "Path to token file")
	tokenDir  = flag.String("token-dir", "", "Path to token directory")
	verbose   = flag.Bool("verbose", false, "Enable verbose output")
	limit     = flag.Int("limit", 5, "Maximum number of results to display")
)

func main() {
	flag.Parse()

	log.SetFlags(log.Ltime)
	log.Printf("🔍 TOKEN Authentication Query Test - HTCondor Collector")
	log.Printf("🎯 Target: %s:%s", CollectorHost, CollectorPort)

	// Get token configuration
	tokenFilePath := *tokenFile
	if tokenFilePath == "" {
		tokenFilePath = os.Getenv("TOKEN_FILE")
	}

	tokenDirPath := *tokenDir
	if tokenDirPath == "" {
		tokenDirPath = os.Getenv("TOKEN_DIR")
	}
	// Default to standard HTCondor token directory if not specified
	if tokenDirPath == "" && tokenFilePath == "" {
		tokenDirPath = os.Getenv("HOME") + "/.condor/tokens.d"
	}

	if tokenFilePath == "" && tokenDirPath == "" {
		log.Printf("❌ No token file or directory specified")
		log.Printf("   Use --token-file or --token-dir, or set TOKEN_FILE/TOKEN_DIR environment variables")
		os.Exit(1)
	}

	log.Printf("🔑 Token configuration:")
	if tokenFilePath != "" {
		log.Printf("   Token file: %s", tokenFilePath)
	}
	if tokenDirPath != "" {
		log.Printf("   Token directory: %s", tokenDirPath)
	}

	if err := performTokenQuery(tokenFilePath, tokenDirPath); err != nil {
		log.Printf("❌ Token authentication query failed: %v", err)
		os.Exit(1)
	}

	log.Printf("✅ Token authentication query completed successfully")
}

func performTokenQuery(tokenFile, tokenDir string) error {
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

	// Configure TOKEN authentication (force authentication)
	secConfig := &security.SecurityConfig{
		PeerName:       CollectorHost,
		AuthMethods:    []security.AuthMethod{security.AuthToken}, // Only TOKEN
		Authentication: security.SecurityRequired,                 // Force authentication
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional, // Optional encryption
		Integrity:      security.SecurityOptional, // Optional integrity
		Command:        commands.QUERY_STARTD_ADS, // Query startd ads
		TrustDomain:    TrustDomain,               // OSPool trust domain

		// Token configuration
		TokenFile: tokenFile,
		TokenDir:  tokenDir,
	}

	// Create security manager and authenticator
	auth := security.NewAuthenticator(secConfig, cedarStream)

	log.Printf("🔐 Starting TOKEN authentication handshake...")

	// Perform client-side handshake
	negotiation, err := auth.ClientHandshake(context.Background())
	if err != nil {
		return fmt.Errorf("TOKEN authentication handshake failed: %w", err)
	}

	log.Printf("🔐 TOKEN Authentication Results:")
	log.Printf("    Negotiated Auth: %s", negotiation.NegotiatedAuth)
	log.Printf("    Negotiated Crypto: %s", negotiation.NegotiatedCrypto)
	log.Printf("    Session ID: %s", negotiation.SessionId)
	log.Printf("    User: %s", negotiation.User)
	log.Printf("    Encryption Enabled: %t", cedarStream.IsEncrypted())

	// Mark stream as authenticated
	cedarStream.SetAuthenticated(true)

	// Send query for startd ads
	log.Printf("📊 Sending QUERY_STARTD_ADS query...")

	if err := sendStartdQuery(cedarStream); err != nil {
		return fmt.Errorf("startd query failed: %w", err)
	}

	return nil
}

func sendStartdQuery(cedarStream *stream.Stream) error {
	// Create query ClassAd
	queryAd := createStartdQueryAd()

	if *verbose {
		log.Printf("📋 Query ClassAd:")
		log.Printf("   MyType = \"Query\"")
		log.Printf("   TargetType = \"Machine\"")
		log.Printf("   Requirements = true")
		log.Printf("   LimitResults = %d", *limit)
	}

	// Create a message for sending the query
	queryMsg := message.NewMessageForStream(cedarStream)

	// Add the ClassAd to the message
	err := queryMsg.PutClassAd(context.Background(), queryAd)
	if err != nil {
		return fmt.Errorf("failed to add ClassAd to message: %w", err)
	}

	// Send the message (flush with End-of-Message)
	err = queryMsg.FinishMessage(context.Background())
	if err != nil {
		return fmt.Errorf("failed to send query message: %w", err)
	}

	log.Printf("✅ Query sent successfully")

	// Receive and process response
	log.Printf("📥 Waiting for collector response...")

	return receiveQueryResponse(cedarStream)
}

func receiveQueryResponse(cedarStream *stream.Stream) error {
	responseMsg := message.NewMessageFromStream(cedarStream)

	// Process response ads
	adsReceived := 0
	for {
		// Read "more" flag
		more, err := responseMsg.GetInt32(context.Background())
		if err != nil {
			log.Fatalf("Failed to read 'more' flag: %v", err)
		}

		if more == 0 {
			fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
			break
		}

		// Read ClassAd
		ad, err := responseMsg.GetClassAd(context.Background())
		if err != nil {
			log.Fatalf("Failed to read ClassAd: %v", err)
		}

		adsReceived++
		displayStartdAd(ad, adsReceived)
		fmt.Print("\n" + strings.Repeat("-", 60) + "\n")
	}

	log.Printf("✅ Successfully received %d ads", adsReceived)
	return nil
}

func displayStartdAd(ad *classad.ClassAd, num int) {
	log.Printf("\n📋 Ad #%d:", num)

	// Extract interesting attributes
	if name, ok := ad.EvaluateAttrString("Name"); ok {
		log.Printf("   Name: %s", name)
	}

	if machine, ok := ad.EvaluateAttrString("Machine"); ok {
		log.Printf("   Machine: %s", machine)
	}

	if state, ok := ad.EvaluateAttrString("State"); ok {
		log.Printf("   State: %s", state)
	}

	if activity, ok := ad.EvaluateAttrString("Activity"); ok {
		log.Printf("   Activity: %s", activity)
	}

	if cpus, ok := ad.EvaluateAttrInt("TotalSlotCpus"); ok {
		log.Printf("   CPUs: %d", cpus)
	} else if cpus, ok := ad.EvaluateAttrInt("Cpus"); ok {
		log.Printf("   CPUs: %d", cpus)
	}

	if memory, ok := ad.EvaluateAttrInt("TotalSlotMemory"); ok {
		log.Printf("   Memory: %d MB", memory)
	} else if memory, ok := ad.EvaluateAttrInt("Memory"); ok {
		log.Printf("   Memory: %d MB", memory)
	}

	if disk, ok := ad.EvaluateAttrInt("TotalSlotDisk"); ok {
		log.Printf("   Disk: %d KB", disk)
	} else if disk, ok := ad.EvaluateAttrInt("Disk"); ok {
		log.Printf("   Disk: %d KB", disk)
	}

	if *verbose {
		// Display all attributes in verbose mode
		log.Printf("   All attributes:")
		attrs := ad.GetAttributes()
		for _, attr := range attrs {
			if expr, ok := ad.Lookup(attr); ok {
				log.Printf("     %s = %s", attr, expr)
			}
		}
	}
}

// createStartdQueryAd creates a ClassAd for querying startd ads
func createStartdQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	// Set Requirements - use "true" to get all ads
	_ = ad.Set("Requirements", true)

	// Set a limit on results
	_ = ad.Set("LimitResults", int64(*limit))

	return ad
}
