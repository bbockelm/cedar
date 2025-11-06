// Demo client for querying HTCondor startd ads with debugging
//
// This version includes debugging output to understand the protocol better.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/bbockelm/golang-cedar/commands"
	"github.com/bbockelm/golang-cedar/message"
	"github.com/bbockelm/golang-cedar/security"
	"github.com/bbockelm/golang-cedar/stream"

	"github.com/PelicanPlatform/classad/classad"
)

func main() {
	// Parse command line arguments
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <hostname> <port>\n", os.Args[0])
		fmt.Printf("Example: %s cm-1.ospool.osg-htc.org 9618\n", os.Args[0])
		os.Exit(1)
	}

	hostname := os.Args[1]
	portStr := os.Args[2]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid port: %s", portStr)
	}

	fmt.Printf("🚀 HTCondor Query Demo Client (Debug Version)\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	// Establish TCP connection
	addr := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create CEDAR stream
	cedarStream := stream.NewStream(conn)

	// Perform security handshake for QUERY_STARTD_ADS
	fmt.Printf("🔐 Performing security handshake...\n")

	// Create security config and authenticator
	secConfig := &security.SecurityConfig{
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthSSL, security.AuthToken, security.AuthNone},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake()
	if err != nil {
		log.Fatalf("Security handshake failed: %v", err)
	}

	// Set up encryption if negotiated
	if negotiation.SharedSecret != nil {
		if err := cedarStream.SetSymmetricKey(negotiation.SharedSecret); err != nil {
			log.Fatalf("Failed to set symmetric key: %v", err)
		}
	}

	cedarStream.SetAuthenticated(true)

	fmt.Printf("✅ Security handshake completed successfully\n")
	fmt.Printf("🔍 Sending query for startd ads...\n")

	// Create query ClassAd
	queryAd := createQueryAd()

	// Create message and send query ad
	msg := message.NewMessage()
	err = msg.PutClassAd(queryAd)
	if err != nil {
		log.Fatalf("Failed to serialize query ad: %v", err)
	}

	fmt.Printf("📤 Sending query ad with %d bytes\n", len(msg.Bytes()))

	// Send the message
	err = cedarStream.SendMessage(msg.Bytes())
	if err != nil {
		log.Fatalf("Failed to send query message: %v", err)
	}

	fmt.Printf("📨 Query sent, processing responses...\n\n")

	// Process response ads with debugging
	adsReceived := 0
	for {
		fmt.Printf("📥 Waiting for response message...\n")

		// Receive response message
		responseData, err := cedarStream.ReceiveMessage()
		if err != nil {
			log.Fatalf("Failed to receive response: %v", err)
		}

		fmt.Printf("📦 Received %d bytes of response data\n", len(responseData))
		fmt.Printf("🔍 First 100 bytes (hex): %x\n", responseData[:min(100, len(responseData))])

		responseMsg := message.NewMessageFromBytes(responseData)

		// Read "more" flag
		fmt.Printf("📊 Reading 'more' flag...\n")
		more, err := responseMsg.GetInt32()
		if err != nil {
			log.Fatalf("Failed to read 'more' flag: %v", err)
		}

		fmt.Printf("📈 More flag: %d\n", more)

		if more == 0 {
			fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
			break
		}

		// Read ClassAd
		fmt.Printf("📜 Reading ClassAd...\n")
		ad, err := responseMsg.GetClassAd()
		if err != nil {
			// Instead of failing, let's see what we can debug
			fmt.Printf("❌ Failed to read ClassAd: %v\n", err)
			fmt.Printf("🔍 Response message analysis failed\n")
			fmt.Printf("🔍 Next 200 bytes (hex): %x\n", responseData[4:min(204, len(responseData))])
			break
		}

		adsReceived++
		fmt.Printf("📄 Ad #%d received successfully\n", adsReceived)
		printAd(ad)
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")

		// Limit output for demo purposes
		if adsReceived >= 3 {
			fmt.Printf("⚠️  Limiting output to first 3 ads for demo purposes\n")
			break
		}
	}
}

// createQueryAd creates a ClassAd for querying startd ads
func createQueryAd() *classad.ClassAd {
	ad := classad.New()

	// Set MyType and TargetType as required by HTCondor query protocol
	ad.Set("MyType", "Query")
	ad.Set("TargetType", "Machine") // Query Machine ads (startd)

	// Set Requirements - use true to get all ads
	ad.Set("Requirements", true)

	return ad
}

// printAd prints key attributes of a ClassAd
func printAd(ad *classad.ClassAd) {
	// Key attributes to display
	keyAttrs := []string{
		"Name", "Machine", "MyAddress", "State", "Activity",
		"LoadAvg", "TotalSlots", "Cpus", "Memory", "Disk",
		"OpSysAndVer", "Arch", "CondorVersion", "MyType", "StartdIpAddr",
	}

	for _, attrName := range keyAttrs {
		if val, ok := ad.EvaluateAttrString(attrName); ok {
			fmt.Printf("  %-15s = %q\n", attrName, val)
		} else if val, ok := ad.EvaluateAttrNumber(attrName); ok {
			fmt.Printf("  %-15s = %.0f\n", attrName, val)
		} else if val, ok := ad.EvaluateAttrBool(attrName); ok {
			fmt.Printf("  %-15s = %t\n", attrName, val)
		}
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
