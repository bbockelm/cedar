// Simple HTCondor Startd Query Client
//
// Focuses just on QUERY_STARTD_ADS with detailed protocol debugging
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-cedar/commands"
	"github.com/bbockelm/golang-cedar/message"
	"github.com/bbockelm/golang-cedar/security"
	"github.com/bbockelm/golang-cedar/stream"
)

func main() {
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

	fmt.Printf("🚀 Simple HTCondor Startd Query\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	addr := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	cedarStream := stream.NewStream(conn)

	fmt.Printf("🔐 Security handshake...\n")

	secConfig := &security.SecurityConfig{
		Command:        commands.QUERY_STARTD_ADS,
		AuthMethods:    []security.AuthMethod{security.AuthNone}, // Only try unauthenticated
		Authentication: security.SecurityNever,                   // Don't require auth
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityNever, // No encryption
		Integrity:      security.SecurityNever, // No integrity
	}

	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake()
	if err != nil {
		log.Fatalf("Security handshake failed: %v", err)
	}

	cedarStream.SetAuthenticated(true)

	fmt.Printf("✅ Handshake complete! User: %s\n", negotiation.User)

	// Send query
	fmt.Printf("📤 Sending QUERY_STARTD_ADS query...\n")

	queryAd := classad.New()
	queryAd.Set("MyType", "Query")
	queryAd.Set("TargetType", "Machine")
	queryAd.Set("Requirements", true)
	queryAd.Set("LimitResults", 10)

	fmt.Printf("📋 Query ClassAd:\n")
	fmt.Printf("   MyType = %q\n", "Query")
	fmt.Printf("   TargetType = %q\n", "Machine")
	fmt.Printf("   Requirements = %v\n", true)
	fmt.Printf("   LimitResults = %d\n", 10)

	msg := message.NewMessage()
	if err := msg.PutClassAd(queryAd); err != nil {
		log.Fatalf("Failed to serialize query: %v", err)
	}

	fmt.Printf("📏 Query message size: %d bytes\n", len(msg.Bytes()))

	if err := cedarStream.SendMessage(msg.Bytes()); err != nil {
		log.Fatalf("Failed to send query: %v", err)
	}

	fmt.Printf("📨 Query sent! Waiting for response...\n")

	// Read first response
	responseData, err := cedarStream.ReceiveMessage()
	if err != nil {
		log.Fatalf("Failed to receive response: %v", err)
	}

	fmt.Printf("📥 Received response: %d bytes\n", len(responseData))

	responseMsg := message.NewMessageFromBytes(responseData)

	numExprs, err := responseMsg.GetInt32()
	if err != nil {
		log.Fatalf("Failed to read numExprs: %v", err)
	}

	fmt.Printf("📊 Response indicates %d expressions\n", numExprs)

	if numExprs == 0 {
		fmt.Printf("❌ No startd ads available\n")
		fmt.Printf("\n💡 This might be normal if:\n")
		fmt.Printf("   - No machines are currently reporting to this collector\n")
		fmt.Printf("   - Authentication is required to see machine ads\n")
		fmt.Printf("   - The collector is configured to hide ads from unauthenticated users\n")
		return
	}

	fmt.Printf("📄 Processing ads...\n")

	adsReceived := 0
	for numExprs > 0 {
		adsReceived++

		fmt.Printf("\n📋 Ad #%d (%d expressions):\n", adsReceived, numExprs)

		// Read expressions
		for i := 0; i < int(numExprs); i++ {
			exprStr, err := responseMsg.GetString()
			if err != nil {
				log.Fatalf("Failed to read expression %d: %v", i, err)
			}
			fmt.Printf("   Expr %d: %s\n", i+1, exprStr)
		}

		// Read MyType and TargetType
		if myType, err := responseMsg.GetString(); err == nil {
			fmt.Printf("   MyType: %s\n", myType)
		}
		if targetType, err := responseMsg.GetString(); err == nil {
			fmt.Printf("   TargetType: %s\n", targetType)
		}

		// Get next response
		responseData, err = cedarStream.ReceiveMessage()
		if err != nil {
			fmt.Printf("❌ Failed to receive next response: %v\n", err)
			break
		}

		responseMsg = message.NewMessageFromBytes(responseData)
		numExprs, err = responseMsg.GetInt32()
		if err != nil {
			fmt.Printf("❌ Failed to read next numExprs: %v\n", err)
			break
		}

		if adsReceived >= 10 {
			fmt.Printf("⚠️  Limiting to first 10 ads for demo\n")
			break
		}
	}

	fmt.Printf("\n✅ Query complete! Received %d ads\n", adsReceived)
}
