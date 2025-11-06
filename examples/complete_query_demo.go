//go:build ignore

// Complete HTCondor Query Demo Client
//
// This demonstrates the full CEDAR protocol with proper security handshake
// and shows session information from the completed handshake.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

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

	fmt.Printf("🚀 HTCondor Complete Query Demo Client\n")
	fmt.Printf("📡 Connecting to %s:%d...\n", hostname, port)

	addr := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	cedarStream := stream.NewStream(conn)

	fmt.Printf("🔐 Performing security handshake...\n")

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

	if negotiation.SharedSecret != nil {
		if err := cedarStream.SetSymmetricKey(negotiation.SharedSecret); err != nil {
			log.Fatalf("Failed to set symmetric key: %v", err)
		}
	}

	cedarStream.SetAuthenticated(true)

	fmt.Printf("✅ Security handshake completed successfully!\n")
	fmt.Printf("📋 Session Information:\n")
	fmt.Printf("   Session ID: %s\n", negotiation.SessionId)
	fmt.Printf("   User: %s\n", negotiation.User)
	fmt.Printf("   Valid Commands: %s\n", negotiation.ValidCommands)
	fmt.Printf("   Command %d (QUERY_STARTD_ADS) allowed: %s\n",
		commands.QUERY_STARTD_ADS,
		checkCommandAllowed(negotiation.ValidCommands, commands.QUERY_STARTD_ADS))

	// Try querying different types of ads
	queries := []struct {
		name   string
		myType string
		target string
		cmd    int
	}{
		{"Startd Ads (Machines)", "Query", "Machine", commands.QUERY_STARTD_ADS},
		{"Collector Ads", "Query", "Collector", commands.QUERY_COLLECTOR_ADS},
		{"Schedd Ads (Schedulers)", "Query", "Scheduler", commands.QUERY_SCHEDD_ADS},
	}

	for _, q := range queries {
		fmt.Printf("\n🔍 Querying %s...\n", q.name)

		allowed := checkCommandAllowed(negotiation.ValidCommands, q.cmd)
		if allowed != "✅" {
			fmt.Printf("   ❌ Command %d not allowed, skipping\n", q.cmd)
			continue
		}

		count := performQuery(cedarStream, q.myType, q.target)
		fmt.Printf("   📊 Result: %d ads received\n", count)
	}
}

func checkCommandAllowed(validCommands string, cmdCode int) string {
	if strings.Contains(validCommands, fmt.Sprintf("%d", cmdCode)) {
		return "✅"
	}
	return "❌"
}

func performQuery(cedarStream *stream.Stream, myType, targetType string) int {
	// Create query ClassAd
	queryAd := classad.New()
	queryAd.Set("MyType", myType)
	queryAd.Set("TargetType", targetType)
	queryAd.Set("Requirements", "true")

	// Send query
	msg := message.NewMessage()
	if err := msg.PutClassAd(queryAd); err != nil {
		fmt.Printf("   ❌ Failed to serialize query: %v\n", err)
		return 0
	}

	if err := cedarStream.SendMessage(msg.Bytes()); err != nil {
		fmt.Printf("   ❌ Failed to send query: %v\n", err)
		return 0
	}

	// Process responses
	adsReceived := 0
	for {
		responseData, err := cedarStream.ReceiveMessage()
		if err != nil {
			fmt.Printf("   ❌ Failed to receive response: %v\n", err)
			break
		}

		responseMsg := message.NewMessageFromBytes(responseData)

		numExprs, err := responseMsg.GetInt32()
		if err != nil {
			fmt.Printf("   ❌ Failed to read response: %v\n", err)
			break
		}

		if numExprs == 0 {
			break // End of results
		}

		// Parse the ClassAd manually
		ad := classad.New()
		for i := 0; i < int(numExprs); i++ {
			exprStr, err := responseMsg.GetString()
			if err != nil {
				fmt.Printf("   ❌ Failed to read expression %d: %v\n", i, err)
				break
			}

			// Parse "attr = value"
			if eqPos := strings.Index(exprStr, " = "); eqPos > 0 {
				attr := strings.TrimSpace(exprStr[:eqPos])
				value := strings.TrimSpace(exprStr[eqPos+3:])
				if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
					value = value[1 : len(value)-1]
				}
				ad.Set(attr, value)
			}
		}

		// Read MyType and TargetType
		if myTypeStr, err := responseMsg.GetString(); err == nil && myTypeStr != "" {
			ad.Set("MyType", myTypeStr)
		}
		if targetTypeStr, err := responseMsg.GetString(); err == nil && targetTypeStr != "" {
			ad.Set("TargetType", targetTypeStr)
		}

		adsReceived++

		if adsReceived <= 3 { // Show details for first few ads
			fmt.Printf("   📄 Ad #%d:\n", adsReceived)
			printAdSummary(ad)
		}

		if adsReceived >= 10 { // Limit for demo
			fmt.Printf("   ⚠️  Limited to first 10 ads for demo\n")
			break
		}
	}

	return adsReceived
}

func printAdSummary(ad *classad.ClassAd) {
	attrs := []string{"Name", "Machine", "MyType", "MyAddress", "State", "Activity"}
	for _, attr := range attrs {
		if val, ok := ad.EvaluateAttrString(attr); ok {
			fmt.Printf("     %-12s: %s\n", attr, val)
		}
	}
}
