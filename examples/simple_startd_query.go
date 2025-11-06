//go:build ignore

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
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// Helper function to serialize ClassAd to bytes
func serializeClassAdToBytes(ad *classad.ClassAd) ([]byte, error) {
	mockStream := &SimpleMockStream{
		frames:    make([][]byte, 0),
		frameEOMs: make([]bool, 0),
		frameIdx:  0,
		encrypted: false,
	}

	msg := message.NewMessageForStream(mockStream)
	if err := msg.PutClassAd(ad); err != nil {
		return nil, err
	}

	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}

	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}

	return result, nil
}

// Helper function to parse Message from bytes
func parseMessageFromBytes(data []byte) (*message.Message, error) {
	mockStream := &SimpleMockStream{
		frames:    [][]byte{data},
		frameEOMs: []bool{true},
		frameIdx:  0,
		encrypted: false,
	}

	return message.NewMessageFromStream(mockStream), nil
}

// SimpleMockStream implements StreamInterface for serialization
type SimpleMockStream struct {
	frames    [][]byte
	frameEOMs []bool
	frameIdx  int
	encrypted bool
}

func (s *SimpleMockStream) ReadFrame() ([]byte, bool, error) {
	if s.frameIdx >= len(s.frames) {
		return nil, false, fmt.Errorf("no more frames")
	}

	data := s.frames[s.frameIdx]
	isEOM := s.frameEOMs[s.frameIdx]
	s.frameIdx++

	return data, isEOM, nil
}

func (s *SimpleMockStream) WriteFrame(data []byte, isEOM bool) error {
	s.frames = append(s.frames, data)
	s.frameEOMs = append(s.frameEOMs, isEOM)
	return nil
}

func (s *SimpleMockStream) IsEncrypted() bool {
	return s.encrypted
}

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

	queryData, err := serializeClassAdToBytes(queryAd)
	if err != nil {
		log.Fatalf("Failed to serialize query: %v", err)
	}

	fmt.Printf("📏 Query message size: %d bytes\n", len(queryData))

	if err := cedarStream.SendMessage(queryData); err != nil {
		log.Fatalf("Failed to send query: %v", err)
	}

	fmt.Printf("📨 Query sent! Waiting for response...\n")

	// Read first response
	responseData, err := cedarStream.ReceiveMessage()
	if err != nil {
		log.Fatalf("Failed to receive response: %v", err)
	}

	fmt.Printf("📥 Received response: %d bytes\n", len(responseData))

	responseMsg, err := parseMessageFromBytes(responseData)
	if err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

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

		responseMsg, err = parseMessageFromBytes(responseData)
		if err != nil {
			fmt.Printf("❌ Failed to parse next response: %v\n", err)
			break
		}
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
