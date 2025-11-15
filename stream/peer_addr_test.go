// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stream

import (
	"net"
	"strings"
	"testing"
)

// TestStreamPeerAddr tests that the stream captures and returns the peer address correctly
func TestStreamPeerAddr(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	// Create stream from server side (will see client's address)
	serverStream := NewStream(server)

	// The peer address should be captured
	peerAddr := serverStream.GetPeerAddr()
	if peerAddr == "" {
		t.Error("Expected peer address to be captured, got empty string")
	}

	// Should be in sinful string format (wrapped in angle brackets)
	if !strings.HasPrefix(peerAddr, "<") || !strings.HasSuffix(peerAddr, ">") {
		t.Errorf("Expected peer address to be in sinful string format <addr>, got: %s", peerAddr)
	}

	t.Logf("Captured peer address: %s", peerAddr)

	// Test SetPeerAddr
	customAddr := "<192.168.1.100:9618>"
	serverStream.SetPeerAddr(customAddr)

	if serverStream.GetPeerAddr() != customAddr {
		t.Errorf("Expected peer address to be %s after SetPeerAddr, got: %s",
			customAddr, serverStream.GetPeerAddr())
	}
}

// TestStreamPeerAddrWithNilConn tests that NewStream handles nil connections gracefully
func TestStreamPeerAddrWithNilConn(t *testing.T) {
	// Create stream with nil connection (shouldn't panic)
	stream := NewStream(nil)

	peerAddr := stream.GetPeerAddr()
	if peerAddr != "" {
		t.Errorf("Expected empty peer address for nil connection, got: %s", peerAddr)
	}
}

// TestStreamSetConnection tests that SetConnection updates the peer address
func TestStreamSetConnection(t *testing.T) {
	// Create first connection
	server1, client1 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = client1.Close() }()

	stream := NewStream(server1)
	firstAddr := stream.GetPeerAddr()

	if firstAddr == "" {
		t.Error("Expected first peer address to be captured")
	}

	// Create second connection
	server2, client2 := net.Pipe()
	defer func() { _ = server2.Close() }()
	defer func() { _ = client2.Close() }()

	// Replace connection
	stream.SetConnection(server2)
	secondAddr := stream.GetPeerAddr()

	if secondAddr == "" {
		t.Error("Expected second peer address to be captured after SetConnection")
	}

	// The addresses might be different (different pipes have different addresses)
	t.Logf("First address: %s", firstAddr)
	t.Logf("Second address: %s", secondAddr)
}
