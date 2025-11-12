package stream

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
)

func TestAADImplementation(t *testing.T) {
	// Create a pair of connected streams
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)
	serverStream := NewStream(server)

	// Generate a 32-byte symmetric key for AES-256-GCM
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Set the same key on both streams
	if err := clientStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set client key: %v", err)
	}
	if err := serverStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set server key: %v", err)
	}

	// Test messages to verify AAD behavior
	messages := [][]byte{
		[]byte("First message - should use full AAD with digests"),
		[]byte("Second message - should use header-only AAD"),
		[]byte("Third message - should also use header-only AAD"),
	}

	// Send multiple messages from client to server
	go func() {
		for i, msg := range messages {
			if err := clientStream.SendMessage(context.Background(), msg); err != nil {
				t.Errorf("Failed to send message %d: %v", i, err)
				return
			}
		}
	}()

	// Receive and verify messages on server
	for i, expectedMsg := range messages {
		receivedMessage, err := serverStream.ReceiveFrame(context.Background())
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}

		if !bytes.Equal(expectedMsg, receivedMessage) {
			t.Errorf("Message %d mismatch.\nExpected: %s\nReceived: %s",
				i, string(expectedMsg), string(receivedMessage))
		}
	}

	// Verify AAD state tracking
	if !clientStream.finishedSendAAD {
		t.Error("Client should have finished send AAD after first message")
	}
	if !serverStream.finishedRecvAAD {
		t.Error("Server should have finished recv AAD after first message")
	}

	// Verify digest finalization occurred
	if clientStream.finalSendDigest == nil {
		t.Error("Client final send digest should be set")
	}
	if serverStream.finalRecvDigest == nil {
		t.Error("Server final recv digest should be set")
	}
}

func TestAADBidirectional(t *testing.T) {
	// Create a pair of connected streams
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)
	serverStream := NewStream(server)

	// Generate a 32-byte symmetric key for AES-256-GCM
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Set the same key on both streams
	if err := clientStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set client key: %v", err)
	}
	if err := serverStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set server key: %v", err)
	}

	// Test bidirectional communication to verify AAD works in both directions
	clientMsg := []byte("Message from client")
	serverMsg := []byte("Message from server")

	// Send client message first
	go func() {
		if err := clientStream.SendMessage(context.Background(), clientMsg); err != nil {
			t.Errorf("Failed to send client message: %v", err)
		}
	}()

	// Receive on server
	receivedFromClient, err := serverStream.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive client message: %v", err)
	}
	if !bytes.Equal(clientMsg, receivedFromClient) {
		t.Errorf("Client message mismatch")
	}

	// Send server response
	go func() {
		if err := serverStream.SendMessage(context.Background(), serverMsg); err != nil {
			t.Errorf("Failed to send server message: %v", err)
		}
	}()

	// Receive on client
	receivedFromServer, err := clientStream.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive server message: %v", err)
	}
	if !bytes.Equal(serverMsg, receivedFromServer) {
		t.Errorf("Server message mismatch")
	}

	// Verify both sides have completed AAD setup
	if !clientStream.finishedSendAAD || !serverStream.finishedSendAAD {
		t.Error("Both streams should have finished send AAD")
	}
	if !clientStream.finishedRecvAAD || !serverStream.finishedRecvAAD {
		t.Error("Both streams should have finished recv AAD")
	}
}
