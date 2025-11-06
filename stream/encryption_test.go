package stream

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

func TestStreamEncryption(t *testing.T) {
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

	// Test data
	testMessage := []byte("This is a secret message that should be encrypted!")

	// Send encrypted message from client to server
	go func() {
		if err := clientStream.SendMessage(testMessage); err != nil {
			t.Errorf("Failed to send message: %v", err)
		}
	}()

	// Receive and decrypt message on server
	receivedMessage, err := serverStream.ReceiveMessage()
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Verify the message was correctly decrypted
	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Message mismatch.\nExpected: %s\nReceived: %s", testMessage, receivedMessage)
	}
}

func TestStreamEncryptionMultipleMessages(t *testing.T) {
	// Create a pair of connected streams
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)
	serverStream := NewStream(server)

	// Generate a 32-byte symmetric key
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

	// Test multiple messages
	messages := [][]byte{
		[]byte("First encrypted message"),
		[]byte("Second encrypted message with more content"),
		[]byte("Third message: 🚀 Unicode test! 🔒"),
		[]byte(""), // Empty message
	}

	// Send all messages
	go func() {
		for i, msg := range messages {
			if err := clientStream.SendMessage(msg); err != nil {
				t.Errorf("Failed to send message %d: %v", i, err)
			}
		}
	}()

	// Receive and verify all messages
	for i, expectedMsg := range messages {
		receivedMsg, err := serverStream.ReceiveMessage()
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}

		if !bytes.Equal(expectedMsg, receivedMsg) {
			t.Errorf("Message %d mismatch.\nExpected: %s\nReceived: %s", i, expectedMsg, receivedMsg)
		}
	}
}

func TestStreamEncryptionWithoutKey(t *testing.T) {
	// Create a pair of connected streams
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)
	serverStream := NewStream(server)

	// Don't set any encryption keys - messages should be sent in plain text

	testMessage := []byte("This message should be sent in plain text")

	// Send unencrypted message
	go func() {
		if err := clientStream.SendMessage(testMessage); err != nil {
			t.Errorf("Failed to send message: %v", err)
		}
	}()

	// Receive unencrypted message
	receivedMessage, err := serverStream.ReceiveMessage()
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Verify the message was received correctly
	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Message mismatch.\nExpected: %s\nReceived: %s", testMessage, receivedMessage)
	}
}

func TestStreamEncryptionLargeMessage(t *testing.T) {
	// Create a pair of connected streams
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)
	serverStream := NewStream(server)

	// Generate a 32-byte symmetric key
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

	// Create a large test message (100KB)
	testMessage := make([]byte, 100*1024)
	if _, err := rand.Read(testMessage); err != nil {
		t.Fatalf("Failed to generate test message: %v", err)
	}

	// Send encrypted message
	go func() {
		if err := clientStream.SendMessage(testMessage); err != nil {
			t.Errorf("Failed to send large message: %v", err)
		}
	}()

	// Receive and decrypt message
	receivedMessage, err := serverStream.ReceiveMessage()
	if err != nil {
		t.Fatalf("Failed to receive large message: %v", err)
	}

	// Verify the message was correctly decrypted
	if !bytes.Equal(testMessage, receivedMessage) {
		t.Errorf("Large message mismatch. Expected %d bytes, got %d bytes", len(testMessage), len(receivedMessage))
	}
}

func TestInvalidKeySize(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientStream := NewStream(client)

	// Test invalid key sizes
	invalidKeys := [][]byte{
		make([]byte, 16), // 16 bytes (AES-128, but we expect 32)
		make([]byte, 24), // 24 bytes (AES-192, but we expect 32)
		make([]byte, 31), // 31 bytes (too short)
		make([]byte, 33), // 33 bytes (too long)
		make([]byte, 0),  // Empty key
	}

	for i, key := range invalidKeys {
		err := clientStream.SetSymmetricKey(key)
		if err == nil {
			t.Errorf("Expected error for invalid key size %d bytes (test case %d)", len(key), i)
		}
	}
}
