package stream

import (
	"bytes"
	"context"
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
		if err := clientStream.SendMessage(context.Background(), testMessage); err != nil {
			t.Errorf("Failed to send message: %v", err)
		}
	}()

	// Receive and decrypt frame on server
	receivedFrame, err := serverStream.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Verify the message was correctly decrypted
	if !bytes.Equal(testMessage, receivedFrame) {
		t.Errorf("Message mismatch.\nExpected: %s\nReceived: %s", testMessage, receivedFrame)
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

	// Test multiple frames
	frames := [][]byte{
		[]byte("First encrypted message"),
		[]byte("Second encrypted message with more content"),
		[]byte("Third message: 🚀 Unicode test! 🔒"),
		[]byte(""), // Empty message
	}

	// Send all messages
	go func() {
		for i, msg := range frames {
			if err := clientStream.SendMessage(context.Background(), msg); err != nil {
				t.Errorf("Failed to send message %d: %v", i, err)
			}
		}
	}()

	// Receive and verify all messages
	for i, expectedFrame := range frames {
		receivedFrame, err := serverStream.ReceiveFrame(context.Background())
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}

		if !bytes.Equal(expectedFrame, receivedFrame) {
			t.Errorf("Message %d mismatch.\nExpected: %s\nReceived: %s", i, expectedFrame, receivedFrame)
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

	// Don't set any encryption keys - frames should be sent in plain text

	testFrame := []byte("This message should be sent in plain text")

	// Send unencrypted frame
	go func() {
		if err := clientStream.SendMessage(context.Background(), testFrame); err != nil {
			t.Errorf("Failed to send message: %v", err)
		}
	}()

	// Receive unencrypted frame
	receivedFrame, err := serverStream.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive frame: %v", err)
	}

	// Verify the frame was received correctly
	if !bytes.Equal(testFrame, receivedFrame) {
		t.Errorf("Frame mismatch.\nExpected: %s\nReceived: %s", testFrame, receivedFrame)
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
	testFrame := make([]byte, 100*1024)
	if _, err := rand.Read(testFrame); err != nil {
		t.Fatalf("Failed to generate test message: %v", err)
	}

	// Send encrypted message
	go func() {
		if err := clientStream.SendMessage(context.Background(), testFrame); err != nil {
			t.Errorf("Failed to send large message: %v", err)
		}
	}()

	// Receive and decrypt message
	receivedFrame, err := serverStream.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("Failed to receive large frame: %v", err)
	}

	// Verify the frame was correctly decrypted
	if !bytes.Equal(testFrame, receivedFrame) {
		t.Errorf("Large message mismatch. Expected %d bytes, got %d bytes", len(testFrame), len(receivedFrame))
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
