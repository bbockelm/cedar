package stream

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHTCondorNonceBehavior(t *testing.T) {
	// Create a stream for testing encryption behavior
	stream := &Stream{}

	// Generate a 32-byte symmetric key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Set up encryption
	if err := stream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	// Test messages
	message1 := []byte("First message")
	message2 := []byte("Second message")
	message3 := []byte("Third message")

	// Encrypt first message
	encrypted1, err := stream.encryptData(message1)
	if err != nil {
		t.Fatalf("Failed to encrypt message 1: %v", err)
	}

	// Encrypt second message
	encrypted2, err := stream.encryptData(message2)
	if err != nil {
		t.Fatalf("Failed to encrypt message 2: %v", err)
	}

	// Encrypt third message
	encrypted3, err := stream.encryptData(message3)
	if err != nil {
		t.Fatalf("Failed to encrypt message 3: %v", err)
	}

	// Verify size behavior: first message should include 16-byte IV
	expectedSize1 := len(message1) + 16 + 16 // message + auth tag + IV
	if len(encrypted1) != expectedSize1 {
		t.Errorf("First encrypted message size mismatch. Expected %d (msg:%d + auth:16 + IV:16), got %d",
			expectedSize1, len(message1), len(encrypted1))
	}

	// Subsequent messages should not include IV
	expectedSize2 := len(message2) + 16 // message + auth tag only
	if len(encrypted2) != expectedSize2 {
		t.Errorf("Second encrypted message size mismatch. Expected %d (msg:%d + auth:16), got %d",
			expectedSize2, len(message2), len(encrypted2))
	}

	expectedSize3 := len(message3) + 16 // message + auth tag only
	if len(encrypted3) != expectedSize3 {
		t.Errorf("Third encrypted message size mismatch. Expected %d (msg:%d + auth:16), got %d",
			expectedSize3, len(message3), len(encrypted3))
	}

	t.Logf("✅ Encryption size behavior verified:")
	t.Logf("   First message:  %d bytes (includes 16-byte IV)", len(encrypted1))
	t.Logf("   Second message: %d bytes (no IV)", len(encrypted2))
	t.Logf("   Third message:  %d bytes (no IV)", len(encrypted3))

	// Create new stream for decryption to test the receive side
	decryptStream := &Stream{}
	if err := decryptStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set decrypt key: %v", err)
	}

	// Decrypt all messages in order
	decrypted1, err := decryptStream.decryptData(encrypted1)
	if err != nil {
		t.Fatalf("Failed to decrypt message 1: %v", err)
	}

	decrypted2, err := decryptStream.decryptData(encrypted2)
	if err != nil {
		t.Fatalf("Failed to decrypt message 2: %v", err)
	}

	decrypted3, err := decryptStream.decryptData(encrypted3)
	if err != nil {
		t.Fatalf("Failed to decrypt message 3: %v", err)
	}

	// Verify message content
	if !bytes.Equal(message1, decrypted1) {
		t.Errorf("Message 1 content mismatch.\nExpected: %s\nReceived: %s", message1, decrypted1)
	}
	if !bytes.Equal(message2, decrypted2) {
		t.Errorf("Message 2 content mismatch.\nExpected: %s\nReceived: %s", message2, decrypted2)
	}
	if !bytes.Equal(message3, decrypted3) {
		t.Errorf("Message 3 content mismatch.\nExpected: %s\nReceived: %s", message3, decrypted3)
	}

	t.Logf("✅ All messages decrypted correctly with HTCondor nonce behavior")

	// Verify counter increments
	if decryptStream.encryptCounter != 0 {
		t.Errorf("Decrypt stream encrypt counter should be 0, got %d", decryptStream.encryptCounter)
	}
	if decryptStream.decryptCounter != 3 {
		t.Errorf("Decrypt stream decrypt counter should be 3, got %d", decryptStream.decryptCounter)
	}

	t.Logf("✅ Message counters work correctly: encrypt=%d, decrypt=%d",
		decryptStream.encryptCounter, decryptStream.decryptCounter)
}
