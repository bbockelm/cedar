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
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSetTimeout tests the socket timeout functionality
func TestSetTimeout(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	_ = NewStream(client) // clientStream not used in this test

	// Test setting timeout
	err := serverStream.SetTimeout(5 * time.Second)
	if err != nil {
		t.Fatalf("SetTimeout failed: %v", err)
	}

	// Verify timeout was set
	if serverStream.GetTimeout() != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", serverStream.GetTimeout())
	}

	// Test clearing timeout
	err = serverStream.SetTimeout(0)
	if err != nil {
		t.Fatalf("SetTimeout(0) failed: %v", err)
	}

	if serverStream.GetTimeout() != 0 {
		t.Errorf("Expected timeout 0, got %v", serverStream.GetTimeout())
	}

	// Note: net.Pipe() doesn't support deadlines, so we can't test actual timeout behavior here
	// The timeout functionality is tested with real TCP connections in TestTimeoutActualBehavior
}

// TestGetEncryption tests the encryption state query
func TestGetEncryption(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)

	// Initially, encryption should be disabled
	if serverStream.GetEncryption() {
		t.Error("Expected encryption to be disabled initially")
	}

	// Enable encryption manually (normally done via key exchange)
	serverStream.encrypted = true

	if !serverStream.GetEncryption() {
		t.Error("Expected encryption to be enabled")
	}
}

// TestSetCryptoMode tests enabling/disabling encryption
func TestSetCryptoMode(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)

	// Try to enable encryption without key exchange - should fail
	if serverStream.SetCryptoMode(true) {
		t.Error("Expected SetCryptoMode(true) to fail without key exchange")
	}

	// Set up encryption manually for testing
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_ = serverStream.SetSymmetricKey(key)

	// Now enabling should succeed
	if !serverStream.SetCryptoMode(true) {
		t.Error("Expected SetCryptoMode(true) to succeed with key")
	}

	if !serverStream.GetEncryption() {
		t.Error("Expected encryption to be enabled")
	}

	// Disable encryption
	if !serverStream.SetCryptoMode(false) {
		t.Error("Expected SetCryptoMode(false) to succeed")
	}

	if serverStream.GetEncryption() {
		t.Error("Expected encryption to be disabled")
	}
}

// TestSecretOperations tests PutSecret and GetSecret
func TestSecretOperations(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Test without encryption
	secret := "my_secret_password_123"

	// Send secret from client
	go func() {
		err := clientStream.PutSecret(secret)
		if err != nil {
			t.Errorf("PutSecret failed: %v", err)
		}
	}()

	// Receive secret on server
	receivedSecret, err := serverStream.GetSecret()
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if receivedSecret != secret {
		t.Errorf("Expected secret %q, got %q", secret, receivedSecret)
	}
}

// TestSecretOperationsWithEncryption tests PutSecret and GetSecret with encryption
func TestSecretOperationsWithEncryption(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Set up encryption on both ends
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	if err := serverStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set server encryption key: %v", err)
	}
	if err := clientStream.SetSymmetricKey(key); err != nil {
		t.Fatalf("Failed to set client encryption key: %v", err)
	}

	// Disable encryption initially - PutSecret/GetSecret should temporarily enable it
	serverStream.SetCryptoMode(false)
	clientStream.SetCryptoMode(false)

	secret := "encrypted_secret_password"

	// Use channel to synchronize goroutine completion
	done := make(chan error, 1)

	// Send secret from client
	go func() {
		err := clientStream.PutSecret(secret)
		done <- err
	}()

	// Receive secret on server
	receivedSecret, err := serverStream.GetSecret()
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	// Wait for sender to complete
	if err := <-done; err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	if receivedSecret != secret {
		t.Errorf("Expected secret %q, got %q", secret, receivedSecret)
	}

	// Verify encryption state was restored (should be off)
	if clientStream.GetEncryption() {
		t.Error("Expected encryption to be restored to off state")
	}
	if serverStream.GetEncryption() {
		t.Error("Expected encryption to be restored to off state")
	}
}

// TestPutGetFile tests file transfer operations
func TestPutGetFile(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "stream-file-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file with known content (about 100KB)
	sourceFile := filepath.Join(tmpDir, "source.dat")
	baseData := []byte("This is test file data for file transfer testing.\n")
	testData := make([]byte, 0, 102400)
	for len(testData) < 100000 {
		testData = append(testData, baseData...)
	}

	if err := os.WriteFile(sourceFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	destFile := filepath.Join(tmpDir, "dest.dat")

	// Transfer file from client to server
	// Use channel to synchronize completion
	type result struct {
		bytes int64
		err   error
	}
	done := make(chan result, 1)

	go func() {
		sentBytes, sendErr := clientStream.PutFile(sourceFile)
		done <- result{bytes: sentBytes, err: sendErr}
	}()

	receivedBytes, err := serverStream.GetFile(destFile)
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}

	// Wait for sender to complete
	res := <-done
	if res.err != nil {
		t.Fatalf("PutFile failed: %v", res.err)
	}
	sentBytes := res.bytes

	// Verify byte counts
	expectedSize := int64(len(testData))
	if sentBytes != expectedSize {
		t.Errorf("Expected to send %d bytes, sent %d", expectedSize, sentBytes)
	}
	if receivedBytes != expectedSize {
		t.Errorf("Expected to receive %d bytes, received %d", expectedSize, receivedBytes)
	}

	// Verify file content
	receivedData, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if !bytes.Equal(testData, receivedData) {
		t.Errorf("File content mismatch: expected %d bytes, got %d bytes", len(testData), len(receivedData))
	}
}

// TestPutGetFileEmpty tests transferring an empty file
func TestPutGetFileEmpty(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "stream-file-test-empty-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create an empty test file
	sourceFile := filepath.Join(tmpDir, "empty.dat")
	if err := os.WriteFile(sourceFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	destFile := filepath.Join(tmpDir, "empty_dest.dat")

	// Transfer empty file
	go func() {
		_, _ = clientStream.PutFile(sourceFile)
	}()

	receivedBytes, err := serverStream.GetFile(destFile)
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}

	if receivedBytes != 0 {
		t.Errorf("Expected to receive 0 bytes, received %d", receivedBytes)
	}

	// Verify destination file exists and is empty
	destData, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if len(destData) != 0 {
		t.Errorf("Expected empty file, got %d bytes", len(destData))
	}
}

// TestPutGetFileLarge tests transferring a larger file
func TestPutGetFileLarge(t *testing.T) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "stream-file-test-large-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a large test file (1MB of random data)
	sourceFile := filepath.Join(tmpDir, "large.dat")
	testData := make([]byte, 1024*1024)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	if err := os.WriteFile(sourceFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	destFile := filepath.Join(tmpDir, "large_dest.dat")

	// Transfer large file
	var sendErr error
	var sentBytes int64
	go func() {
		sentBytes, sendErr = clientStream.PutFile(sourceFile)
	}()

	receivedBytes, err := serverStream.GetFile(destFile)
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}

	// Wait for sender to complete
	time.Sleep(100 * time.Millisecond)
	if sendErr != nil {
		t.Fatalf("PutFile failed: %v", sendErr)
	}

	// Verify byte counts
	expectedSize := int64(len(testData))
	if sentBytes != expectedSize {
		t.Errorf("Expected to send %d bytes, sent %d", expectedSize, sentBytes)
	}
	if receivedBytes != expectedSize {
		t.Errorf("Expected to receive %d bytes, received %d", expectedSize, receivedBytes)
	}

	// Verify file content by comparing hashes
	receivedData, err := os.ReadFile(destFile)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if !bytes.Equal(testData, receivedData) {
		t.Error("Large file content mismatch")
	}
}

// TestPutFileNonexistent tests error handling for nonexistent file
func TestPutFileNonexistent(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	clientStream := NewStream(client)

	// Try to send a file that doesn't exist
	_, err := clientStream.PutFile("/nonexistent/file/path.dat")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

// TestGetFileError tests error handling during file receive
func TestGetFileError(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)

	// Close the client to cause a read error
	_ = client.Close()

	// Try to receive file - should fail
	_, err := serverStream.GetFile("/tmp/test.dat")
	if err == nil {
		t.Error("Expected error when receiving from closed connection, got nil")
	}
}

// TestSecretEmptyString tests sending an empty secret
func TestSecretEmptyString(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Send empty secret
	go func() {
		err := clientStream.PutSecret("")
		if err != nil {
			t.Errorf("PutSecret failed: %v", err)
		}
	}()

	// Receive empty secret
	receivedSecret, err := serverStream.GetSecret()
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if receivedSecret != "" {
		t.Errorf("Expected empty secret, got %q", receivedSecret)
	}
}

// BenchmarkPutFile benchmarks file transfer performance
func BenchmarkPutFile(b *testing.B) {
	// Create a pair of connected sockets
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	// Create a temporary directory for test files
	tmpDir, _ := os.MkdirTemp("", "stream-bench-*")
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create a test file (100KB)
	sourceFile := filepath.Join(tmpDir, "bench.dat")
	testData := make([]byte, 100*1024)
	_, _ = rand.Read(testData)
	_ = os.WriteFile(sourceFile, testData, 0644)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		destFile := filepath.Join(tmpDir, "bench_dest.dat")

		done := make(chan bool)
		go func() {
			_, _ = serverStream.GetFile(destFile)
			done <- true
		}()

		_, _ = clientStream.PutFile(sourceFile)
		<-done

		_ = os.Remove(destFile)
	}
}

// BenchmarkSecret benchmarks secret transfer performance
func BenchmarkSecret(b *testing.B) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	serverStream := NewStream(server)
	clientStream := NewStream(client)

	secret := "benchmark_secret_password_123"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		done := make(chan bool)
		go func() {
			_, _ = serverStream.GetSecret()
			done <- true
		}()

		_ = clientStream.PutSecret(secret)
		<-done
	}
}

// TestTimeoutContext tests that timeout affects blocking operations
func TestTimeoutContext(t *testing.T) {
	// Skip this test in short mode as it involves timing
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	// Create client that will timeout
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = client.Close() }()

	clientStream := NewStream(client)

	// Set a short timeout
	_ = clientStream.SetTimeout(100 * time.Millisecond)

	// Try to read when no data is sent - should timeout quickly
	start := time.Now()
	_, err = clientStream.ReceiveFrame()
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	// Should have timed out within reasonable time (not blocked indefinitely)
	if elapsed > 2*time.Second {
		t.Errorf("Timeout took too long: %v (expected ~100ms)", elapsed)
	}
}

// TestGetFileWithDifferentSizes tests file transfer with various sizes
func TestGetFileWithDifferentSizes(t *testing.T) {
	sizes := []int{0, 1, 100, 1024, 10 * 1024, 100 * 1024}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = server.Close() }()
			defer func() { _ = client.Close() }()

			serverStream := NewStream(server)
			clientStream := NewStream(client)

			tmpDir, _ := os.MkdirTemp("", "stream-size-test-*")
			defer func() { _ = os.RemoveAll(tmpDir) }()

			// Create test file
			sourceFile := filepath.Join(tmpDir, "test.dat")
			testData := make([]byte, size)
			if size > 0 {
				_, _ = io.ReadFull(rand.Reader, testData)
			}
			_ = os.WriteFile(sourceFile, testData, 0644)

			destFile := filepath.Join(tmpDir, "dest.dat")

			// Transfer file
			go func() {
				_, _ = clientStream.PutFile(sourceFile)
			}()

			receivedBytes, err := serverStream.GetFile(destFile)
			if err != nil {
				t.Fatalf("GetFile failed for size %d: %v", size, err)
			}

			if receivedBytes != int64(size) {
				t.Errorf("Size mismatch: expected %d, got %d", size, receivedBytes)
			}

			// Verify content
			receivedData, _ := os.ReadFile(destFile)
			if !bytes.Equal(testData, receivedData) {
				t.Errorf("Content mismatch for size %d", size)
			}
		})
	}
}
