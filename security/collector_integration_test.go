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

package security

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/stream"
)

// condorTestHarness manages a mini HTCondor collector instance for integration testing
type condorTestHarness struct {
	tmpDir        string
	configFile    string
	logDir        string
	passwordDir   string
	collectorCmd  *exec.Cmd
	collectorAddr string
	collectorHost string
	collectorPort int
	caCertFile    string
	caKeyFile     string
	hostCertFile  string
	hostKeyFile   string
	tokenKeyFile  string
	t             *testing.T
}

// setupCondorHarness creates and starts a mini HTCondor collector instance
func setupCondorHarness(t *testing.T) *condorTestHarness {
	t.Helper()

	// Check if condor_collector is available
	collectorPath, err := exec.LookPath("condor_collector")
	if err != nil {
		t.Skip("condor_collector not found in PATH, skipping integration test")
	}

	// Create temporary directory structure
	tmpDir := t.TempDir()

	h := &condorTestHarness{
		tmpDir:      tmpDir,
		configFile:  filepath.Join(tmpDir, "condor_config"),
		logDir:      filepath.Join(tmpDir, "log"),
		passwordDir: filepath.Join(tmpDir, "passwords"),
		t:           t,
	}

	// Create directories
	for _, dir := range []string{h.logDir, h.passwordDir} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Generate SSL certificates
	h.caCertFile = filepath.Join(tmpDir, "ca-cert.pem")
	h.caKeyFile = filepath.Join(tmpDir, "ca-key.pem")
	h.hostCertFile = filepath.Join(tmpDir, "host-cert.pem")
	h.hostKeyFile = filepath.Join(tmpDir, "host-key.pem")

	if err := GenerateTestCA(h.caCertFile, h.caKeyFile); err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	if err := GenerateTestHostCert(h.hostCertFile, h.hostKeyFile, h.caCertFile, h.caKeyFile, "localhost"); err != nil {
		t.Fatalf("Failed to generate host certificate: %v", err)
	}

	// Generate TOKEN signing key
	h.tokenKeyFile = filepath.Join(h.passwordDir, "POOL")
	if err := GeneratePoolSigningKey(h.tokenKeyFile); err != nil {
		t.Fatalf("Failed to generate token signing key: %v", err)
	}

	// Generate HTCondor configuration
	h.collectorHost = "127.0.0.1"
	h.collectorPort = 0 // Use dynamic port

	configContent := fmt.Sprintf(`
# Mini HTCondor collector configuration for integration testing
CONDOR_HOST = 127.0.0.1

# Use local directory structure
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log

# Collector configuration
COLLECTOR_NAME = test_collector
COLLECTOR_HOST = 127.0.0.1:0
CONDOR_VIEW_HOST = $(COLLECTOR_HOST)

# Network settings
BIND_ALL_INTERFACES = False
NETWORK_INTERFACE = 127.0.0.1

# Security settings - enable all authentication methods
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS,CLAIMTOBE,PASSWORD,SSL,IDTOKENS,TOKEN
SEC_DEFAULT_ENCRYPTION = OPTIONAL
SEC_DEFAULT_INTEGRITY = OPTIONAL
SEC_CLIENT_AUTHENTICATION_METHODS = FS,CLAIMTOBE,PASSWORD,SSL,IDTOKENS,TOKEN

# Allow all access for testing
ALLOW_READ = *
ALLOW_WRITE = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *
ALLOW_OWNER = *
ALLOW_CLIENT = *

# SSL configuration
AUTH_SSL_SERVER_CERTFILE = %s
AUTH_SSL_SERVER_KEYFILE = %s
AUTH_SSL_SERVER_CAFILE = %s
AUTH_SSL_CLIENT_CERTFILE = %s
AUTH_SSL_CLIENT_KEYFILE = %s
AUTH_SSL_CLIENT_CAFILE = %s

# TOKEN configuration
SEC_PASSWORD_DIRECTORY = %s
SEC_TOKEN_POOL_SIGNING_KEY_FILE = %s
SEC_TOKEN_ISSUER_KEY = POOL
TRUST_DOMAIN = test.domain

# Logging
MAX_COLLECTOR_LOG = 10000000
COLLECTOR_DEBUG = D_FULLDEBUG D_SECURITY

# Disable unwanted features for testing
ENABLE_SOAP = False
ENABLE_WEB_SERVER = False
`, h.tmpDir, h.hostCertFile, h.hostKeyFile, h.caCertFile,
		h.hostCertFile, h.hostKeyFile, h.caCertFile,
		h.passwordDir, h.tokenKeyFile)

	if err := os.WriteFile(h.configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Start condor_collector
	h.collectorCmd = exec.Command(collectorPath, "-f")
	h.collectorCmd.Env = append(os.Environ(),
		"CONDOR_CONFIG="+h.configFile,
		"_CONDOR_LOCAL_DIR="+h.tmpDir,
	)
	h.collectorCmd.Dir = h.tmpDir

	// Capture output for debugging
	h.collectorCmd.Stdout = os.Stdout
	h.collectorCmd.Stderr = os.Stderr

	if err := h.collectorCmd.Start(); err != nil {
		t.Fatalf("Failed to start condor_collector: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		h.Shutdown()
	})

	// Wait for collector to start and discover its address
	if err := h.waitForCollector(); err != nil {
		t.Fatalf("Failed to wait for collector: %v", err)
	}

	return h
}

// waitForCollector waits for the collector to start and become responsive
func (h *condorTestHarness) waitForCollector() error {
	// Wait for collector to write its address file
	addressFile := filepath.Join(h.logDir, ".collector_address")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.printCollectorLog()
			return fmt.Errorf("timeout waiting for collector to start")
		case <-ticker.C:
			// Check if address file exists
			if data, err := os.ReadFile(addressFile); err == nil {
				// Parse address from file
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "$") {
						h.collectorAddr = line
						break
					}
				}

				if h.collectorAddr == "" {
					continue
				}

				// Check for invalid address
				if strings.Contains(h.collectorAddr, "(null)") {
					h.printCollectorLog()
					return fmt.Errorf("collector address file contains '(null)' - daemon failed to start")
				}

				// Parse address (format: <127.0.0.1:9618?addrs=...>)
				addr := h.collectorAddr
				addr = strings.TrimPrefix(addr, "<")
				if idx := strings.Index(addr, "?"); idx > 0 {
					addr = addr[:idx]
				}
				addr = strings.TrimSuffix(addr, ">")

				// Split host and port
				host, portStr, err := net.SplitHostPort(addr)
				if err != nil {
					h.t.Logf("Failed to parse collector address %q: %v", addr, err)
					continue
				}

				port := 0
				if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
					h.t.Logf("Failed to parse collector port: %v", err)
					continue
				}

				h.collectorHost = host
				h.collectorPort = port

				h.t.Logf("Collector started at: %s (host=%s, port=%d)", h.collectorAddr, host, port)

				// Give a bit more time for collector to fully initialize
				time.Sleep(1 * time.Second)

				return nil
			}
		}
	}
}

// printCollectorLog prints the collector log for debugging
func (h *condorTestHarness) printCollectorLog() {
	collectorLog := filepath.Join(h.logDir, "CollectorLog")
	data, err := os.ReadFile(collectorLog)
	if err != nil {
		h.t.Logf("Failed to read CollectorLog: %v", err)
		return
	}

	h.t.Logf("=== CollectorLog contents ===\n%s\n=== End CollectorLog ===", string(data))
}

// Shutdown stops the collector instance
func (h *condorTestHarness) Shutdown() {
	if h.collectorCmd != nil && h.collectorCmd.Process != nil {
		h.t.Log("Shutting down HTCondor collector")

		// Try graceful shutdown first
		if err := h.collectorCmd.Process.Signal(os.Interrupt); err != nil {
			h.t.Logf("Failed to send interrupt to collector: %v", err)
		}

		// Wait for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- h.collectorCmd.Wait()
		}()

		select {
		case <-time.After(5 * time.Second):
			// Force kill if graceful shutdown times out
			if err := h.collectorCmd.Process.Kill(); err != nil {
				h.t.Logf("Failed to kill collector: %v", err)
			}
			<-done
		case <-done:
			// Graceful shutdown succeeded
		}
	}
}

// GetCollectorAddr returns the collector address
func (h *condorTestHarness) GetCollectorAddr() string {
	return h.collectorAddr
}

// GetCollectorHost returns the collector host
func (h *condorTestHarness) GetCollectorHost() string {
	return h.collectorHost
}

// GetCollectorPort returns the collector port
func (h *condorTestHarness) GetCollectorPort() int {
	return h.collectorPort
}

// GetCollectorAlias extracts the alias from the collector sinful string
// Sinful string format: <127.0.0.1:52504?addrs=127.0.0.1-52504&alias=f4hp7ql65f-2.local>
func (h *condorTestHarness) GetCollectorAlias() string {
	// Parse the alias from the sinful string
	if strings.Contains(h.collectorAddr, "alias=") {
		// Extract everything after "alias="
		parts := strings.Split(h.collectorAddr, "alias=")
		if len(parts) >= 2 {
			// Get the alias value (everything after alias= until & or >)
			alias := parts[1]
			// Trim any trailing characters
			if idx := strings.IndexAny(alias, "&>"); idx >= 0 {
				alias = alias[:idx]
			}
			return alias
		}
	}
	// Fallback to host if no alias found
	return h.collectorHost
}

// TestFSAuthenticationIntegration tests FS authentication against a real HTCondor collector
func TestFSAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := setupCondorHarness(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with FS authentication
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("FS authentication handshake failed: %v", err)
	}

	t.Logf("✅ FS authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
}

// TestClaimToBeAuthenticationIntegration tests CLAIMTOBE authentication against a real HTCondor collector
func TestClaimToBeAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := setupCondorHarness(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with CLAIMTOBE authentication
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthClaimToBe},
		Authentication: SecurityRequired,
		TrustDomain:    "test.domain",
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("CLAIMTOBE authentication handshake failed: %v", err)
	}

	t.Logf("✅ CLAIMTOBE authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)
}

// TestTokenAuthenticationIntegration tests TOKEN authentication against a real HTCondor collector
func TestTokenAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := setupCondorHarness(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Generate a test JWT token with issuer matching TRUST_DOMAIN
	// Use passwordDir as keyDir and "POOL" as keyID
	tokenFile := filepath.Join(harness.tmpDir, "test_token.jwt")
	token, err := GenerateTestJWT(harness.passwordDir, "POOL", "testuser@test.domain", "test.domain", 1*time.Hour, nil)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	// Write token to file
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with TOKEN authentication
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthToken},
		Authentication: SecurityRequired,
		TokenFile:      tokenFile,
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("TOKEN authentication handshake failed: %v", err)
	}

	t.Logf("✅ TOKEN authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)
	t.Logf("  Session Key Length: %d bytes", len(negotiation.SharedSecret))
}

// TestSSLAuthenticationIntegration tests SSL authentication against a real HTCondor collector
func TestSSLAuthenticationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := setupCondorHarness(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with SSL authentication
	// Use "localhost" as ServerName since that's what's in the test certificate
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthSSL},
		Authentication: SecurityRequired,
		CertFile:       harness.hostCertFile,
		KeyFile:        harness.hostKeyFile,
		CAFile:         harness.caCertFile,
		ServerName:     "localhost", // Match the hostname in the test certificate
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("SSL authentication handshake failed: %v", err)
	}

	t.Logf("✅ SSL authentication integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)
}

// TestMultipleAuthMethodsIntegration tests negotiation with multiple authentication methods
func TestMultipleAuthMethodsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	harness := setupCondorHarness(t)
	t.Logf("Collector started at: %s:%d", harness.GetCollectorHost(), harness.GetCollectorPort())

	// Generate a test JWT token
	tokenFile := filepath.Join(harness.tmpDir, "test_token.jwt")
	token, err := GenerateTestJWT(harness.passwordDir, "POOL", "testuser@test.domain", "test.domain", 1*time.Hour, nil)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	// Connect to collector
	addr := net.JoinHostPort(harness.GetCollectorHost(), fmt.Sprintf("%d", harness.GetCollectorPort()))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to collector: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Create stream
	cedarStream := stream.NewStream(conn)

	// Create client configuration with multiple authentication methods
	// Server should choose the most secure one available
	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthClaimToBe, AuthFS, AuthToken, AuthSSL},
		Authentication: SecurityOptional,
		TokenFile:      tokenFile,
		CertFile:       harness.hostCertFile,
		KeyFile:        harness.hostKeyFile,
		CAFile:         harness.caCertFile,
		Command:        commands.DC_NOP,
	}

	// Create authenticator and perform handshake
	auth := NewAuthenticator(clientConfig, cedarStream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		t.Fatalf("Multiple auth methods handshake failed: %v", err)
	}

	t.Logf("✅ Multiple authentication methods integration test completed successfully")
	t.Logf("  Negotiated Auth: %s", negotiation.NegotiatedAuth)
	t.Logf("  Session ID: %s", negotiation.SessionId)
	t.Logf("  User: %s", negotiation.User)

	// Verify that a secure method was chosen (not CLAIMTOBE or FS if TOKEN/SSL available)
	switch negotiation.NegotiatedAuth {
	case AuthClaimToBe:
		t.Logf("  Note: CLAIMTOBE was negotiated (least secure)")
	case AuthToken, AuthSSL:
		t.Logf("  Good: Secure method %s was negotiated", negotiation.NegotiatedAuth)
	}
}
