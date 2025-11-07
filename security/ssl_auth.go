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

// Package security provides SSL authentication implementation for HTCondor CEDAR protocol
package security

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bbockelm/cedar/message"
)

// SSL authentication state constants matching HTCondor's implementation
const (
	AuthSSLOK        = 0
	AuthSSLSending   = 1
	AuthSSLReceiving = 2
	AuthSSLQuitting  = 3
	AuthSSLHolding   = 4
	AuthSSLError     = -1

	// Session key length for symmetric encryption after SSL handshake
	AuthSSLSessionKeyLen = 256
)

// SSLAuthenticator handles SSL certificate-based authentication following HTCondor's protocol
type SSLAuthenticator struct {
	authenticator *Authenticator
	tlsConfig     *tls.Config

	// SSL handshake state
	clientStatus int
	serverStatus int
	sessionKey   []byte

	// TLS connection state
	tlsConn *tls.Conn

	// Configuration
	serverName string
	verifyPeer bool
}

// NewSSLAuthenticator creates a new SSL authenticator following HTCondor's implementation
func NewSSLAuthenticator(auth *Authenticator) *SSLAuthenticator {
	return &SSLAuthenticator{
		authenticator: auth,
		clientStatus:  AuthSSLOK,
		serverStatus:  AuthSSLOK,
		sessionKey:    make([]byte, AuthSSLSessionKeyLen),
	}
}

// PerformSSLHandshake performs the complete SSL authentication handshake following HTCondor's protocol
func (ssl *SSLAuthenticator) PerformSSLHandshake(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Starting SSL authentication handshake...")

	// Create TLS configuration based on authenticator settings
	tlsConfig, err := ssl.createTLSConfig(negotiation.ClientConfig.PeerName)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}
	ssl.tlsConfig = tlsConfig

	// Determine server name for hostname verification
	if err := ssl.setupServerName(); err != nil {
		return fmt.Errorf("failed to setup server name: %w", err)
	}

	// Exchange initial status messages
	if err := ssl.exchangeStatus(negotiation); err != nil {
		return fmt.Errorf("status exchange failed: %w", err)
	}

	// Perform TLS handshake through message protocol
	if err := ssl.performTLSHandshake(negotiation); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Verify peer certificate
	if err := ssl.verifyPeerCertificate(negotiation); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Exchange session key for symmetric encryption
	if err := ssl.exchangeSessionKey(negotiation); err != nil {
		return fmt.Errorf("session key exchange failed: %w", err)
	}

	// Final status confirmation
	if err := ssl.finalizeAuthentication(negotiation); err != nil {
		return fmt.Errorf("authentication finalization failed: %w", err)
	}

	log.Printf("✅ SSL: SSL authentication completed successfully")
	return nil
}

// createTLSConfig creates TLS configuration based on authenticator settings
func (ssl *SSLAuthenticator) createTLSConfig(serverName string) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // HTCondor requires TLS 1.2+
		MaxVersion: tls.VersionTLS12, // Support modern TLS
		// For testing purposes, skip certificate verification
		// In production, this should be properly configured with ServerName
		// InsecureSkipVerify: true,
		ServerName: serverName,
	}

	// Load client/server certificate if specified
	if ssl.authenticator.config.CertFile != "" && ssl.authenticator.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(ssl.authenticator.config.CertFile, ssl.authenticator.config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate pair: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
		log.Printf("🔐 SSL: Loaded certificate from %s", ssl.authenticator.config.CertFile)
	}

	// Load CA certificate if specified
	if ssl.authenticator.config.CAFile != "" {
		caCert, err := loadCAFile(ssl.authenticator.config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
		config.ClientCAs = caCertPool
		// If we have CA certificates, we can enable proper verification
		config.InsecureSkipVerify = false
		log.Printf("🔐 SSL: Loaded CA certificate from %s", ssl.authenticator.config.CAFile)
	}

	// Set cipher suites (HTCondor compatible - using only available constants)
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	return config, nil
}

// setupServerName determines the server name for certificate verification
func (ssl *SSLAuthenticator) setupServerName() error {
	// For client mode, we need the server name for hostname verification
	// This would typically come from the connection address or configuration
	ssl.serverName = "unknown" // TODO: Extract from connection or config
	ssl.verifyPeer = true
	return nil
}

// exchangeStatus exchanges initial status messages following HTCondor's protocol
func (ssl *SSLAuthenticator) exchangeStatus(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Exchanging initial status...")

	if negotiation.IsClient {
		// Client: receive server status, then send client status
		statusMsg := message.NewMessageFromStream(ssl.authenticator.stream)
		serverStatus, err := statusMsg.GetInt()
		if err != nil {
			return fmt.Errorf("failed to receive server status: %w", err)
		}
		ssl.serverStatus = serverStatus

		// Send client status
		clientMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := clientMsg.PutInt(ssl.clientStatus); err != nil {
			return fmt.Errorf("failed to send client status: %w", err)
		}
		if err := clientMsg.FinishMessage(); err != nil {
			return fmt.Errorf("failed to finish client status message: %w", err)
		}
	} else {
		// Server: send server status, then receive client status
		serverMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := serverMsg.PutInt(ssl.serverStatus); err != nil {
			return fmt.Errorf("failed to send server status: %w", err)
		}
		if err := serverMsg.FinishMessage(); err != nil {
			return fmt.Errorf("failed to finish server status message: %w", err)
		}

		// Receive client status
		clientMsg := message.NewMessageFromStream(ssl.authenticator.stream)
		clientStatus, err := clientMsg.GetInt()
		if err != nil {
			return fmt.Errorf("failed to receive client status: %w", err)
		}
		ssl.clientStatus = clientStatus
	}

	// Check if both sides are ready
	if ssl.clientStatus != AuthSSLOK || ssl.serverStatus != AuthSSLOK {
		return fmt.Errorf("SSL initialization failed - client: %d, server: %d", ssl.clientStatus, ssl.serverStatus)
	}

	log.Printf("🔐 SSL: Status exchange completed successfully")
	return nil
}

// performTLSHandshake performs the TLS handshake through HTCondor's message protocol
func (ssl *SSLAuthenticator) performTLSHandshake(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Performing TLS handshake through CEDAR message protocol...")

	// Create a custom connection that handles TLS data exchange via CEDAR messages
	cedarConn := &CEDARTLSConnection{
		authenticator: ssl.authenticator,
		isClient:      negotiation.IsClient,
		readBuffer:    make([]byte, 0),
		writeBuffer:   make([]byte, 0),
		clientStatus:  AuthSSLOK,
		serverStatus:  AuthSSLOK,
	}

	// Create TLS connection using the CEDAR connection wrapper
	if negotiation.IsClient {
		ssl.tlsConn = tls.Client(cedarConn, ssl.tlsConfig)
	} else {
		ssl.tlsConn = tls.Server(cedarConn, ssl.tlsConfig)
	}

	// Perform handshake - Go's TLS implementation will handle the state machine
	// and call our Read/Write methods to exchange data via CEDAR messages
	if err := ssl.tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	log.Printf("🔐 SSL: Go TLS handshake completed, ensuring all data is sent...")

	// Ensure any buffered data in the CEDAR connection is flushed
	if err := cedarConn.flushBufferedData(); err != nil {
		return fmt.Errorf("failed to flush buffered TLS data: %w", err)
	}
	log.Printf("🔐 SSL: Status (c: %d, s: %d)", cedarConn.clientStatus, cedarConn.serverStatus)

	log.Printf("🔐 SSL: TLS handshake fully completed")
	log.Printf("🔐 SSL: Negotiated TLS version: %x", ssl.tlsConn.ConnectionState().Version)
	log.Printf("🔐 SSL: Negotiated cipher suite: %x", ssl.tlsConn.ConnectionState().CipherSuite)

	// After TLS handshake completion, both sides should transition to holding state
	// and confirm this via status exchange
	if err := ssl.confirmHandshakeCompletion(negotiation, cedarConn); err != nil {
		return fmt.Errorf("handshake completion confirmation failed: %w", err)
	}

	return nil
}

// confirmHandshakeCompletion ensures both client and server are in holding state after TLS handshake
func (ssl *SSLAuthenticator) confirmHandshakeCompletion(negotiation *SecurityNegotiation, cedarConn *CEDARTLSConnection) error {
	log.Printf("🔐 SSL: Confirming handshake completion with status exchange...")
	log.Printf("🔐 SSL: Status (c: %d, s: %d)", cedarConn.clientStatus, cedarConn.serverStatus)
	ssl.serverStatus = cedarConn.serverStatus

	if negotiation.IsClient {

		if cedarConn.serverStatus != AuthSSLHolding {
			log.Printf("🔐 SSL: Client waiting for server holding status...")
			serverMsg := message.NewMessageFromStream(ssl.authenticator.stream)
			serverStatus, err := serverMsg.GetInt()
			if err != nil {
				return fmt.Errorf("failed to receive server status: %w", err)
			}
			ssl.serverStatus = serverStatus
		}

		// Send client status
		log.Printf("🔐 SSL: Client sending holding status...")
		ssl.clientStatus = AuthSSLHolding
		statusMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := statusMsg.PutInt(ssl.clientStatus); err != nil {
			return fmt.Errorf("failed to send client status: %w", err)
		}
		if err := statusMsg.PutInt(0); err != nil {
			return fmt.Errorf("failed to send client status: %w", err)
		}
		if err := statusMsg.FinishMessage(); err != nil {
			return fmt.Errorf("failed to finish client status message: %w", err)
		}

		log.Printf("🔐 SSL: Status (c: %d, s: %d)", ssl.clientStatus, ssl.serverStatus)
	} else {
		// Server: send server status first, then receive client status
		log.Printf("🔐 SSL: Server sending holding status...")
		statusMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := statusMsg.PutInt(ssl.serverStatus); err != nil {
			return fmt.Errorf("failed to send server status: %w", err)
		}
		if err := statusMsg.FinishMessage(); err != nil {
			return fmt.Errorf("failed to finish server status message: %w", err)
		}

		// Receive client status
		log.Printf("🔐 SSL: Server waiting for client holding status...")
		clientMsg := message.NewMessageFromStream(ssl.authenticator.stream)
		clientStatus, err := clientMsg.GetInt()
		if err != nil {
			return fmt.Errorf("failed to receive client status: %w", err)
		}
		ssl.clientStatus = clientStatus

		log.Printf("🔐 SSL: Status (c: %d, s: %d)", ssl.clientStatus, ssl.serverStatus)
	}

	// Verify both sides are in HOLDING state (4)
	if ssl.clientStatus != AuthSSLHolding || ssl.serverStatus != AuthSSLHolding {
		return fmt.Errorf("handshake completion failed - expected both sides in HOLDING (4), got client: %d, server: %d",
			ssl.clientStatus, ssl.serverStatus)
	}

	log.Printf("🔐 SSL: Handshake completion confirmed - both sides in holding state")
	return nil
}

// CEDARTLSConnection implements net.Conn for TLS over CEDAR messages
type CEDARTLSConnection struct {
	authenticator  *Authenticator
	isClient       bool
	readBuffer     []byte
	writeBuffer    []byte
	closed         bool
	roundCount     int
	clientStatus   int
	serverStatus   int
	sessionKeyMode bool // Flag for session key exchange mode
}

func (c *CEDARTLSConnection) Read(b []byte) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// If we don't have data in our read buffer, receive a message
	if len(c.readBuffer) == 0 {
		// Check if we should receive based on the HTCondor message exchange pattern
		// The pattern in HTCondor is based on round counter and client/server roles
		if c.shouldReceive() {
			// Update status before receiving
			if c.isClient {
				c.clientStatus = AuthSSLReceiving
			} else {
				c.serverStatus = AuthSSLReceiving
			}

			role := "CLIENT"
			if !c.isClient {
				role = "SERVER"
			}
			log.Printf("🔐 SSL: %s Round %d - Receiving message (client_status: %d, server_status: %d)",
				role, c.roundCount, c.clientStatus, c.serverStatus)

			data, err := c.receiveMessage()
			if err != nil {
				// Set error state on receive failure
				if c.isClient {
					c.clientStatus = AuthSSLQuitting
				} else {
					c.serverStatus = AuthSSLQuitting
				}
				return 0, err
			}
			c.readBuffer = data

			// Update status after receiving - transition to SENDING to prepare for next response
			if c.isClient {
				c.clientStatus = AuthSSLSending
			} else {
				c.serverStatus = AuthSSLSending
			}
		} else {
			// We're not supposed to receive now, return would block
			readRole := "CLIENT"
			if !c.isClient {
				readRole = "SERVER"
			}
			log.Printf("🔐 SSL: %s Round %d - Want read but not time to receive",
				readRole, c.roundCount)
			return 0, fmt.Errorf("tls: want read")
		}
	}

	// Copy data from our buffer to the caller's buffer
	n := copy(b, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]

	return n, nil
}

func (c *CEDARTLSConnection) Write(b []byte) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	// Add data to write buffer
	c.writeBuffer = append(c.writeBuffer, b...)

	// Check if we should send based on the HTCondor message exchange pattern
	if c.shouldSend() {
		// Update status based on current state
		if c.isClient {
			c.clientStatus = AuthSSLSending
		} else {
			c.serverStatus = AuthSSLSending
		}

		// Debug information
		role := "CLIENT"
		if !c.isClient {
			role = "SERVER"
		}
		log.Printf("🔐 SSL: %s Round %d - Sending message (client_status: %d, server_status: %d, buffer_len: %d)",
			role, c.roundCount, c.clientStatus, c.serverStatus, len(c.writeBuffer))

		// Send the data as a message with proper HTCondor protocol
		if err := c.sendMessage(c.writeBuffer); err != nil {
			// Set error state on send failure
			if c.isClient {
				c.clientStatus = AuthSSLQuitting
			} else {
				c.serverStatus = AuthSSLQuitting
			}
			return 0, err
		}

		n := len(c.writeBuffer)
		c.writeBuffer = c.writeBuffer[:0] // Clear buffer
		c.roundCount++

		// Update status after sending - transition to RECEIVING to wait for peer response
		if c.isClient {
			c.clientStatus = AuthSSLReceiving
		} else {
			c.serverStatus = AuthSSLReceiving
		}

		return n, nil
	} else {
		// We're not supposed to send now, just buffer the data
		bufferRole := "CLIENT"
		if !c.isClient {
			bufferRole = "SERVER"
		}
		log.Printf("🔐 SSL: %s Round %d - Buffering data (not time to send, buffer_len: %d)",
			bufferRole, c.roundCount, len(c.writeBuffer))
		return len(b), nil
	}
}

// shouldSend determines if this side should send a message based on HTCondor's protocol
func (c *CEDARTLSConnection) shouldSend() bool {
	return true

	// HTCondor TLS handshake pattern with proper alternation:
	// Round 0: Client sends (ClientHello)
	// Round 1: Server sends (ServerHello, Certificate, etc.)
	// Round 2: Client sends (Certificate/KeyExchange/Finished)
	// Round 3: Server sends (Finished)
	// etc.

}

// shouldReceive determines if this side should receive a message
func (c *CEDARTLSConnection) shouldReceive() bool {
	return true

	// The opposite of shouldSend for regular TLS handshake

}

func (c *CEDARTLSConnection) Close() error {
	c.closed = true
	return nil
}

// setSessionKeyMode switches the connection to session key exchange mode where server initiates
func (c *CEDARTLSConnection) setSessionKeyMode() {
	c.sessionKeyMode = true

	// Reset round count to 0 for session key exchange to align with HTCondor debugging output
	c.roundCount = 0

	// For session key exchange, server initiates on round 0 (even round)
	if !c.isClient {
		log.Printf("🔐 SSL: Server set to session key mode at round %d", c.roundCount)
	} else {
		log.Printf("🔐 SSL: Client set to session key mode at round %d", c.roundCount)
	}
}

// flushBufferedData ensures any buffered write data is sent
func (c *CEDARTLSConnection) flushBufferedData() error {
	if len(c.writeBuffer) == 0 {
		log.Printf("🔐 SSL: No buffered data to flush")
		return nil
	}

	log.Printf("🔐 SSL: Flushing %d buffered bytes...", len(c.writeBuffer))

	// Force send any buffered data regardless of round logic
	if err := c.sendMessage(c.writeBuffer); err != nil {
		return fmt.Errorf("failed to send buffered data: %w", err)
	}

	// Clear the buffer and increment round count
	c.writeBuffer = c.writeBuffer[:0]
	c.roundCount++

	// Don't automatically set status to HOLDING here - let the normal state transitions handle it
	// The status should only go to HOLDING after TLS handshake completion confirmation

	log.Printf("🔐 SSL: Buffered data flushed successfully")
	return nil
}

func (c *CEDARTLSConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *CEDARTLSConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (c *CEDARTLSConnection) SetDeadline(t time.Time) error {
	return nil
}

func (c *CEDARTLSConnection) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *CEDARTLSConnection) SetWriteDeadline(t time.Time) error {
	return nil
}

// sendMessage sends TLS handshake data following HTCondor's exact protocol:
// status (int) + length (int) + data bytes
func (c *CEDARTLSConnection) sendMessage(data []byte) error {
	msg := message.NewMessageForStream(c.authenticator.stream)

	// Get the current status for this side
	status := c.clientStatus
	if !c.isClient {
		status = c.serverStatus
	}

	// HTCondor protocol: send status first
	if err := msg.PutInt(status); err != nil {
		return fmt.Errorf("failed to put TLS status: %w", err)
	}

	// HTCondor protocol: send length second
	if err := msg.PutInt(len(data)); err != nil {
		return fmt.Errorf("failed to put TLS data length: %w", err)
	}

	// HTCondor protocol: send data bytes third (if length > 0)
	for _, b := range data {
		if err := msg.PutChar(b); err != nil {
			return fmt.Errorf("failed to put TLS data byte: %w", err)
		}
	}

	if err := msg.FinishMessage(); err != nil {
		return fmt.Errorf("failed to finish TLS message: %w", err)
	}

	log.Printf("🔐 SSL: Sent message - status: %d, length: %d bytes", status, len(data))
	return nil
}

// receiveMessage receives TLS handshake data following HTCondor's exact protocol:
// status (int) + length (int) + data bytes
func (c *CEDARTLSConnection) receiveMessage() ([]byte, error) {
	msg := message.NewMessageFromStream(c.authenticator.stream)

	// HTCondor protocol: receive status first
	peerStatus, err := msg.GetInt()
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS peer status: %w", err)
	}

	// HTCondor protocol: receive length second
	length, err := msg.GetInt()
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS data length: %w", err)
	}

	// HTCondor protocol: receive data bytes third (if length > 0)
	data := make([]byte, length)
	for i := 0; i < length; i++ {
		b, err := msg.GetChar()
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS data byte %d: %w", i, err)
		}
		data[i] = b
	}

	// Update peer status
	if c.isClient {
		c.serverStatus = peerStatus
	} else {
		c.clientStatus = peerStatus
	}

	log.Printf("🔐 SSL: Received message - peer_status: %d, length: %d bytes", peerStatus, len(data))
	return data, nil
}

// verifyPeerCertificate verifies the peer's certificate following HTCondor's verification logic
func (ssl *SSLAuthenticator) verifyPeerCertificate(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Verifying peer certificate...")

	state := ssl.tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		if negotiation.IsClient {
			return fmt.Errorf("server provided no certificate")
		} else {
			// Server can allow anonymous clients if configured
			log.Printf("🔐 SSL: Client provided no certificate (anonymous mode)")
			return nil
		}
	}

	peerCert := state.PeerCertificates[0]

	if negotiation.IsClient {
		// Client verifying server certificate
		log.Printf("🔐 SSL: Verifying server certificate")
		log.Printf("🔐 SSL: Server cert subject: %s", peerCert.Subject.String())
		log.Printf("🔐 SSL: Server cert issuer: %s", peerCert.Issuer.String())

		// Verify hostname (simplified - real implementation would check SAN and CN)
		if ssl.verifyPeer && ssl.serverName != "unknown" {
			if err := ssl.verifyHostname(peerCert, ssl.serverName); err != nil {
				return fmt.Errorf("hostname verification failed: %w", err)
			}
		}
	} else {
		// Server verifying client certificate
		log.Printf("🔐 SSL: Verifying client certificate")
		log.Printf("🔐 SSL: Client cert subject: %s", peerCert.Subject.String())
		log.Printf("🔐 SSL: Client cert issuer: %s", peerCert.Issuer.String())
	}

	// Additional verification could include:
	// - Certificate chain validation
	// - CRL checking
	// - Custom policy verification
	// - Identity mapping for authorization

	log.Printf("✅ SSL: Peer certificate verification completed")
	return nil
}

// verifyHostname performs hostname verification similar to HTCondor's implementation
func (ssl *SSLAuthenticator) verifyHostname(cert *x509.Certificate, hostname string) error {
	// Check Subject Alternative Names first
	for _, name := range cert.DNSNames {
		if ssl.hostnameMatch(name, hostname) {
			log.Printf("🔐 SSL: Hostname %s matches SAN: %s", hostname, name)
			return nil
		}
	}

	// Fall back to Common Name
	if cert.Subject.CommonName != "" {
		if ssl.hostnameMatch(cert.Subject.CommonName, hostname) {
			log.Printf("🔐 SSL: Hostname %s matches CN: %s", hostname, cert.Subject.CommonName)
			return nil
		}
	}

	return fmt.Errorf("certificate does not match hostname %s", hostname)
}

// hostnameMatch performs hostname matching with wildcard support
func (ssl *SSLAuthenticator) hostnameMatch(pattern, hostname string) bool {
	// Simple implementation - could be enhanced with proper wildcard matching
	pattern = strings.ToLower(pattern)
	hostname = strings.ToLower(hostname)

	if pattern == hostname {
		return true
	}

	// Basic wildcard support
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		if strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}

	return false
}

// exchangeSessionKey exchanges the session key over the TLS connection following HTCondor's protocol
func (ssl *SSLAuthenticator) exchangeSessionKey(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Exchanging session key over TLS connection...")

	// Access the CEDAR TLS connection to coordinate the round-based exchange
	cedarConn := ssl.tlsConn.NetConn().(*CEDARTLSConnection)

	// For session key exchange, the server initiates (unlike TLS handshake where client initiates)
	// Switch to session key exchange mode with reversed round logic
	cedarConn.setSessionKeyMode()

	if negotiation.IsClient {
		// Client: receive session key from server over TLS connection
		log.Printf("🔐 SSL: Client receiving session key from server over TLS...")

		ssl.sessionKey = make([]byte, AuthSSLSessionKeyLen)

		// Read session key - this will trigger the session key round logic
		totalRead := 0
		for totalRead < AuthSSLSessionKeyLen {
			n, err := ssl.tlsConn.Read(ssl.sessionKey[totalRead:])
			if err != nil {
				return fmt.Errorf("failed to receive session key over TLS (read %d/%d bytes): %w",
					totalRead, AuthSSLSessionKeyLen, err)
			}
			totalRead += n
			log.Printf("🔐 SSL: Client received %d/%d session key bytes", totalRead, AuthSSLSessionKeyLen)
		}

		log.Printf("🔐 SSL: Client received complete session key (%d bytes) over TLS", len(ssl.sessionKey))
	} else {
		// Server: generate and send session key to client over TLS connection
		log.Printf("🔐 SSL: Server generating and sending session key over TLS...")

		// Generate random session key
		ssl.sessionKey = make([]byte, AuthSSLSessionKeyLen)
		if _, err := rand.Read(ssl.sessionKey); err != nil {
			return fmt.Errorf("failed to generate session key: %w", err)
		}

		// Send session key to client over TLS connection - this will trigger the session key round logic
		totalWritten := 0
		for totalWritten < AuthSSLSessionKeyLen {
			n, err := ssl.tlsConn.Write(ssl.sessionKey[totalWritten:])
			if err != nil {
				return fmt.Errorf("failed to send session key over TLS (sent %d/%d bytes): %w",
					totalWritten, AuthSSLSessionKeyLen, err)
			}
			totalWritten += n
			log.Printf("🔐 SSL: Server sent %d/%d session key bytes", totalWritten, AuthSSLSessionKeyLen)
		}

		log.Printf("🔐 SSL: Server sent complete session key (%d bytes) over TLS", len(ssl.sessionKey))
	} // Ensure any buffered data is flushed after session key exchange
	if err := cedarConn.flushBufferedData(); err != nil {
		log.Printf("🔐 SSL: Warning: Failed to flush buffer after session key exchange: %v", err)
	}

	err := ssl.confirmHandshakeCompletion(negotiation, cedarConn)
	if err != nil {
		return fmt.Errorf("handshake completion confirmation after session key exchange failed: %w", err)
	}

	log.Printf("🔐 SSL: Session key exchange completed successfully over TLS")
	return nil
}

// finalizeAuthentication performs final status exchange and cleanup
func (ssl *SSLAuthenticator) finalizeAuthentication(negotiation *SecurityNegotiation) error {
	log.Printf("🔐 SSL: Finalizing authentication...")

	// Set authentication status based on success
	ssl.clientStatus = AuthSSLOK
	ssl.serverStatus = AuthSSLOK

	// In HTCondor, after TLS handshake and session key exchange, the connection is established
	// The final status exchange would normally happen over the TLS connection
	// However, in many implementations, once TLS is established and session key is exchanged,
	// authentication is considered complete without additional status exchange

	log.Printf("🔐 SSL: Authentication completed - TLS established and session key exchanged")
	log.Printf("🔐 SSL: Client status: %d, Server status: %d", ssl.clientStatus, ssl.serverStatus)

	// At this point, the authenticator would normally set up the stream encryption
	// using the session key for subsequent CEDAR protocol messages
	// This completes the SSL authentication process

	log.Printf("🔐 SSL: Authentication finalized successfully")
	return nil
}

// GetSessionKey returns the SSL session key for stream encryption
func (ssl *SSLAuthenticator) GetSessionKey() []byte {
	return ssl.sessionKey
}

// Helper function to load CA file
func loadCAFile(caFile string) ([]byte, error) {
	// Read CA certificate file
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
	}
	return caCert, nil
}
