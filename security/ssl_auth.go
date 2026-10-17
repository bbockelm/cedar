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
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/cedar/addresses"
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
	pipe    *tlsPipe

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
func (ssl *SSLAuthenticator) PerformSSLHandshake(ctx context.Context, negotiation *SecurityNegotiation) error {
	slog.Info("🔐 SSL: Starting SSL authentication handshake...", "destination", "cedar")

	// Set up the server name and TLS config before the SSL status exchange. If
	// either fails we cannot do TLS -- but returning here would strand the peer,
	// which is already blocked waiting for the status exchange, and hang both
	// sides. Instead we still enter the status exchange with a failure status
	// (see signalSetupFailure), so both peers see a non-OK status, return an
	// error together, and fall back to the bitmask handshake to try another
	// method. The connection stays alive; only this method is abandoned.
	if err := ssl.setupServerName(negotiation.IsClient); err != nil {
		return ssl.signalSetupFailure(ctx, negotiation, fmt.Errorf("failed to setup server name: %w", err))
	}
	tlsConfig, err := ssl.createTLSConfig(ssl.serverName, negotiation.IsClient)
	if err != nil {
		return ssl.signalSetupFailure(ctx, negotiation, fmt.Errorf("failed to create TLS config: %w", err))
	}
	ssl.tlsConfig = tlsConfig

	// Exchange initial status messages
	if err := ssl.exchangeStatus(ctx, negotiation); err != nil {
		return fmt.Errorf("status exchange failed: %w", err)
	}

	// Perform TLS handshake through message protocol
	if err := ssl.performTLSHandshake(ctx, negotiation); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Verify peer certificate; on failure tell the peer in place of the
	// session key exchange.
	if err := ssl.verifyPeerCertificate(negotiation); err != nil {
		ssl.quitAfterHandshake(ctx, negotiation)
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Exchange session key for symmetric encryption
	if err := ssl.exchangeSessionKey(ctx, negotiation); err != nil {
		return fmt.Errorf("session key exchange failed: %w", err)
	}

	// Final status confirmation
	if err := ssl.finalizeAuthentication(negotiation); err != nil {
		return fmt.Errorf("authentication finalization failed: %w", err)
	}

	slog.Info("✅ SSL: SSL authentication completed successfully", "destination", "cedar")
	return nil
}

// signalSetupFailure sends a failed status (AuthSSLError) in the initial status
// exchange instead of an OK one, and returns cause. Used when this side cannot
// start TLS: sending the failure in-band lets both sides return an error from
// exchangeStatus and fall back to another auth method, rather than one side
// hanging while it waits for a status that a plain early return would never
// send.
func (ssl *SSLAuthenticator) signalSetupFailure(ctx context.Context, negotiation *SecurityNegotiation, cause error) error {
	if negotiation.IsClient {
		ssl.clientStatus = AuthSSLError
	} else {
		ssl.serverStatus = AuthSSLError
	}
	if err := ssl.exchangeStatus(ctx, negotiation); err != nil {
		slog.Info(fmt.Sprintf("🔐 SSL: signaled setup failure to peer via status exchange: %v", err), "destination", "cedar")
	}
	return cause
}

// createTLSConfig creates TLS configuration based on authenticator settings
func (ssl *SSLAuthenticator) createTLSConfig(serverName string, isClient bool) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // HTCondor requires TLS 1.2+
		MaxVersion: tls.VersionTLS12, // Support modern TLS
		// For testing purposes, skip certificate verification
		// In production, this should be properly configured with ServerName
		// InsecureSkipVerify: true,
		ServerName: serverName,
	}

	// Certificate, key and trust anchors follow C++ Condor_Auth_SSL::setup_ssl_ctx;
	// see loadCertKeyPair and buildCAPool for the candidate-list rules.
	if ssl.authenticator.config.CertFile != "" && ssl.authenticator.config.KeyFile != "" {
		cert, certPath, err := ssl.authenticator.config.loadCertKeyPair()
		if err != nil {
			return nil, err
		}
		switch {
		case cert != nil:
			config.Certificates = []tls.Certificate{*cert}
			slog.Info(fmt.Sprintf("🔐 SSL: Loaded certificate from %s", certPath), "destination", "cedar")
		case isClient:
			// C++ proceeds without a client certificate when none of the
			// candidates is readable: the client authenticates anonymously.
			slog.Info(fmt.Sprintf("🔐 SSL: no readable client certificate/key among cert=%q key=%q; continuing without one",
				ssl.authenticator.config.CertFile, ssl.authenticator.config.KeyFile), "destination", "cedar")
		default:
			// A server without a certificate cannot complete the handshake;
			// failing here signals it to the peer through the status exchange.
			return nil, fmt.Errorf("no readable certificate/key pair among cert=%q key=%q",
				ssl.authenticator.config.CertFile, ssl.authenticator.config.KeyFile)
		}
	}

	pool, err := ssl.authenticator.config.buildCAPool()
	if err != nil {
		return nil, err
	}
	if pool != nil {
		config.RootCAs = pool
		config.ClientCAs = pool
	}
	if !isClient {
		// C++ sets SSL_VERIFY_PEER on the server too: it asks for a client
		// certificate and verifies one if presented, but does not require it.
		config.ClientAuth = tls.VerifyClientCertIfGiven
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

// setupServerName determines the server name used for certificate verification and SNI.
// An explicit config.ServerName always wins. Otherwise, for a client, it is derived from
// the address the client dialed (see serverNameFromAddress) so the peer cert is verified
// against the real hostname instead of the "unknown" placeholder -- which no certificate
// carries, so verification always failed ("certificate is valid for <host>, not unknown").
func (ssl *SSLAuthenticator) setupServerName(isClient bool) error {
	switch {
	case ssl.authenticator.config.ServerName != "":
		ssl.serverName = ssl.authenticator.config.ServerName
	case isClient:
		ssl.serverName = serverNameFromAddress(ssl.authenticator.stream.GetPeerAddr())
	}
	if ssl.serverName == "" {
		ssl.serverName = "unknown" // server side, or a target with no usable hostname
	}
	ssl.verifyPeer = true
	return nil
}

// serverNameFromAddress extracts the TLS server name from an HTCondor address: the sinful
// "alias" parameter if present -- the DNS hostname HTCondor attaches precisely so a cert
// can be verified behind an IP -- otherwise the host portion. Returns "" if the address is
// empty or unparseable (leaving the caller's "unknown" fallback).
func serverNameFromAddress(addr string) string {
	if addr == "" {
		return ""
	}
	info, err := addresses.ParseSinful(addr)
	if err != nil {
		return ""
	}
	if info.Alias != "" {
		return info.Alias
	}
	return info.Host
}

// exchangeStatus exchanges initial status messages following HTCondor's protocol
func (ssl *SSLAuthenticator) exchangeStatus(ctx context.Context, negotiation *SecurityNegotiation) error {
	slog.Info("🔐 SSL: Exchanging initial status...", "destination", "cedar")

	if negotiation.IsClient {
		// Client: receive server status, then send client status
		statusMsg := message.NewMessageFromStream(ssl.authenticator.stream)
		serverStatus, err := statusMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive server status: %w", err)
		}
		ssl.serverStatus = serverStatus

		// Send client status
		clientMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := clientMsg.PutInt(ctx, ssl.clientStatus); err != nil {
			return fmt.Errorf("failed to send client status: %w", err)
		}
		if err := clientMsg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish client status message: %w", err)
		}
	} else {
		// Server: send server status, then receive client status
		serverMsg := message.NewMessageForStream(ssl.authenticator.stream)
		if err := serverMsg.PutInt(ctx, ssl.serverStatus); err != nil {
			return fmt.Errorf("failed to send server status: %w", err)
		}
		if err := serverMsg.FinishMessage(ctx); err != nil {
			return fmt.Errorf("failed to finish server status message: %w", err)
		}

		// Receive client status
		clientMsg := message.NewMessageFromStream(ssl.authenticator.stream)
		clientStatus, err := clientMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("failed to receive client status: %w", err)
		}
		ssl.clientStatus = clientStatus
	}

	// Check if both sides are ready
	if ssl.clientStatus != AuthSSLOK || ssl.serverStatus != AuthSSLOK {
		return fmt.Errorf("SSL initialization failed - client: %d, server: %d", ssl.clientStatus, ssl.serverStatus)
	}

	slog.Info("🔐 SSL: Status exchange completed successfully", "destination", "cedar")
	return nil
}

// The exchange after the initial status follows Condor_Auth_SSL
// (condor_auth_ssl.cpp). Each phase -- the TLS handshake, the session key
// transfer and, for SCITOKENS, the token transfer -- is a loop of rounds. In
// every round each side first advances its TLS operation, unless it already
// reports HOLDING (its operation is done), then either sends or receives one
// message: its status, a length, and the TLS bytes its engine wrote since its
// last send. The sides alternate, so each round is one side's send and the
// other's receive. A phase ends when both sides have reported HOLDING and fails
// when either reports QUITTING; either way both sides leave it in the same
// round, so the stream stays aligned for whatever follows.

// sslMaxMessageLen bounds the TLS bytes in one exchange message
// (AUTH_SSL_BUF_SIZE).
const sslMaxMessageLen = 1 << 20

// sslMaxRounds bounds the rounds in one phase, as C++ does for the session key
// and SciToken phases.
const sslMaxRounds = 256

// runPhase runs one phase of the exchange. op is this side's TLS operation;
// sendFirst says whether this side sends in the phase's first round.
func (ssl *SSLAuthenticator) runPhase(ctx context.Context, name string, isClient, sendFirst bool, op func() error) error {
	mine, peer := AuthSSLReceiving, AuthSSLReceiving
	var opErr error
	for round := 0; ; round++ {
		if round >= sslMaxRounds {
			return fmt.Errorf("SSL %s: too many rounds", name)
		}
		if mine != AuthSSLHolding {
			mine, opErr = ssl.pipe.advance(ctx, op)
		}
		if (round%2 == 0) == sendFirst {
			if err := ssl.sendMessage(ctx, mine, ssl.pipe.takeOut()); err != nil {
				return fmt.Errorf("SSL %s: %w", name, err)
			}
		} else {
			status, err := ssl.receiveMessage(ctx)
			if err != nil {
				return fmt.Errorf("SSL %s: %w", name, err)
			}
			peer = status
		}
		if peer == AuthSSLError {
			peer = AuthSSLQuitting
		}
		if isClient {
			ssl.clientStatus, ssl.serverStatus = mine, peer
		} else {
			ssl.serverStatus, ssl.clientStatus = mine, peer
		}
		slog.Debug(fmt.Sprintf("🔐 SSL: %s round %d (c: %d, s: %d)", name, round, ssl.clientStatus, ssl.serverStatus), "destination", "cedar")
		switch {
		case mine == AuthSSLQuitting:
			return fmt.Errorf("SSL %s failed: %w", name, opErr)
		case peer == AuthSSLQuitting:
			return fmt.Errorf("SSL %s failed: %w", name, errSSLPeerQuit)
		case mine == AuthSSLHolding && peer == AuthSSLHolding:
			return nil
		}
	}
}

// errSSLPeerQuit reports that the peer ended an SSL exchange phase with
// AUTH_SSL_QUITTING.
var errSSLPeerQuit = errors.New("peer quit the exchange")

// sendMessage sends one exchange message: status, then data with its length.
func (ssl *SSLAuthenticator) sendMessage(ctx context.Context, status int, data []byte) error {
	msg := message.NewMessageForStream(ssl.authenticator.stream)
	if err := msg.PutInt(ctx, status); err != nil {
		return fmt.Errorf("failed to send SSL status: %w", err)
	}
	if err := msg.PutInt(ctx, len(data)); err != nil {
		return fmt.Errorf("failed to send SSL data length: %w", err)
	}
	if err := msg.PutBytes(ctx, data); err != nil {
		return fmt.Errorf("failed to send SSL data: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish SSL message: %w", err)
	}
	return nil
}

// receiveMessage receives one exchange message, queues its TLS bytes for the
// engine, and returns the peer's status.
func (ssl *SSLAuthenticator) receiveMessage(ctx context.Context) (int, error) {
	msg := message.NewMessageFromStream(ssl.authenticator.stream)
	status, err := msg.GetInt(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to receive SSL status: %w", err)
	}
	length, err := msg.GetInt(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to receive SSL data length: %w", err)
	}
	if length < 0 || length > sslMaxMessageLen {
		return 0, fmt.Errorf("invalid SSL data length %d", length)
	}
	data, err := msg.GetBytes(ctx, length)
	if err != nil {
		return 0, fmt.Errorf("failed to receive SSL data: %w", err)
	}
	ssl.pipe.feed(data)
	return status, nil
}

// performTLSHandshake runs the TLS handshake phase. The client sends first.
func (ssl *SSLAuthenticator) performTLSHandshake(ctx context.Context, negotiation *SecurityNegotiation) error {
	ssl.pipe = newTLSPipe()
	if negotiation.IsClient {
		ssl.tlsConn = tls.Client(ssl.pipe, ssl.tlsConfig)
	} else {
		ssl.tlsConn = tls.Server(ssl.pipe, ssl.tlsConfig)
	}
	if err := ssl.runPhase(ctx, "handshake", negotiation.IsClient, negotiation.IsClient, ssl.tlsConn.Handshake); err != nil {
		return err
	}
	state := ssl.tlsConn.ConnectionState()
	slog.Debug(fmt.Sprintf("🔐 SSL: TLS handshake complete (version %x, cipher suite %x)", state.Version, state.CipherSuite), "destination", "cedar")
	return nil
}

// close stops the TLS engine if an operation is still waiting for input.
func (ssl *SSLAuthenticator) close() {
	if ssl.pipe != nil {
		ssl.pipe.close()
	}
}

// tlsPipe is the connection the TLS engine runs over, in place of the memory
// BIOs C++ gives OpenSSL. Bytes the engine writes collect in out until the
// exchange sends them; bytes the exchange receives collect in in until the
// engine reads them. An engine that reads while in is empty parks until more
// arrives, which is how the exchange learns the engine wants to read (C++'s
// SSL_ERROR_WANT_READ).
//
// The engine runs each operation in its own goroutine; the exchange drives it
// with advance and never runs two operations at once.
type tlsPipe struct {
	mu  sync.Mutex
	in  []byte
	out []byte

	events chan tlsEvent // engine -> exchange
	wake   chan struct{} // exchange -> parked engine: in has data
	quit   chan struct{} // closed by close
	once   sync.Once
	busy   bool // an operation is running (exchange side only)
}

// tlsEvent is what an engine operation reports: that it finished (done, with
// its error), or that it parked waiting for input.
type tlsEvent struct {
	done bool
	err  error
}

func newTLSPipe() *tlsPipe {
	return &tlsPipe{
		events: make(chan tlsEvent, 1),
		wake:   make(chan struct{}, 1),
		quit:   make(chan struct{}),
	}
}

// advance starts op, or resumes the running operation if input has arrived for
// it, and waits until the operation finishes or parks for more input. It
// returns HOLDING when the operation finished, RECEIVING when it waits for the
// peer, and QUITTING with the error when it failed.
func (p *tlsPipe) advance(ctx context.Context, op func() error) (int, error) {
	if !p.busy {
		p.busy = true
		go func() {
			err := op()
			select {
			case p.events <- tlsEvent{done: true, err: err}:
			case <-p.quit:
			}
		}()
	} else {
		p.mu.Lock()
		pending := len(p.in) > 0
		p.mu.Unlock()
		if !pending {
			return AuthSSLReceiving, nil
		}
		p.wake <- struct{}{}
	}
	select {
	case ev := <-p.events:
		if !ev.done {
			return AuthSSLReceiving, nil
		}
		p.busy = false
		if ev.err != nil {
			return AuthSSLQuitting, ev.err
		}
		return AuthSSLHolding, nil
	case <-ctx.Done():
		p.close()
		return AuthSSLQuitting, ctx.Err()
	}
}

// feed queues bytes received from the peer for the engine.
func (p *tlsPipe) feed(data []byte) {
	if len(data) == 0 {
		return
	}
	p.mu.Lock()
	p.in = append(p.in, data...)
	p.mu.Unlock()
}

// takeOut returns the bytes the engine has written since the last call, up to
// sslMaxMessageLen.
func (p *tlsPipe) takeOut() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := min(len(p.out), sslMaxMessageLen)
	data := p.out[:n:n]
	p.out = p.out[n:]
	return data
}

// close makes a parked or future engine read fail, ending its operation.
func (p *tlsPipe) close() {
	p.once.Do(func() { close(p.quit) })
}

func (p *tlsPipe) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		if len(p.in) > 0 {
			n := copy(b, p.in)
			p.in = p.in[n:]
			p.mu.Unlock()
			return n, nil
		}
		p.mu.Unlock()
		select {
		case p.events <- tlsEvent{}:
		case <-p.quit:
			return 0, net.ErrClosed
		}
		select {
		case <-p.wake:
		case <-p.quit:
			return 0, net.ErrClosed
		}
	}
}

func (p *tlsPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.out = append(p.out, b...)
	p.mu.Unlock()
	return len(b), nil
}

func (p *tlsPipe) Close() error {
	p.close()
	return nil
}

func (p *tlsPipe) LocalAddr() net.Addr  { return tlsPipeAddr{} }
func (p *tlsPipe) RemoteAddr() net.Addr { return tlsPipeAddr{} }

func (p *tlsPipe) SetDeadline(time.Time) error      { return nil }
func (p *tlsPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *tlsPipe) SetWriteDeadline(time.Time) error { return nil }

type tlsPipeAddr struct{}

func (tlsPipeAddr) Network() string { return "cedar-ssl" }
func (tlsPipeAddr) String() string  { return "cedar-ssl" }

// verifyPeerCertificate verifies the peer's certificate following HTCondor's verification logic
func (ssl *SSLAuthenticator) verifyPeerCertificate(negotiation *SecurityNegotiation) error {
	slog.Info("🔐 SSL: Verifying peer certificate...", "destination", "cedar")

	state := ssl.tlsConn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		if negotiation.IsClient {
			return fmt.Errorf("server provided no certificate")
		} else {
			// Server can allow anonymous clients if configured
			slog.Info("🔐 SSL: Client provided no certificate (anonymous mode)", "destination", "cedar")
			return nil
		}
	}

	peerCert := state.PeerCertificates[0]

	if negotiation.IsClient {
		// Client verifying server certificate
		slog.Info("🔐 SSL: Verifying server certificate", "destination", "cedar")
		slog.Info(fmt.Sprintf("🔐 SSL: Server cert subject: %s", peerCert.Subject.String()), "destination", "cedar")
		slog.Info(fmt.Sprintf("🔐 SSL: Server cert issuer: %s", peerCert.Issuer.String()), "destination", "cedar")

		// Verify hostname (simplified - real implementation would check SAN and CN)
		if ssl.verifyPeer && ssl.serverName != "unknown" {
			if err := ssl.verifyHostname(peerCert, ssl.serverName); err != nil {
				return fmt.Errorf("hostname verification failed: %w", err)
			}
		}
	} else {
		// Server verifying client certificate
		slog.Info("🔐 SSL: Verifying client certificate", "destination", "cedar")
		slog.Info(fmt.Sprintf("🔐 SSL: Client cert subject: %s", peerCert.Subject.String()), "destination", "cedar")
		slog.Info(fmt.Sprintf("🔐 SSL: Client cert issuer: %s", peerCert.Issuer.String()), "destination", "cedar")
	}

	// Additional verification could include:
	// - Certificate chain validation
	// - CRL checking
	// - Custom policy verification
	// - Identity mapping for authorization

	slog.Info("✅ SSL: Peer certificate verification completed", "destination", "cedar")
	return nil
}

// verifyHostname performs hostname verification similar to HTCondor's implementation
func (ssl *SSLAuthenticator) verifyHostname(cert *x509.Certificate, hostname string) error {
	// Check Subject Alternative Names first
	for _, name := range cert.DNSNames {
		if ssl.hostnameMatch(name, hostname) {
			slog.Info(fmt.Sprintf("🔐 SSL: Hostname %s matches SAN: %s", hostname, name), "destination", "cedar")
			return nil
		}
	}

	// Fall back to Common Name
	if cert.Subject.CommonName != "" {
		if ssl.hostnameMatch(cert.Subject.CommonName, hostname) {
			slog.Info(fmt.Sprintf("🔐 SSL: Hostname %s matches CN: %s", hostname, cert.Subject.CommonName), "destination", "cedar")
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

// exchangeSessionKey runs the session key phase: the server writes a random key
// over TLS and the client reads it. The server sends first.
func (ssl *SSLAuthenticator) exchangeSessionKey(ctx context.Context, negotiation *SecurityNegotiation) error {
	ssl.sessionKey = make([]byte, AuthSSLSessionKeyLen)
	var op func() error
	if negotiation.IsClient {
		op = func() error {
			_, err := io.ReadFull(ssl.tlsConn, ssl.sessionKey)
			return err
		}
	} else {
		if _, err := rand.Read(ssl.sessionKey); err != nil {
			return fmt.Errorf("failed to generate session key: %w", err)
		}
		op = func() error {
			_, err := ssl.tlsConn.Write(ssl.sessionKey)
			return err
		}
	}
	return ssl.runPhase(ctx, "session key exchange", negotiation.IsClient, !negotiation.IsClient, op)
}

// quitAfterHandshake tells the peer this side is abandoning the exchange after
// the handshake, as C++ does when its post-connection check fails: the server
// sends QUITTING in place of the session key; the client reads the server's
// session key message and answers QUITTING unless the server already quit.
func (ssl *SSLAuthenticator) quitAfterHandshake(ctx context.Context, negotiation *SecurityNegotiation) {
	if !negotiation.IsClient {
		_ = ssl.sendMessage(ctx, AuthSSLQuitting, nil)
		return
	}
	status, err := ssl.receiveMessage(ctx)
	if err == nil && status != AuthSSLQuitting {
		_ = ssl.sendMessage(ctx, AuthSSLQuitting, nil)
	}
}

// exchangeSciToken runs the SciToken phase after the session key exchange
// (authenticate_server_scitoken): the client writes the token's length and the
// token over TLS; the server reads and verifies it. The client sends first. On
// the server it returns the token's subject.
func (ssl *SSLAuthenticator) exchangeSciToken(ctx context.Context, negotiation *SecurityNegotiation, tokenStr string) (string, error) {
	if negotiation.IsClient {
		token := make([]byte, 4+len(tokenStr))
		binary.BigEndian.PutUint32(token, uint32(len(tokenStr)))
		copy(token[4:], tokenStr)
		op := func() error {
			_, err := ssl.tlsConn.Write(token)
			return err
		}
		if err := ssl.runPhase(ctx, "SciToken exchange", true, true, op); err != nil {
			if errors.Is(err, errSSLPeerQuit) {
				return "", fmt.Errorf("server rejected SciToken: %w", err)
			}
			return "", err
		}
		return "", nil
	}

	var claims *SciTokenClaims
	op := func() error {
		var size [4]byte
		if _, err := io.ReadFull(ssl.tlsConn, size[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(size[:])
		if n == 0 || n > sslMaxMessageLen {
			return fmt.Errorf("invalid SciToken length %d", n)
		}
		token := make([]byte, n)
		if _, err := io.ReadFull(ssl.tlsConn, token); err != nil {
			return err
		}
		c, err := VerifySciToken(string(token))
		if err != nil {
			return fmt.Errorf("SciToken verification failed: %w", err)
		}
		claims = c
		return nil
	}
	if err := ssl.runPhase(ctx, "SciToken exchange", false, false, op); err != nil {
		return "", err
	}
	// The token's condor scopes bound the session (server_verify_scitoken,
	// condor_auth_ssl.cpp).
	negotiation.AuthorizationLimits = sciTokenAuthorizationLimits(claims.Scope)
	return claims.Subject, nil
}

// finalizeAuthentication performs final status exchange and cleanup
func (ssl *SSLAuthenticator) finalizeAuthentication(negotiation *SecurityNegotiation) error {
	slog.Info("🔐 SSL: Finalizing authentication...", "destination", "cedar")

	// Set authentication status based on success
	ssl.clientStatus = AuthSSLOK
	ssl.serverStatus = AuthSSLOK

	// In HTCondor, after TLS handshake and session key exchange, the connection is established
	// The final status exchange would normally happen over the TLS connection
	// However, in many implementations, once TLS is established and session key is exchanged,
	// authentication is considered complete without additional status exchange

	slog.Info("🔐 SSL: Authentication completed - TLS established and session key exchanged", "destination", "cedar")
	slog.Info(fmt.Sprintf("🔐 SSL: Client status: %d, Server status: %d", ssl.clientStatus, ssl.serverStatus), "destination", "cedar")

	// At this point, the authenticator would normally set up the stream encryption
	// using the session key for subsequent CEDAR protocol messages
	// This completes the SSL authentication process

	slog.Info("🔐 SSL: Authentication finalized successfully", "destination", "cedar")
	return nil
}

// GetSessionKey returns the SSL session key for stream encryption
func (ssl *SSLAuthenticator) GetSessionKey() []byte {
	return ssl.sessionKey
}

// loadCAFile reads a CA bundle. CA material is public, so it is read under the
// process's own identity, as C++ does.
func loadCAFile(caFile string) ([]byte, error) {
	caCert, err := os.ReadFile(caFile) //nolint:gosec // operator-configured CA path
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
	}
	return caCert, nil
}
