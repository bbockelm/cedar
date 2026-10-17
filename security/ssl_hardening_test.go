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
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// phasePair returns an SSLAuthenticator ready to run a phase and a peer
// SSLAuthenticator on the other end of the connection, used only to send and
// receive exchange messages by hand.
func phasePair(t *testing.T) (*SSLAuthenticator, *SSLAuthenticator) {
	t.Helper()
	mine, theirs, cleanup := handshakePair(t)
	t.Cleanup(cleanup)
	ssl := &SSLAuthenticator{authenticator: &Authenticator{stream: mine}, pipe: newTLSPipe()}
	t.Cleanup(ssl.close)
	peer := &SSLAuthenticator{authenticator: &Authenticator{stream: theirs}}
	return ssl, peer
}

// TestSSLPhaseRejectsDataWhileHolding: once this side's TLS operation is done,
// a peer message carrying TLS bytes is refused at once -- this side answers
// QUITTING and fails -- instead of the bytes being queued, unread, for every
// remaining round.
func TestSSLPhaseRejectsDataWhileHolding(t *testing.T) {
	ssl, peer := phasePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The operation finishes at once, so this side is HOLDING from round 0.
	done := make(chan error, 1)
	go func() { done <- ssl.runPhase(ctx, "test", false, true, func() error { return nil }) }()

	junk := make([]byte, sslMaxMessageLen)
	sent := 0
	for {
		status, _, err := peer.receiveMessage(ctx)
		if err != nil {
			t.Fatalf("peer receive after %d junk messages: %v", sent, err)
		}
		if status == AuthSSLQuitting {
			break
		}
		if sent == 4 {
			t.Fatalf("still exchanging after %d junk messages; want QUITTING after the first", sent)
		}
		if err := peer.sendMessage(ctx, AuthSSLReceiving, junk); err != nil {
			t.Fatalf("peer send: %v", err)
		}
		sent++
	}
	if sent != 1 {
		t.Errorf("QUITTING came after %d junk messages, want 1", sent)
	}
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "after this side finished") {
		t.Fatalf("runPhase = %v, want a rejection of data sent while holding", err)
	}
	ssl.pipe.mu.Lock()
	buffered := len(ssl.pipe.in)
	ssl.pipe.mu.Unlock()
	if buffered != 0 {
		t.Errorf("%d junk bytes buffered for the engine, want 0", buffered)
	}
}

// TestSSLPhaseAcceptsDataWithPeerQuit: a QUITTING peer may carry TLS bytes (an
// alert) while this side is HOLDING; that is the peer's failure, not a
// protocol violation, and this side does not answer it.
func TestSSLPhaseAcceptsDataWithPeerQuit(t *testing.T) {
	ssl, peer := phasePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ssl.runPhase(ctx, "test", false, true, func() error { return nil }) }()
	if _, _, err := peer.receiveMessage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := peer.sendMessage(ctx, AuthSSLQuitting, []byte("alert")); err != nil {
		t.Fatal(err)
	}
	err := <-done
	if err == nil || !strings.Contains(err.Error(), errSSLPeerQuit.Error()) {
		t.Fatalf("runPhase = %v, want the peer's quit", err)
	}
}

// TestSSLRoundCapTellsPeer: a phase that reaches the round cap tells the peer
// it is quitting, so the peer returns promptly instead of waiting for a message
// until its own deadline. Both parities: the cap falls on this side's send
// round, or on its receive round (where it first reads the peer's message, so
// the stream stays aligned).
func TestSSLRoundCapTellsPeer(t *testing.T) {
	for _, sendFirst := range []bool{true, false} {
		name := "send-first"
		if !sendFirst {
			name = "receive-first"
		}
		t.Run(name, func(t *testing.T) {
			ssl, peer := phasePair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// The operation waits for input that never comes.
			op := func() error {
				var b [1]byte
				_, err := ssl.pipe.Read(b[:])
				return err
			}
			done := make(chan error, 1)
			go func() { done <- ssl.runPhase(ctx, "test", true, sendFirst, op) }()

			// The peer answers RECEIVING, with no data, every time it is its turn.
			peerDone := make(chan error, 1)
			go func() {
				for round := 0; ; round++ {
					if (round%2 == 0) == sendFirst {
						status, _, err := peer.receiveMessage(ctx)
						if err != nil {
							peerDone <- err
							return
						}
						if status == AuthSSLQuitting {
							peerDone <- nil
							return
						}
					} else if err := peer.sendMessage(ctx, AuthSSLReceiving, nil); err != nil {
						peerDone <- err
						return
					}
				}
			}()

			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatalf("peer: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("peer never received QUITTING after the round cap")
			}
			if err := <-done; err == nil || !strings.Contains(err.Error(), "too many rounds") {
				t.Fatalf("runPhase = %v, want the round cap", err)
			}
			// The stream is still aligned: no message of the peer's is left
			// unread, so the next one this side reads is the peer's next.
			if err := peer.sendMessage(ctx, 99, nil); err != nil {
				t.Fatal(err)
			}
			if status, _, err := ssl.receiveMessage(ctx); err != nil || status != 99 {
				t.Errorf("next message: status %d, %v; want the peer's next (99)", status, err)
			}
		})
	}
}

// TestClientCertificateWithheld: as in C++ setup_ssl_ctx, a client presents
// its certificate only for plain SSL as itself -- not in SCITOKENS mode and
// not with a delegated credential. A server always presents one.
func TestClientCertificateWithheld(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	if err := GenerateTestHostCert(cert, key, caCert, caKey, "localhost"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		client    bool
		sciTokens bool
		delegated bool
		want      int
	}{
		{"client ssl", true, false, false, 1},
		{"client scitokens", true, true, false, 0},
		{"client delegated", true, false, true, 0},
		{"server scitokens", false, true, false, 1},
		{"server delegated", false, false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssl := &SSLAuthenticator{
				authenticator: &Authenticator{config: &SecurityConfig{
					CertFile:            cert,
					KeyFile:             key,
					CAFile:              caCert,
					DelegatedCredential: tc.delegated,
				}},
				sciTokensMode: tc.sciTokens,
			}
			cfg, err := ssl.createTLSConfig("localhost", tc.client)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Certificates) != tc.want {
				t.Errorf("%d certificates, want %d", len(cfg.Certificates), tc.want)
			}
			if !cfg.SessionTicketsDisabled {
				t.Error("session tickets enabled")
			}
		})
	}
}

// TestCADirCached: an unchanged CA directory is not re-read; adding a file,
// rewriting one in place (which leaves the directory's mtime alone),
// repointing a symlink's target, and removing a file are each picked up.
func TestCADirCached(t *testing.T) {
	dir := t.TempDir()
	caA := newTrustTestCA(t, "CA A")
	caB := newTrustTestCA(t, "CA B")
	caC := newTrustTestCA(t, "CA C")
	leafA, _, _ := caA.issue(t, "a.example")
	leafB, _, _ := caB.issue(t, "b.example")
	leafC, _, _ := caC.issue(t, "c.example")

	writeFile(t, filepath.Join(dir, "a.pem"), caA.pem)
	outside := filepath.Join(t.TempDir(), "c.pem")
	writeFile(t, outside, caA.pem)
	if err := os.Symlink(outside, filepath.Join(dir, "link.0")); err != nil {
		t.Fatal(err)
	}

	check := func(wantLoads int64, want map[string]bool) {
		t.Helper()
		before := caDirLoads.Load()
		cfg := &SecurityConfig{CADir: dir, UseDefaultCAs: boolPtr(false)}
		pool, err := cfg.buildCAPool()
		if err != nil {
			t.Fatal(err)
		}
		if got := caDirLoads.Load() - before; got != wantLoads {
			t.Errorf("directory loaded %d times, want %d", got, wantLoads)
		}
		for name, leaf := range map[string]*x509.Certificate{"a": leafA, "b": leafB, "c": leafC} {
			if got := trusts(t, pool, leaf); got != want[name] {
				t.Errorf("trusts %s = %v, want %v", name, got, want[name])
			}
		}
	}
	// bump moves a file's mtime forward, so a rewrite registers even on a
	// filesystem with coarse timestamps.
	bump := func(path string) {
		t.Helper()
		later := time.Now().Add(time.Hour)
		if err := os.Chtimes(path, later, later); err != nil {
			t.Fatal(err)
		}
	}

	check(1, map[string]bool{"a": true})
	check(0, map[string]bool{"a": true})

	// A new file: the listing changes.
	writeFile(t, filepath.Join(dir, "b.pem"), caB.pem)
	check(1, map[string]bool{"a": true, "b": true})
	check(0, map[string]bool{"a": true, "b": true})

	// Rewritten in place, through the symlink: the listing is the same.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, outside, caC.pem)
	bump(outside)
	if after, err := os.Stat(dir); err != nil || !after.ModTime().Equal(dirInfo.ModTime()) {
		t.Fatalf("directory mtime changed (%v); the in-place case is not being tested", err)
	}
	check(1, map[string]bool{"a": true, "b": true, "c": true})

	// Rewritten in place, a regular file.
	writeFile(t, filepath.Join(dir, "a.pem"), caC.pem)
	bump(filepath.Join(dir, "a.pem"))
	check(1, map[string]bool{"b": true, "c": true})

	if err := os.Remove(filepath.Join(dir, "b.pem")); err != nil {
		t.Fatal(err)
	}
	check(1, map[string]bool{"c": true})
	check(0, map[string]bool{"c": true})
}

// untrustedClientCertSetup returns a server config and a client config whose
// certificate comes from a CA the server does not trust, while the client
// trusts the server. The server trusts only the system store: crypto/tls
// clients offer a certificate only when its issuer is among the CAs the server
// names, and a server with an explicit pool names them all, while one using the
// system store (or OpenSSL with a CA directory) names none.
func untrustedClientCertSetup(t *testing.T) (serverCfg, clientCfg *SecurityConfig) {
	t.Helper()
	dir := t.TempDir()
	serverCA := newTrustTestCA(t, "server CA")
	otherCA := newTrustTestCA(t, "other CA")
	_, serverCert, serverKey := serverCA.issue(t, "localhost")
	_, clientCert, clientKey := otherCA.issue(t, "client.example")
	serverCfg = &SecurityConfig{
		CertFile: writeFile(t, filepath.Join(dir, "server.crt"), serverCert),
		KeyFile:  writeFile(t, filepath.Join(dir, "server.key"), serverKey),
	}
	clientCfg = &SecurityConfig{
		CertFile:      writeFile(t, filepath.Join(dir, "client.crt"), clientCert),
		KeyFile:       writeFile(t, filepath.Join(dir, "client.key"), clientKey),
		CAFile:        writeFile(t, filepath.Join(dir, "server-ca.pem"), serverCA.pem),
		UseDefaultCAs: boolPtr(false),
		ServerName:    "localhost",
	}
	return serverCfg, clientCfg
}

// serverSeesClientCert runs the server side of the SSL exchange against client
// and returns how many certificates the client presented and the server's
// error.
func serverSeesClientCert(t *testing.T, serverCfg, clientCfg *SecurityConfig,
	client func(ctx context.Context, a *Authenticator) error) (int, error) {
	t.Helper()
	cs, ss, cleanup := handshakePair(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := NewSSLAuthenticator(&Authenticator{config: serverCfg, stream: ss})
	defer server.close()
	sErr := make(chan error, 1)
	go func() {
		err := server.PerformSSLHandshake(ctx, &SecurityNegotiation{IsClient: false})
		// The SSL exchange is all this test is about; end the connection.
		cleanup()
		sErr <- err
	}()
	_ = client(ctx, &Authenticator{config: clientCfg, stream: cs})
	err := <-sErr
	if err != nil {
		return 0, err
	}
	return len(server.tlsConn.ConnectionState().PeerCertificates), nil
}

func sslClient(ctx context.Context, a *Authenticator) error {
	c := NewSSLAuthenticator(a)
	defer c.close()
	return c.PerformSSLHandshake(ctx, &SecurityNegotiation{IsClient: true})
}

// TestDelegatedClientCertNotPresented: a client acting for somebody else does
// not present its certificate, and authenticates anonymously; were it
// presented, the server would reject the handshake.
func TestDelegatedClientCertNotPresented(t *testing.T) {
	serverCfg, clientCfg := untrustedClientCertSetup(t)
	if _, err := serverSeesClientCert(t, serverCfg, clientCfg, sslClient); err == nil {
		t.Fatal("not delegated: server accepted a client certificate from an untrusted CA; the test cannot detect a presented certificate")
	}
	clientCfg.DelegatedCredential = true
	n, err := serverSeesClientCert(t, serverCfg, clientCfg, sslClient)
	if err != nil {
		t.Fatalf("delegated: server failed: %v; want success without a client certificate", err)
	}
	if n != 0 {
		t.Errorf("delegated: server saw %d client certificates, want 0", n)
	}
}

// TestSciTokensClientCertNotPresented: a SCITOKENS client does not present its
// certificate during the SSL exchange that carries its token.
func TestSciTokensClientCertNotPresented(t *testing.T) {
	serverCfg, clientCfg := untrustedClientCertSetup(t)
	// Only its shape matters: the server here stops after the SSL exchange.
	clientCfg.Token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2ln"
	n, err := serverSeesClientCert(t, serverCfg, clientCfg, func(ctx context.Context, a *Authenticator) error {
		return a.performSciTokenAuthentication(ctx, &SecurityNegotiation{IsClient: true, ClientConfig: clientCfg})
	})
	if err != nil {
		t.Fatalf("server failed: %v; want success without a client certificate", err)
	}
	if n != 0 {
		t.Errorf("server saw %d client certificates, want 0", n)
	}
}
