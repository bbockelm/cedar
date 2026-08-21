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
	"os/user"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/stream"
)

// dialLoopbackPair returns a connected (client, server) TCP pair on loopback so
// both ends have real addresses (unlike net.Pipe), which is what engages FS-auth
// channel binding.
func dialLoopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return client, r.c
}

// TestFSAuthChannelBindingRoundTrip runs cedar's own FS-auth client and server
// against each other over a real loopback connection. Because both ends have
// real addresses, the server emits an address-qualified name ending in '_', the
// client appends its view of the server and reports it, and the server verifies
// the binding and stats the bound directory -- exercising both new code paths.
func TestFSAuthChannelBindingRoundTrip(t *testing.T) {
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		TrustDomain:    "test.domain",
		Command:        commands.DC_AUTHENTICATE,
	}
	serverConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		TrustDomain:    "test.domain",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ServerConfig: serverConfig, IsClient: false}
	clientNeg := &SecurityNegotiation{Command: commands.DC_AUTHENTICATE, ClientConfig: clientConfig, IsClient: true}

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- NewAuthenticator(serverConfig, stream.NewStream(serverConn)).
			performFSAuthenticationServer(ctx, serverNeg, false)
	}()

	if err := NewAuthenticator(clientConfig, stream.NewStream(clientConn)).
		performFSAuthenticationClient(ctx, clientNeg, false); err != nil {
		t.Fatalf("client FS auth failed: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server FS auth failed: %v", err)
	}

	cur, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	if serverNeg.User != cur.Username {
		t.Errorf("authenticated user = %q, want %q", serverNeg.User, cur.Username)
	}
}

// TestVerifyServerChannelBindingExt checks the server-side extension validation
// against a real connection whose local endpoint is known.
func TestVerifyServerChannelBindingExt(t *testing.T) {
	clientConn, serverConn := dialLoopbackPair(t)
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	a := NewAuthenticator(&SecurityConfig{}, stream.NewStream(serverConn))
	local := serverConn.LocalAddr().(*net.TCPAddr)
	matching := fmt.Sprintf("%s:%d", local.IP.String(), local.Port)

	if err := a.verifyServerChannelBindingExt(matching); err != nil {
		t.Errorf("matching endpoint %q rejected: %v", matching, err)
	}

	bad := []string{
		fmt.Sprintf("%s:%d", local.IP.String(), local.Port+1), // wrong port
		fmt.Sprintf("10.99.99.99:%d", local.Port),             // wrong ip
		"not-an-addr",
		"1.2.3.4:5/../etc", // path separator
		"",
	}
	for _, ext := range bad {
		if err := a.verifyServerChannelBindingExt(ext); err == nil {
			t.Errorf("extension %q accepted, want rejected", ext)
		}
	}
}
