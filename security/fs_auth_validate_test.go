// Copyright 2026 Morgridge Institute for Research
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
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// TestValidateFSAuthPath covers each rejection rule in isolation, plus
// the happy-path acceptance for both local and remote variants.
//
// Why this matters: performFSAuthenticationClient takes the directory
// path verbatim from the wire and used to call os.Mkdir on it without
// validation. A malicious server could direct the client to create
// arbitrary directories anywhere the client process had write
// permission — useful for "defeat existence-based locking" attacks
// (where some downstream tool aborts if a particular path exists) or
// for dropping attacker-named state in $HOME / /tmp.
//
// The test pins each rejection rule individually so a future refactor
// that "simplifies" validateFSAuthPath by collapsing checks can't
// silently weaken the protection.
func TestValidateFSAuthPath(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		remote    bool
		wantLeaf  string // empty when an error is expected
		wantErrIs string // substring of the error message; empty for success
	}{
		{
			name:     "happy path: local",
			path:     "/tmp/FS_12345",
			wantLeaf: "FS_12345",
		},
		{
			// os.MkdirTemp uses decimal digits for the random suffix
			// — the leaf-shape regex requires that. Earlier this fixture
			// used "abc" for the random component, which would have
			// passed the loose prefix-only check but slipped through
			// the tight regex now in place. Updated to match what the
			// server actually produces.
			name:     "happy path: remote",
			path:     "/tmp/FS_REMOTE_host_42_67890",
			remote:   true,
			wantLeaf: "FS_REMOTE_host_42_67890",
		},
		{
			// Hostname containing underscores (uncommon but allowed
			// by some sites). Greedy regex backtracks to the correct
			// hostname/pid/rand split.
			name:     "happy path: remote with underscore in hostname",
			path:     "/tmp/FS_REMOTE_my_host_42_67890",
			remote:   true,
			wantLeaf: "FS_REMOTE_my_host_42_67890",
		},
		{
			// Hostname containing dots (FQDN form).
			name:     "happy path: remote with FQDN hostname",
			path:     "/tmp/FS_REMOTE_host.example.com_42_67890",
			remote:   true,
			wantLeaf: "FS_REMOTE_host.example.com_42_67890",
		},
		{
			// HTCondor's condor_mkstemp template is FS_XXXXXXXXX
			// (9 X's). Random fill is alphanumeric; some Xs may stay
			// literal in the output. Real-world leaves look like
			// "FS_XXXjlv9Zj". This must pass — the integration test
			// against a real condor collector exercises this path.
			name:     "happy path: HTCondor C++ alphanumeric leaf",
			path:     "/tmp/FS_XXXjlv9Zj",
			wantLeaf: "FS_XXXjlv9Zj",
		},
		{
			// Random suffix containing characters outside [A-Za-z0-9]
			// — dot, dash, etc. — must be rejected. A malicious
			// server could otherwise pick "FS_..foo" or similar.
			name:      "non-alphanumeric in random suffix rejected",
			path:      "/tmp/FS_abc.def",
			wantErrIs: "does not match expected pattern",
		},
		{
			// Random suffix exceeds the 16-character cap. The cap
			// covers Go's uint32-decimal (≤10 digits) and HTCondor's
			// 9-char alphanumeric template with headroom; anything
			// longer almost certainly means a malicious or buggy
			// peer.
			name:      "oversized random suffix rejected",
			path:      "/tmp/FS_aaaaaaaaaaaaaaaaa",
			wantErrIs: "does not match expected pattern",
		},
		{
			// Remote leaf missing the trailing _<rand> component.
			name:      "remote missing random suffix rejected",
			path:      "/tmp/FS_REMOTE_host_42",
			remote:    true,
			wantErrIs: "does not match expected pattern",
		},
		{
			name:      "empty rejected",
			wantErrIs: "empty path",
		},
		{
			name:      "relative rejected",
			path:      "tmp/FS_12345",
			wantErrIs: "not an absolute path",
		},
		{
			name:      "non-canonical rejected (..)",
			path:      "/tmp/FS_12345/../FS_67890",
			wantErrIs: "not in canonical form",
		},
		{
			name:      "non-canonical rejected (//)",
			path:      "/tmp//FS_12345",
			wantErrIs: "not in canonical form",
		},
		{
			name:      "non-canonical rejected (trailing slash)",
			path:      "/tmp/FS_12345/",
			wantErrIs: "not in canonical form",
		},
		{
			name: "wrong base directory rejected",
			// Even canonical, this lives outside /tmp.
			path:      "/var/tmp/FS_12345",
			wantErrIs: "not the expected base directory",
		},
		{
			name:      "nested under base rejected",
			path:      "/tmp/sub/FS_12345",
			wantErrIs: "not the expected base directory",
		},
		{
			name: "wrong prefix on leaf rejected",
			// Lives in /tmp but doesn't follow the FS_ pattern the
			// server's MkdirTemp emits — could collide with
			// attacker-controlled state under /tmp like
			// /tmp/.X11-unix or /tmp/.font-unix.
			path:      "/tmp/.X11-unix",
			wantErrIs: "does not match expected pattern",
		},
		{
			// FS_<digits> matches the local pattern but not the
			// remote one — when the protocol is in remote mode, the
			// leaf must be FS_REMOTE_<host>_<pid>_<rand>.
			name:      "FS_ prefix rejected when remote variant expected",
			path:      "/tmp/FS_12345",
			remote:    true,
			wantErrIs: "does not match expected pattern",
		},
		{
			// "FS_" alone (no digits) should also fail — the regex
			// requires at least one digit, so a server can't pick a
			// 0-digit leaf to defeat parent-equality assumptions.
			name:      "FS_ with no digits rejected",
			path:      "/tmp/FS_",
			wantErrIs: "does not match expected pattern",
		},
		{
			name: "leaf-only attempts (no parent) rejected",
			// /FS_12345 has parent "/" not "/tmp".
			path:      "/FS_12345",
			wantErrIs: "not the expected base directory",
		},
		{
			name: "leaf containing slash rejected even if it canonicalizes back",
			// filepath.Clean("/tmp/FS_a/b") == "/tmp/FS_a/b", which has
			// parent "/tmp/FS_a", so the "wrong base" rule catches it.
			// This case is here to document that nesting is also
			// rejected by parent-equality rather than depending on
			// the leaf-shape check.
			path:      "/tmp/FS_a/b",
			wantErrIs: "not the expected base directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := validateFSAuthPath(tc.path, tc.remote)
			if tc.wantErrIs == "" {
				if err != nil {
					t.Fatalf("validateFSAuthPath(%q) errored: %v; expected success", tc.path, err)
				}
				if leaf != tc.wantLeaf {
					t.Errorf("leaf = %q, want %q", leaf, tc.wantLeaf)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateFSAuthPath(%q) succeeded with leaf %q; expected error %q",
					tc.path, leaf, tc.wantErrIs)
			}
			if !strings.Contains(err.Error(), tc.wantErrIs) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErrIs)
			}
		})
	}
}

// TestFSAuthClient_RejectsPathOutsideBase exercises the full client
// receive path with a malicious server that sends a path outside
// fsAuthBaseDir. We assert two properties:
//
//  1. The client returns a failure result on the wire (clientResult
//     == -1) rather than complying.
//  2. The attacker-named directory does NOT exist after the handshake
//     — i.e. the client neither created it nor relied on a
//     hand-rolled cleanup that could fail to undo a successful mkdir.
//
// We use a temp directory for the attack target so the test cleans up
// regardless of outcome (and so a buggy implementation that did mkdir
// the path doesn't pollute /tmp).
func TestFSAuthClient_RejectsPathOutsideBase(t *testing.T) {
	target := filepath.Join(t.TempDir(), "evil-FS_dir")

	clientResult := runClientWithMaliciousPath(t, target, false /* remote */)
	if clientResult != -1 {
		t.Errorf("expected client result == -1 (refusal), got %d", clientResult)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected target %q to not exist after rejected handshake; stat err = %v", target, err)
	}
}

// TestFSAuthClient_RejectsTraversal is the analogous test for the
// "/tmp/FS_X/../home/user/.config" style of attack where the path
// canonicalizes outside fsAuthBaseDir. validateFSAuthPath rejects on
// the canonical-form check before either parent-equality or the
// os.Root mkdir gets a chance to fire.
func TestFSAuthClient_RejectsTraversal(t *testing.T) {
	clientResult := runClientWithMaliciousPath(t,
		"/tmp/FS_12345/../FS_67890", false)
	if clientResult != -1 {
		t.Errorf("expected client result == -1 (refusal) for traversal path; got %d", clientResult)
	}
}

// TestFSAuthClient_RejectsWrongPrefix pins the leaf-prefix check
// against a server that sends an in-base path with a known-existing
// well-known leaf (e.g. /tmp/.X11-unix on Linux desktops). Without
// the prefix check, the client would attempt mkdir on it; with the
// check, we refuse.
func TestFSAuthClient_RejectsWrongPrefix(t *testing.T) {
	// Use a deliberately non-FS_ leaf. Doesn't matter if the path
	// pre-exists on this host — validation runs before any
	// filesystem call.
	clientResult := runClientWithMaliciousPath(t,
		"/tmp/.X11-unix", false)
	if clientResult != -1 {
		t.Errorf("expected client result == -1 (refusal) for wrong-prefix path; got %d", clientResult)
	}
}

// runClientWithMaliciousPath spins up the client side of the FS auth
// handshake against a fake server that just sends `dirPath` and reads
// back the result code. Returns the int the client wrote to the wire,
// or fails the test on protocol error / timeout. Used by the attack-
// rejection tests above so each focuses on a single property.
func runClientWithMaliciousPath(t *testing.T, dirPath string, remote bool) int {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	clientStream := stream.NewStream(clientConn)
	serverStream := stream.NewStream(serverConn)

	clientConfig := &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		Authentication: SecurityRequired,
		Command:        commands.DC_AUTHENTICATE,
	}
	clientAuth := NewAuthenticator(clientConfig, clientStream)

	clientNegotiation := &SecurityNegotiation{
		Command:      commands.DC_AUTHENTICATE,
		ClientConfig: clientConfig,
		ServerConfig: clientConfig,
		IsClient:     true,
	}

	// The fake server performs only the wire moves the client cares
	// about: send the path, read the int response, send a success
	// verdict to drive the client through to its return. We don't
	// care what auth identity it claims — the test is about whether
	// the client refused the dangerous path.
	gotResult := make(chan int, 1)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Send the malicious path.
		m := message.NewMessageForStream(serverStream)
		if err := m.PutString(ctx, dirPath); err != nil {
			t.Errorf("server PutString: %v", err)
			return
		}
		if err := m.FinishMessage(ctx); err != nil {
			t.Errorf("server FinishMessage: %v", err)
			return
		}

		// Read client's result code.
		respMsg := message.NewMessageFromStream(serverStream)
		result, err := respMsg.GetInt(ctx)
		if err != nil {
			t.Errorf("server GetInt: %v", err)
			return
		}
		gotResult <- result

		// Drive the client past its second read so its goroutine
		// returns normally. Sending 0 says "verification ok" — the
		// client returns nil if it created the dir, or returns a
		// "server verification failed" error if it didn't. Either
		// way, what we care about is the result code already in
		// gotResult.
		verifyMsg := message.NewMessageForStream(serverStream)
		_ = verifyMsg.PutInt(ctx, 0)
		_ = verifyMsg.FinishMessage(ctx)
	}()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()
	// We don't assert on the return value; the test focuses on the
	// wire-level result code via gotResult.
	_ = clientAuth.performFSAuthenticationClient(clientCtx, clientNegotiation, remote)

	select {
	case r := <-gotResult:
		<-srvDone
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client result code")
		return 0
	}
}
