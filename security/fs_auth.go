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

// Package security provides FS and CLAIMTOBE authentication implementation
// for CEDAR streams.
//
// This file implements HTCondor's FS (filesystem) and CLAIMTOBE authentication
// methods as documented in condor_auth_fs.cpp and condor_auth_claim.cpp.
package security

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/bbockelm/cedar/message"
)

const (
	// Maximum sizes for DoS protection
	MaxDirPathSize  = 4096 // 4KB max for directory paths
	MaxUsernameSize = 1024 // 1KB max for usernames

	// fsAuthBaseDir is the only base directory under which the client
	// will accept a server-supplied FS-auth path. Mirrors the server's
	// generateLocalFSPath / generateRemoteFSPath, which both root
	// their os.MkdirTemp call under "/tmp". When SecurityConfig later
	// grows an FSLocalDir / FSRemoteDir field, the client should look
	// it up here too — but the server's literal "/tmp" must remain in
	// the allowlist regardless, since that's the on-the-wire default.
	fsAuthBaseDir = "/tmp"
)

// fsAuthLocalLeafRE matches the exact leaf shape an FS-auth server
// emits, covering both implementations a real client may meet:
//
//   - Cedar's generateLocalFSPath uses os.MkdirTemp(baseDir, "FS_*"),
//     which replaces "*" with decimal digits from runtime random
//     (uint32, ≤10 digits).
//   - HTCondor's C++ condor_auth_fs.cpp uses condor_mkstemp on
//     template "FS_XXXXXXXXX" (9 X's). The X-replacement pulls from
//     mkstemp's alphanumeric character set, and not all positions
//     are guaranteed to be filled — we've observed leaves like
//     "FS_XXXjlv9Zj" where the first three X's stayed literal.
//     "X" is a perfectly valid alphanumeric character, so we don't
//     need a special case for it; the bound of 16 just gives some
//     headroom over HTCondor's 9-char template.
//
// The regex anchors both ends and requires at least one alphanumeric
// after the "FS_" prefix. Anything else — embedded "..", slashes,
// dots, dashes, well-known leaves like ".X11-unix" — is rejected so
// a malicious server can't pick its own leaf name even after passing
// the base-dir check.
var fsAuthLocalLeafRE = regexp.MustCompile(`^FS_[A-Za-z0-9]{1,16}$`)

// fsAuthRemoteLeafRE matches generateRemoteFSPath's pattern:
// "FS_REMOTE_<hostname>_<pid>_<rand>". Hostname allows the
// RFC-1123-friendly character set plus underscore (some sites use
// underscores in /etc/hostname even though RFC 1123 frowns on it),
// PID is 1+ decimal digits, random suffix is up to 16 alphanumeric
// characters (covers Go's decimal-uint32 output and HTCondor's
// 9-char mkstemp output). The regex backtracks correctly when the
// hostname itself contains underscores: greedy hostname consumption
// gives way to the trailing "_<pid>_<rand>$" anchor.
var fsAuthRemoteLeafRE = regexp.MustCompile(`^FS_REMOTE_[A-Za-z0-9._\-]+_[0-9]+_[A-Za-z0-9]{1,16}$`)

// performFSAuthentication performs filesystem-based authentication
// Implements the CAUTH_FILESYSTEM protocol from condor_auth_fs.cpp
func (a *Authenticator) performFSAuthentication(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	if negotiation.IsClient {
		return a.performFSAuthenticationClient(ctx, negotiation, remote)
	}
	return a.performFSAuthenticationServer(ctx, negotiation, remote)
}

// performFSAuthenticationClient handles client side of FS authentication.
//
// Security note: the path the client mkdirs is supplied by the server.
// A malicious server could otherwise direct the client to create
// directories anywhere the client process has write permission —
// useful for "defeat existence-based locking" or "drop attacker-named
// directory under $HOME" classes of confused-deputy attack. We mitigate
// in two layers:
//
//  1. validateFSAuthPath rejects anything whose absolute parent isn't
//     fsAuthBaseDir or whose leaf doesn't match the expected
//     FS_ / FS_REMOTE_ prefix the server's MkdirTemp emits. That stops
//     path traversal, base-directory escape, and "leaf collides with
//     a known lockdir name" before any filesystem call.
//
//  2. The actual mkdir/remove go through *os.Root opened on
//     fsAuthBaseDir. os.Root.Mkdir refuses any name that escapes the
//     root via "..", absolute paths, or symlinks pointing outside —
//     so even if validateFSAuthPath had a bug, the kernel-enforced
//     root would block escape. Belt-and-suspenders.
func (a *Authenticator) performFSAuthenticationClient(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	// Receive directory name to create from server
	msg := message.NewMessageFromStream(a.stream)

	// Use WithMaxSize to limit directory path size and prevent DoS
	dirPath, err := msg.GetStringWithMaxSize(ctx, MaxDirPathSize)
	if err != nil {
		return fmt.Errorf("failed to receive directory path: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	// Initialize result as failure
	clientResult := -1
	// leafName is the validated, single-component name passed to
	// root.Mkdir / root.Remove. Set only after validateFSAuthPath
	// accepts the server-supplied path.
	var leafName string
	var root *os.Root

	// Try to create the directory if server provided a valid path
	if dirPath != "" {
		leaf, err := validateFSAuthPath(dirPath, remote)
		if err != nil {
			// Refuse to mkdir at the server's request. We still send
			// the failure code through the wire so the server gets a
			// clean negative response rather than a hang; the actual
			// validation error is logged so the operator can tell
			// "server paid an attempted attack" apart from "FS auth
			// just didn't work".
			fmt.Printf("FS: rejected server-supplied path %q: %v\n", dirPath, err)
		} else {
			// Open an os.Root scoped to the FS-auth base dir, then
			// mkdir the validated leaf inside it. os.Root enforces no
			// escape via .., absolute paths, or symlinks at the
			// kernel level — even if validateFSAuthPath had a logic
			// bug, this would block the actual directory creation.
			r, openErr := os.OpenRoot(fsAuthBaseDir)
			if openErr != nil {
				fmt.Printf("FS: open root %s: %v\n", fsAuthBaseDir, openErr)
			} else {
				// Mode 0700 — same as the original; other users must
				// not be able to access this dir between mkdir and
				// the server's stat-based ownership check.
				if mkErr := r.Mkdir(leaf, 0700); mkErr == nil {
					clientResult = 0
					leafName = leaf
					root = r
				} else {
					fmt.Printf("FS: Failed to create directory %s/%s: %v\n", fsAuthBaseDir, leaf, mkErr)
					_ = r.Close()
				}
			}
		}
	} else {
		// Server had an error generating the path
		fmt.Printf("FS: Server error - received empty directory path\n")
	}

	// Send result back to server
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutInt(ctx, clientResult); err != nil {
		if root != nil {
			_ = root.Close()
		}
		return fmt.Errorf("failed to send client result: %w", err)
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		if root != nil {
			_ = root.Close()
		}
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Clean up directory if we created it
	defer func() {
		if root == nil {
			return
		}
		defer func() { _ = root.Close() }()
		if clientResult == 0 && leafName != "" {
			if err := root.Remove(leafName); err != nil {
				// Log but don't fail - cleanup is best effort
				fmt.Printf("Warning: failed to remove directory %s/%s: %v\n", fsAuthBaseDir, leafName, err)
			}
		}
	}()

	// Receive server verification result
	verifyMsg := message.NewMessageFromStream(a.stream)
	serverResult, err := verifyMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive server result: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = verifyMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for verification message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	if serverResult != 0 {
		return fmt.Errorf("FS authentication failed: server verification failed")
	}

	return nil
}

// performFSAuthenticationServer handles server side of FS authentication
func (a *Authenticator) performFSAuthenticationServer(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	// Generate unique directory name
	var dirPath string
	var err error

	if remote {
		// FS_REMOTE: use FS_REMOTE_DIR from config
		dirPath, err = a.generateRemoteFSPath(negotiation.ServerConfig)
	} else {
		// FS: use FS_LOCAL_DIR from config or /tmp
		dirPath, err = a.generateLocalFSPath(negotiation.ServerConfig)
	}

	if err != nil {
		// Send empty string to indicate error
		dirPath = ""
	}

	// Send directory path to client
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutString(ctx, dirPath); err != nil {
		return fmt.Errorf("failed to send directory path: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// If we failed to generate a path, still need to continue the protocol
	if dirPath == "" {
		// Receive client result (will be failure)
		responseMsg := message.NewMessageFromStream(a.stream)
		_, _ = responseMsg.GetInt(ctx)
		// Try to read EOM marker (ignoring errors since this is error path)
		_, _ = responseMsg.GetChar(ctx)

		// Send failure result
		verifyMsg := message.NewMessageForStream(a.stream)
		_ = verifyMsg.PutInt(ctx, -1)
		_ = verifyMsg.FinishMessage(ctx)

		return fmt.Errorf("FS authentication failed: could not generate temp directory")
	}

	// Receive client result
	responseMsg := message.NewMessageFromStream(a.stream)
	clientResult, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive client result: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = responseMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for response message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	serverResult := -1 // Assume failure

	// Verify the directory was created correctly if client succeeded
	if clientResult == 0 && dirPath != "" {
		// For remote FS, sync NFS by creating a temp file
		if remote {
			a.syncNFS(negotiation.ServerConfig)
		}

		// Stat the directory to verify ownership and permissions
		fileInfo, err := os.Lstat(dirPath)
		if err == nil {
			// Verify it's a directory with correct permissions (0700)
			// and not a symlink
			stat, ok := fileInfo.Sys().(*syscall.Stat_t)
			if ok {
				mode := fileInfo.Mode()

				// Check all security requirements:
				// 1. Must be a directory
				// 2. Must not be a symlink
				// 3. Must have mode 0700 (owner only)
				// 4. Link count must be 1 or 2 (btrfs compatibility)
				if mode.IsDir() &&
					(mode&os.ModeSymlink) == 0 &&
					(mode.Perm() == 0700) &&
					(stat.Nlink == 1 || stat.Nlink == 2) {

					// Get username from UID
					u, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
					if err == nil {
						// Authentication successful
						serverResult = 0
						negotiation.User = u.Username

						// Set domain from config or use local domain
						if negotiation.ServerConfig.TrustDomain != "" {
							// Domain is already set in config
						} else {
							// Could set to hostname or leave empty
							negotiation.ServerConfig.TrustDomain = "localhost"
						}
					}
				}
			}
		}

		// Clean up the directory
		if err := os.Remove(dirPath); err != nil {
			// Log but don't fail - cleanup is best effort
			fmt.Printf("Warning: failed to remove directory %s: %v\n", dirPath, err)
		}
	}

	// Send server verification result
	verifyMsg := message.NewMessageForStream(a.stream)
	if err := verifyMsg.PutInt(ctx, serverResult); err != nil {
		return fmt.Errorf("failed to send server result: %w", err)
	}
	if err := verifyMsg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish verification message: %w", err)
	}

	if serverResult != 0 {
		return fmt.Errorf("FS authentication failed: directory verification failed")
	}

	return nil
}

// validateFSAuthPath checks that a server-supplied FS-auth directory
// path is something the client should be willing to mkdir. Returns
// the validated leaf name (the directory's basename) on success, or
// an error describing why the path was rejected.
//
// Rules, all of which must hold:
//
//  1. Non-empty.
//
//  2. Absolute path. (Relative paths could be interpreted against the
//     client's CWD, which is attacker-controlled territory once
//     `condor_history` or similar is run from a writable directory.)
//
//  3. filepath.Clean(path) == path — no embedded "..", no doubled
//     slashes, no trailing slash. This rules out the simplest
//     traversal attacks before they reach the os.Root layer.
//
//  4. The parent directory equals fsAuthBaseDir exactly. We don't
//     allow nested subdirs of the base; the server's MkdirTemp emits
//     a flat path, and accepting nesting would let a server pick a
//     leaf that collides with attacker-controlled state in some
//     subdirectory.
//
//  5. The leaf matches the exact name shape the server's
//     os.MkdirTemp call produces:
//
//     - FS: fsAuthLocalLeafRE → ^FS_[0-9]{1,10}$
//     - FS_REMOTE: fsAuthRemoteLeafRE
//     → ^FS_REMOTE_<host>_<pid>_<rand>$
//
//     The earlier version of this check just required the leaf to
//     *start with* "FS_" / "FS_REMOTE_". That left wiggle room: a
//     malicious server could pick "FS_../../etc" — we'd already
//     reject that on the canonical-form rule, but the prefix-only
//     check is loose enough that other wedge cases ("FS_anything-I-want")
//     would slip through if any of the earlier rules were
//     accidentally relaxed. Pinning to the actual MkdirTemp output
//     shape eliminates that wedge entirely.
//
// The returned leaf is safe to pass to (*os.Root).Mkdir on a Root
// rooted at fsAuthBaseDir.
func validateFSAuthPath(dirPath string, remote bool) (string, error) {
	if dirPath == "" {
		return "", fmt.Errorf("empty path")
	}
	if !filepath.IsAbs(dirPath) {
		return "", fmt.Errorf("not an absolute path: %q", dirPath)
	}
	if filepath.Clean(dirPath) != dirPath {
		return "", fmt.Errorf("path %q is not in canonical form (Clean)", dirPath)
	}
	parent := filepath.Dir(dirPath)
	if parent != fsAuthBaseDir {
		return "", fmt.Errorf("parent %q is not the expected base directory %q", parent, fsAuthBaseDir)
	}
	leaf := filepath.Base(dirPath)
	leafRE := fsAuthLocalLeafRE
	if remote {
		leafRE = fsAuthRemoteLeafRE
	}
	if !leafRE.MatchString(leaf) {
		return "", fmt.Errorf("leaf %q does not match expected pattern %s", leaf, leafRE)
	}
	// Belt-and-suspenders: leaf shouldn't contain a slash or "..".
	// filepath.Base + filepath.Clean and the regex anchors above
	// should already guarantee this; the explicit check costs nothing
	// and pins the invariant against future refactors that loosen
	// the regex.
	if strings.ContainsAny(leaf, "/\x00") || leaf == "." || leaf == ".." {
		return "", fmt.Errorf("leaf %q contains an unsafe component", leaf)
	}
	return leaf, nil
}

// generateLocalFSPath generates a unique temporary directory path for local FS auth
func (a *Authenticator) generateLocalFSPath(config *SecurityConfig) (string, error) {
	// Use /tmp as default directory
	baseDir := "/tmp"

	// Could support FS_LOCAL_DIR config here if needed
	// if config.FSLocalDir != "" {
	//     baseDir = config.FSLocalDir
	// }

	// Create unique temp directory
	// os.MkdirTemp creates the directory, but we need to delete it and let client create it
	tempDir, err := os.MkdirTemp(baseDir, "FS_*")
	if err != nil {
		return "", fmt.Errorf("failed to generate temp directory path: %w", err)
	}

	// Remove the directory - client needs to create it
	if err := os.Remove(tempDir); err != nil {
		return "", fmt.Errorf("failed to remove temp directory: %w", err)
	}

	return tempDir, nil
}

// generateRemoteFSPath generates a unique temporary directory path for remote FS auth
func (a *Authenticator) generateRemoteFSPath(config *SecurityConfig) (string, error) {
	// Use /tmp as default directory
	baseDir := "/tmp"

	// Could support FS_REMOTE_DIR config here if needed
	// if config.FSRemoteDir != "" {
	//     baseDir = config.FSRemoteDir
	// }

	// Get hostname for uniqueness
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Use PID for uniqueness
	pid := os.Getpid()

	// Generate pattern like HTCondor: FS_REMOTE_hostname_pid_XXXXXX
	pattern := fmt.Sprintf("FS_REMOTE_%s_%d_*", hostname, pid)

	// Create unique temp directory
	tempDir, err := os.MkdirTemp(baseDir, pattern)
	if err != nil {
		return "", fmt.Errorf("failed to generate temp directory path: %w", err)
	}

	// Remove the directory - client needs to create it
	if err := os.Remove(tempDir); err != nil {
		return "", fmt.Errorf("failed to remove temp directory: %w", err)
	}

	return tempDir, nil
}

// syncNFS attempts to sync NFS by creating and deleting a temp file
// This forces NFS client to sync with server before checking for client's directory
func (a *Authenticator) syncNFS(config *SecurityConfig) {
	baseDir := "/tmp"
	hostname, _ := os.Hostname()
	pid := os.Getpid()

	pattern := fmt.Sprintf("FS_REMOTE_%s_%d_sync_*", hostname, pid)

	// Create temp file to force NFS sync
	tempFile, err := os.CreateTemp(baseDir, pattern)
	if err == nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}
}

// performClaimToBeAuthentication performs CLAIMTOBE authentication
// Implements the CAUTH_CLAIMTOBE protocol from condor_auth_claim.cpp
func (a *Authenticator) performClaimToBeAuthentication(ctx context.Context, negotiation *SecurityNegotiation) error {
	if negotiation.IsClient {
		return a.performClaimToBeAuthenticationClient(ctx, negotiation)
	}
	return a.performClaimToBeAuthenticationServer(ctx, negotiation)
}

// performClaimToBeAuthenticationClient handles client side of CLAIMTOBE authentication
func (a *Authenticator) performClaimToBeAuthenticationClient(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Get username - prefer configured user, otherwise use current user
	username, err := a.getClaimUsername(negotiation.ClientConfig)
	if err != nil {
		// Send error indicator (0) followed by end of message
		msg := message.NewMessageForStream(a.stream)
		_ = msg.PutInt(ctx, 0)
		_ = msg.FinishMessage(ctx)
		return fmt.Errorf("failed to get username: %w", err)
	}

	// Check if we should include domain
	includeDomain := true // Default to true like HTCondor
	// Could support SEC_CLAIMTOBE_INCLUDE_DOMAIN config here
	// if config.ClaimToBeIncludeDomain != nil {
	//     includeDomain = *config.ClaimToBeIncludeDomain
	// }

	// Append domain if configured
	if includeDomain {
		domain := negotiation.ClientConfig.TrustDomain
		if domain == "" {
			// Could read from UID_DOMAIN config
			domain = "localhost"
		}
		username = username + "@" + domain
	}

	// Send success indicator (1) followed by username
	msg := message.NewMessageForStream(a.stream)
	if err := msg.PutInt(ctx, 1); err != nil {
		return fmt.Errorf("failed to send success indicator: %w", err)
	}
	if err := msg.PutString(ctx, username); err != nil {
		return fmt.Errorf("failed to send username: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Receive server acknowledgment
	responseMsg := message.NewMessageFromStream(a.stream)
	result, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive server acknowledgment: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = responseMsg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for acknowledgment completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	if result != 1 {
		return fmt.Errorf("CLAIMTOBE authentication failed: server rejected claim")
	}

	return nil
}

// performClaimToBeAuthenticationServer handles server side of CLAIMTOBE authentication
func (a *Authenticator) performClaimToBeAuthenticationServer(ctx context.Context, negotiation *SecurityNegotiation) error {
	// Receive client status indicator
	msg := message.NewMessageFromStream(a.stream)
	status, err := msg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive client status: %w", err)
	}

	if status != 1 {
		// Client had an error
		// Verify we've received the complete message with EOM marker
		_, err := msg.GetChar(ctx)
		if err != io.EOF {
			if err != nil {
				return fmt.Errorf("protocol error: error checking for message completion: %w", err)
			}
			return fmt.Errorf("protocol error: expected EOM but more data available")
		}
		return fmt.Errorf("CLAIMTOBE authentication failed: client error")
	}

	// Receive username with size limit to prevent DoS
	username, err := msg.GetStringWithMaxSize(ctx, MaxUsernameSize)
	if err != nil {
		return fmt.Errorf("failed to receive username: %w", err)
	}

	// Verify we've received the complete message with EOM marker
	_, err = msg.GetChar(ctx)
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("protocol error: error checking for message completion: %w", err)
		}
		return fmt.Errorf("protocol error: expected EOM but more data available")
	}

	// Check if domain is included
	includeDomain := true // Default to true
	// Could support SEC_CLAIMTOBE_INCLUDE_DOMAIN config here

	if includeDomain {
		// Parse user@domain format
		parts := strings.Split(username, "@")
		if len(parts) >= 2 {
			// Username has domain
			negotiation.User = parts[0]
			negotiation.ServerConfig.TrustDomain = parts[1]
		} else {
			// No domain in username, use configured domain
			negotiation.User = username
			if negotiation.ServerConfig.TrustDomain == "" {
				negotiation.ServerConfig.TrustDomain = "localhost"
			}
		}
	} else {
		negotiation.User = username
	}

	// Send success acknowledgment
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutInt(ctx, 1); err != nil {
		return fmt.Errorf("failed to send acknowledgment: %w", err)
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish acknowledgment: %w", err)
	}

	return nil
}

// getClaimUsername gets the username to claim for authentication
func (a *Authenticator) getClaimUsername(config *SecurityConfig) (string, error) {
	// Could support SEC_CLAIMTOBE_USER config to override username
	// if config.ClaimToBeUser != "" {
	//     return config.ClaimToBeUser, nil
	// }

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("failed to get current user: %w", err)
	}

	return currentUser.Username, nil
}
