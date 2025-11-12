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
	"strings"
	"syscall"

	"github.com/bbockelm/cedar/message"
)

const (
	// Maximum sizes for DoS protection
	MaxDirPathSize  = 4096 // 4KB max for directory paths
	MaxUsernameSize = 1024 // 1KB max for usernames
)

// performFSAuthentication performs filesystem-based authentication
// Implements the CAUTH_FILESYSTEM protocol from condor_auth_fs.cpp
func (a *Authenticator) performFSAuthentication(ctx context.Context, negotiation *SecurityNegotiation, remote bool) error {
	if negotiation.IsClient {
		return a.performFSAuthenticationClient(ctx, negotiation, remote)
	}
	return a.performFSAuthenticationServer(ctx, negotiation, remote)
}

// performFSAuthenticationClient handles client side of FS authentication
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

	// Try to create the directory if server provided a valid path
	if dirPath != "" {
		// Create directory with mode 0700 (owner read/write/execute only)
		// This is critical for security - other users must not be able to access
		err := os.Mkdir(dirPath, 0700)
		if err == nil {
			clientResult = 0 // Success
		} else {
			// Log the error but continue with failure result
			fmt.Printf("FS: Failed to create directory %s: %v\n", dirPath, err)
		}
	} else {
		// Server had an error generating the path
		fmt.Printf("FS: Server error - received empty directory path\n")
	}

	// Send result back to server
	responseMsg := message.NewMessageForStream(a.stream)
	if err := responseMsg.PutInt(ctx, clientResult); err != nil {
		return fmt.Errorf("failed to send client result: %w", err)
	}
	if err := responseMsg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Clean up directory if we created it
	defer func() {
		if clientResult == 0 && dirPath != "" {
			if err := os.Remove(dirPath); err != nil {
				// Log but don't fail - cleanup is best effort
				fmt.Printf("Warning: failed to remove directory %s: %v\n", dirPath, err)
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
