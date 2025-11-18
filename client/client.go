// Package client provides HTCondor API client implementations
// using the CEDAR protocol.
//
// This package will eventually contain clients for various HTCondor
// operations, starting with a condor_status equivalent.
package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/client/sharedport"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// HTCondorClient represents a client connection to an HTCondor daemon
type HTCondorClient struct {
	stream           *stream.Stream
	config           *ClientConfig
	sharedPortClient *sharedport.SharedPortClient
}

// ClientConfig holds configuration for HTCondor client connections
type ClientConfig struct {
	// Address is the HTCondor daemon address. Can be:
	// - "host:port" for direct TCP connection
	// - "host:port?sock=daemon_id" for shared port connection
	// - "<host:port?sock=daemon_id>" for shared port connection (HTCondor format)
	Address string

	// Deprecated: Use Address field instead
	Host string
	// Deprecated: Use Address field instead
	Port int

	// Timeout for connection establishment (default: 30 seconds)
	Timeout time.Duration

	// ClientName for shared port connections (for debugging)
	ClientName string

	Security *security.SecurityConfig
}

// NewClient creates a new HTCondor client
func NewClient(config *ClientConfig) *HTCondorClient {
	// Set default values
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.ClientName == "" {
		config.ClientName = "golang-cedar-client"
	}

	// Support legacy Host:Port format
	if config.Address == "" && config.Host != "" && config.Port != 0 {
		config.Address = fmt.Sprintf("%s:%d", config.Host, config.Port)
	}

	return &HTCondorClient{
		config:           config,
		sharedPortClient: sharedport.NewSharedPortClient(config.ClientName),
	}
}

// Connect establishes a connection to the HTCondor daemon
func (c *HTCondorClient) Connect(ctx context.Context) error {
	if c.config.Address == "" {
		return fmt.Errorf("no address specified in client configuration")
	}

	// Parse the address to determine if it's a shared port connection
	addrInfo := addresses.ParseHTCondorAddress(c.config.Address)

	var err error
	if addrInfo.IsSharedPort {
		// Use shared port connection
		c.stream, err = c.sharedPortClient.ConnectViaSharedPort(
			ctx,
			addrInfo.ServerAddr,
			addrInfo.SharedPortID,
			c.config.Timeout,
		)
	} else {
		// Use direct TCP connection with context-aware dialing
		dialer := &net.Dialer{Timeout: c.config.Timeout}
		conn, dialErr := dialer.DialContext(ctx, "tcp", addrInfo.ServerAddr)
		if dialErr != nil {
			return fmt.Errorf("failed to connect to %s: %w", addrInfo.ServerAddr, dialErr)
		}
		c.stream = stream.NewStream(conn)
	}

	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	// Set peer address on stream using the original address format (with brackets if applicable)
	if c.stream != nil {
		c.stream.SetPeerAddr(c.config.Address)
	}

	return nil
}

// ConnectToAddress is a convenience method that creates a client and connects to the specified address
func ConnectToAddress(ctx context.Context, address string) (*HTCondorClient, error) {
	config := &ClientConfig{
		Address: address,
	}

	client := NewClient(config)
	err := client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ConnectAndAuthenticate establishes a connection and performs authentication handshake
// with automatic retry on session resumption failures. This is the recommended method
// for establishing authenticated connections to HTCondor daemons.
//
// If session resumption fails (e.g., SID_NOT_FOUND), the function will:
// 1. Close the current connection
// 2. Establish a new connection
// 3. Retry the handshake (which will perform full authentication)
//
// This ensures that failed session resumption attempts don't leave the stream in an
// unusable state.
func ConnectAndAuthenticate(ctx context.Context, address string, securityConfig *security.SecurityConfig) (*HTCondorClient, error) {
	config := &ClientConfig{
		Address:  address,
		Security: securityConfig,
	}

	return ConnectAndAuthenticateWithConfig(ctx, config)
}

// ConnectAndAuthenticateWithConfig is like ConnectAndAuthenticate but accepts a full ClientConfig
func ConnectAndAuthenticateWithConfig(ctx context.Context, config *ClientConfig) (*HTCondorClient, error) {
	const maxRetries = 2 // Initial attempt + 1 retry on session resumption failure

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		client := NewClient(config)

		// Establish connection
		if err := client.Connect(ctx); err != nil {
			lastErr = fmt.Errorf("failed to connect to %s: %w", config.Address, err)
			continue
		}

		// Perform authentication handshake
		if config.Security != nil {
			auth := security.NewAuthenticator(config.Security, client.stream)
			_, err := auth.ClientHandshake(ctx)

			// Check if this is a session resumption error
			if security.IsSessionResumptionError(err) {
				// Close the connection and retry with a fresh connection
				_ = client.Close()
				lastErr = fmt.Errorf("session resumption failed, retrying with new connection: %w", err)
				continue
			}

			if err != nil {
				_ = client.Close()
				return nil, fmt.Errorf("authentication handshake failed: %w", err)
			}
		}

		// Success!
		return client, nil
	}

	return nil, fmt.Errorf("failed to connect and authenticate after %d attempts: %w", maxRetries, lastErr)
}

// IsConnected returns true if the client is connected to a daemon
func (c *HTCondorClient) IsConnected() bool {
	return c.stream != nil && c.stream.IsConnected()
}

// GetStream returns the underlying CEDAR stream for advanced operations
func (c *HTCondorClient) GetStream() *stream.Stream {
	return c.stream
}

// Close closes the client connection
func (c *HTCondorClient) Close() error {
	if c.stream != nil {
		return c.stream.Close()
	}
	return nil
}
