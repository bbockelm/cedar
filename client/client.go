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
func ConnectToAddress(ctx context.Context, address string, timeout time.Duration) (*HTCondorClient, error) {
	config := &ClientConfig{
		Address: address,
		Timeout: timeout,
	}

	client := NewClient(config)
	err := client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
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
