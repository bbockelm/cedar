package ccb

import (
	"context"
	"fmt"
	"net"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// resolveContact resolves a (possibly nested) CCB contact to a byte pipe to the
// target, following one streaming hop per '#' (§4.4). It splits the contact on
// the LAST '#'; if the resulting broker is itself CCB-routed it recurses to reach
// that broker first, then issues a streaming CCB_REQUEST for the peeled id over
// the resulting pipe. The returned conn is spliced end-to-end through every CCB;
// the caller runs the end-to-end CEDAR handshake to the real target over it.
func resolveContact(ctx context.Context, contact string, opts DialOptions) (net.Conn, error) {
	broker, id, ok := addresses.SplitCCBContact(contact)
	if !ok {
		return nil, fmt.Errorf("ccb: malformed CCB contact %q", contact)
	}
	connectID, err := GenerateConnectID()
	if err != nil {
		return nil, err
	}

	if addresses.BrokerIsCCB(broker) {
		// Nested: reach the next-hop broker first (recursively), then extend the
		// pipe one more hop with a streaming request for `id`.
		pipe, err := resolveContact(ctx, broker, opts)
		if err != nil {
			return nil, err
		}
		conn, err := proxyRequestOverConn(ctx, pipe, id, connectID, opts)
		if err != nil {
			_ = pipe.Close()
			return nil, err
		}
		return conn, nil
	}

	// Base case: broker is a directly-dialable sinful (the entry CCB).
	return proxyRequestDial(ctx, broker, id, connectID, opts)
}

// proxyRequestDial dials the entry broker (TCP or shared-port), authenticates as
// CCB_REQUEST, version-gates streaming, and issues the streaming request for
// ccbid, returning the spliced pipe.
func proxyRequestDial(ctx context.Context, broker, ccbid, connectID string, opts DialOptions) (net.Conn, error) {
	brokerConn, brokerStream, neg, err := dialBrokerAuth(ctx, broker, opts.Security)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = brokerConn.Close()
		}
	}()
	if !brokerSupportsStreaming(neg) {
		return nil, fmt.Errorf("ccb: entry broker %s does not support streaming (required for nested routing)", broker)
	}
	pipe, err := proxyRequestOnStream(ctx, brokerConn, brokerStream, ccbid, connectID, opts.ProxyReturnAddr, requesterName(opts.TargetDesc))
	if err != nil {
		return nil, err
	}
	handedOff = true
	return pipe, nil
}

// proxyRequestOverConn authenticates a CCB_REQUEST over an existing pipe (from
// resolving the previous hop) and issues the streaming request for ccbid,
// extending the pipe one hop.
func proxyRequestOverConn(ctx context.Context, pipe net.Conn, ccbid, connectID string, opts DialOptions) (net.Conn, error) {
	s, _, err := authOnConn(ctx, pipe, opts.Security, CommandRequest)
	if err != nil {
		return nil, fmt.Errorf("ccb: authenticating over nested pipe: %w", err)
	}
	return proxyRequestOnStream(ctx, pipe, s, ccbid, connectID, opts.ProxyReturnAddr, requesterName(opts.TargetDesc))
}

// authOnConn wraps an existing connection in a CEDAR stream and runs the client
// handshake for command.
func authOnConn(ctx context.Context, conn net.Conn, sec *security.SecurityConfig, command int) (*stream.Stream, *security.SecurityNegotiation, error) {
	s := stream.NewStream(conn)
	cfg := *sec
	cfg.Command = command
	auth := security.NewAuthenticator(&cfg, s)
	neg, err := auth.ClientHandshake(ctx)
	if err != nil {
		return nil, nil, err
	}
	return s, neg, nil
}
