package ccb

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/client/sharedport"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/cedar/version"
)

// StreamingMinVersion is the minimum broker $CondorVersion$ that is assumed to
// support streaming/proxy mode when no explicit capability flag is available.
// golang-ccb advertises a version at or above this; older C++ CCB servers fall
// below it, so a private requester fails fast instead of sending a request the
// old server would mishandle.
var StreamingMinVersion = version.CondorVersion{Major: 25, Minor: 12, Sub: 0}

// DialOptions configures a CCB reverse-connect dial.
type DialOptions struct {
	// Security is the credential/config used to authenticate to the CCB
	// broker. Its Command is overridden with CCB_REQUEST. Required.
	Security *security.SecurityConfig

	// MyAddress, if set, is the reverse-connect address advertised to the
	// target (HTCondor sinful, e.g. "<1.2.3.4:5678>"). If empty, the address
	// of the local reverse-connect listener is used. Ignored in proxy mode.
	MyAddress string

	// ProxyReturnAddr, if set, switches the dial to streaming/proxy mode: the
	// requester is itself private, so instead of listening it asks the broker
	// to proxy. The value is the requester's own CCB sinful (carrying a ccbid),
	// sent as MyAddress so the broker recognizes proxy mode.
	ProxyReturnAddr string

	// RequireStreaming makes proxy mode mandatory: if the broker does not
	// support streaming, the dial fails fast rather than falling back.
	RequireStreaming bool

	// TargetDesc is a human-readable description of the target (debugging).
	TargetDesc string

	// ListenAddr is the bind address for the reverse-connect listener in
	// standard mode (default ":0").
	ListenAddr string

	// Timeout bounds the whole dial (default 30s).
	Timeout time.Duration

	// Stagger is the Happy-Eyeballs delay between starting attempts to
	// successive brokers (default 250ms). A new broker attempt is also started
	// immediately whenever an outstanding attempt fails. Set to a negative
	// value to force fully-sequential dialing (one broker at a time).
	Stagger time.Duration
}

// defaultStagger is the Happy-Eyeballs inter-attempt delay (RFC 8305 suggests
// ~250ms as a reasonable "connection attempt delay").
const defaultStagger = 250 * time.Millisecond

// Dial reaches a target daemon through the CCB broker(s) named by contacts,
// using connection reversal, and returns a net.Conn connected to the target
// (the reverse-connect hello already consumed and validated). The caller then
// runs the normal CEDAR client handshake over the returned connection.
//
// When more than one broker contact is given, Dial uses a Happy-Eyeballs-style
// algorithm: it tries brokers in randomized order, starting an attempt to the
// next broker after Stagger has elapsed (or immediately if an outstanding
// attempt has already failed), and returns the first connection that succeeds.
// Remaining attempts are cancelled. This bounds the latency impact of a slow or
// dead CCB server in a multi-CCB pool. Each attempt uses its own connect id, so
// concurrent attempts to different brokers do not collide.
func Dial(ctx context.Context, contacts []addresses.CCBContact, opts DialOptions) (net.Conn, error) {
	if opts.Security == nil {
		return nil, fmt.Errorf("ccb: Dial requires a Security config for the broker")
	}
	if len(contacts) == 0 {
		return nil, fmt.Errorf("ccb: Dial requires at least one broker contact")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	stagger := opts.Stagger
	if stagger == 0 {
		stagger = defaultStagger
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Randomize broker order to spread load (mirrors CCBClient).
	order := make([]addresses.CCBContact, len(contacts))
	copy(order, contacts)
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

	// Each attempt runs under attemptCtx, which is cancelled as soon as we
	// return (so losing/outstanding attempts tear down their listen sockets and
	// broker connections).
	attemptCtx, attemptCancel := context.WithCancel(ctx)
	defer attemptCancel()

	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, len(order))
	next := 0
	inflight := 0
	var errs []error

	launch := func() {
		contact := order[next]
		next++
		inflight++
		go func() {
			conn, err := dialOne(attemptCtx, contact, opts)
			results <- result{conn: conn, err: err}
		}()
	}

	launch() // first broker
	timer := time.NewTimer(stagger)
	defer timer.Stop()
	// When stagger < 0, never auto-launch on the timer (sequential mode); a
	// stopped timer with a drained channel never fires.
	if stagger < 0 {
		if !timer.Stop() {
			<-timer.C
		}
	}

	for inflight > 0 {
		var staggerC <-chan time.Time
		if next < len(order) {
			staggerC = timer.C
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("ccb: dial timed out/cancelled with %d broker(s) tried: %w", next, ctx.Err())
		case res := <-results:
			inflight--
			if res.err == nil {
				return res.conn, nil // winner; deferred attemptCancel tears down the rest
			}
			errs = append(errs, res.err)
			// Happy Eyeballs: a failure means we can start the next broker now.
			if next < len(order) {
				launch()
				resetTimer(timer, stagger)
			}
		case <-staggerC:
			launch()
			resetTimer(timer, stagger)
		}
	}
	return nil, fmt.Errorf("ccb: all %d broker(s) failed: %w", len(order), errors.Join(errs...))
}

// resetTimer restarts t to fire after d, unless d is negative (sequential mode),
// in which case the timer is left stopped.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	if d >= 0 {
		t.Reset(d)
	}
}

// dialOne performs a single broker attempt with a fresh connect id.
func dialOne(ctx context.Context, contact addresses.CCBContact, opts DialOptions) (net.Conn, error) {
	connectID, err := GenerateConnectID()
	if err != nil {
		return nil, err
	}
	if opts.ProxyReturnAddr != "" {
		return dialProxy(ctx, contact, connectID, opts)
	}
	return dialStandard(ctx, contact, connectID, opts)
}

// dialStandard performs the public-requester CCB flow: listen for the reverse
// connection, ask the broker to have the target connect back, and accept it.
func dialStandard(ctx context.Context, contact addresses.CCBContact, connectID string, opts DialOptions) (net.Conn, error) {
	listenAddr := opts.ListenAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("ccb: failed to listen for reverse connection: %w", err)
	}
	defer func() { _ = ln.Close() }()

	myAddr := opts.MyAddress
	if myAddr == "" {
		myAddr = sinfulFromAddr(ln.Addr().String())
	}

	brokerConn, brokerStream, _, err := dialBrokerAuth(ctx, contact.BrokerAddr, opts.Security)
	if err != nil {
		return nil, err
	}
	// brokerConn is closed unless we hand it off; in standard mode we always
	// close it (the data path is the accepted reverse connection).
	defer func() { _ = brokerConn.Close() }()

	req := NewAd(map[string]any{
		AttrCCBID:     contact.CCBID,
		AttrClaimID:   connectID,
		AttrName:      requesterName(opts.TargetDesc),
		AttrMyAddress: myAddr,
	})
	if err := WriteControlAd(ctx, brokerStream, req); err != nil {
		return nil, err
	}

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := acceptReversed(ctx, ln, connectID)
		acceptCh <- acceptResult{conn: conn, err: err}
	}()

	replyCh := make(chan error, 1)
	go func() {
		replyCh <- readBrokerFailure(ctx, brokerStream)
	}()

	select {
	case r := <-acceptCh:
		if r.err != nil {
			return nil, r.err
		}
		return r.conn, nil
	case err := <-replyCh:
		// Broker sent a (failure) reply before the reverse connection arrived.
		if err == nil {
			err = fmt.Errorf("ccb: broker reported failure")
		}
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("ccb: timed out reaching %s via broker %s: %w", opts.TargetDesc, contact.BrokerAddr, ctx.Err())
	}
}

// dialProxy performs the private-requester streaming flow: the broker proxies
// the connection on the same socket the request was sent over.
func dialProxy(ctx context.Context, contact addresses.CCBContact, connectID string, opts DialOptions) (net.Conn, error) {
	brokerConn, brokerStream, neg, err := dialBrokerAuth(ctx, contact.BrokerAddr, opts.Security)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = brokerConn.Close()
		}
	}()

	// Pre-send version gate: do not send a proxy request to a broker that
	// cannot honor it.
	if !brokerSupportsStreaming(neg) {
		if opts.RequireStreaming {
			ver := ""
			if neg != nil && neg.ServerConfig != nil {
				ver = neg.ServerConfig.RemoteVersion
			}
			return nil, &StreamingUnsupportedError{Broker: contact.BrokerAddr, Version: ver}
		}
		return nil, fmt.Errorf("ccb: broker %s does not support streaming mode", contact.BrokerAddr)
	}

	req := NewAd(map[string]any{
		AttrCCBID:                contact.CCBID,
		AttrClaimID:              connectID,
		AttrName:                 requesterName(opts.TargetDesc),
		AttrMyAddress:            opts.ProxyReturnAddr,
		AttrCCBStreamingRequired: true,
	})
	if err := WriteControlAd(ctx, brokerStream, req); err != nil {
		return nil, err
	}

	// In proxy mode the broker replies on this socket, then splices it to the
	// target. Read the reply first.
	reply, err := ReadControlAd(ctx, brokerStream)
	if err != nil {
		return nil, err
	}
	if result, _ := AdBool(reply, AttrResult); !result {
		if unsup, _ := AdBool(reply, AttrCCBStreamingUnsupported); unsup {
			return nil, &StreamingUnsupportedError{Broker: contact.BrokerAddr, Version: AdString(reply, AttrName)}
		}
		return nil, fmt.Errorf("ccb: broker %s refused proxy request: %s", contact.BrokerAddr, AdString(reply, AttrErrorString))
	}

	// The broker now splices in the target's reverse-connect hello. Validate it.
	helloAd, err := readReverseConnect(ctx, brokerStream)
	if err != nil {
		return nil, fmt.Errorf("ccb: reading proxied reverse-connect hello: %w", err)
	}
	if got := AdString(helloAd, AttrClaimID); got != connectID {
		return nil, fmt.Errorf("ccb: proxied reverse-connect id mismatch")
	}

	handedOff = true
	return brokerConn, nil
}

// acceptReversed accepts connections on ln until one presents the matching
// reverse-connect hello, then returns it.
func acceptReversed(ctx context.Context, ln net.Listener, connectID string) (net.Conn, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		conn, err := ln.Accept()
		if err != nil {
			return nil, fmt.Errorf("ccb: accept reversed connection: %w", err)
		}
		s := stream.NewStream(conn)
		helloAd, err := readReverseConnect(ctx, s)
		if err != nil {
			_ = conn.Close()
			continue
		}
		if got := AdString(helloAd, AttrClaimID); got != connectID {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// readBrokerFailure waits for and reads a reply ClassAd from the broker; it is
// only consulted in the failure case (the success path is the reverse
// connection). Returns the failure error, or nil if the reply was a success.
func readBrokerFailure(ctx context.Context, s *stream.Stream) error {
	ad, err := ReadControlAd(ctx, s)
	if err != nil {
		return err
	}
	if result, _ := AdBool(ad, AttrResult); result {
		return nil
	}
	return fmt.Errorf("ccb: broker failure: %s", AdString(ad, AttrErrorString))
}

// dialBrokerAuth dials the broker and performs the CEDAR client handshake with
// Command=CCB_REQUEST, returning the conn, stream and negotiation. The broker
// address may be a direct sinful ("host:port") or a shared-port sinful
// ("host:port?sock=name"), in which case the connection is routed through the
// shared-port server.
func dialBrokerAuth(ctx context.Context, brokerAddr string, sec *security.SecurityConfig) (net.Conn, *stream.Stream, *security.SecurityNegotiation, error) {
	s, err := dialBroker(ctx, brokerAddr, "ccb-requester")
	if err != nil {
		return nil, nil, nil, err
	}

	// Clone the security config and pin the command to CCB_REQUEST.
	cfg := *sec
	cfg.Command = CommandRequest
	auth := security.NewAuthenticator(&cfg, s)
	neg, err := auth.ClientHandshake(ctx)
	if err != nil {
		_ = s.GetConnection().Close()
		return nil, nil, nil, fmt.Errorf("ccb: authenticating to broker %s: %w", brokerAddr, err)
	}
	return s.GetConnection(), s, neg, nil
}

// dialBroker connects to a CCB broker and returns a CEDAR stream. The broker
// address may be a direct sinful ("host:port") or a shared-port sinful
// ("host:port?sock=name"), in which case the connection is routed through the
// shared-port server. clientName identifies the caller to the shared-port
// server (debugging only). Used by both the requester and the listener so a CCB
// behind a shared port is reachable from either side.
func dialBroker(ctx context.Context, brokerAddr, clientName string) (*stream.Stream, error) {
	addrInfo := addresses.ParseHTCondorAddress(brokerAddr)
	var s *stream.Stream
	if addrInfo.IsSharedPort {
		spc := sharedport.NewSharedPortClient(clientName)
		st, err := spc.ConnectViaSharedPort(ctx, addrInfo.ServerAddr, addrInfo.SharedPortID, dialDeadline(ctx))
		if err != nil {
			return nil, fmt.Errorf("ccb: dialing shared-port broker %s: %w", brokerAddr, err)
		}
		s = st
	} else {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addrInfo.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("ccb: dialing broker %s: %w", brokerAddr, err)
		}
		s = stream.NewStream(conn)
	}
	s.SetPeerAddr(brokerAddr)
	return s, nil
}

// dialDeadline returns the time remaining until ctx's deadline, or a default
// when ctx has none, for APIs that take a duration rather than a context.
func dialDeadline(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

func brokerSupportsStreaming(neg *security.SecurityNegotiation) bool {
	if neg == nil || neg.ServerConfig == nil {
		return false
	}
	v, ok := version.Parse(neg.ServerConfig.RemoteVersion)
	if !ok {
		return false
	}
	return v.AtLeast(StreamingMinVersion)
}

// StreamingUnsupportedError indicates the broker cannot honor a required
// streaming/proxy request.
type StreamingUnsupportedError struct {
	Broker  string
	Version string
}

func (e *StreamingUnsupportedError) Error() string {
	return fmt.Sprintf("ccb: broker %s (version %q) does not support streaming mode required to reach a private target",
		e.Broker, e.Version)
}

// sinfulFromAddr turns a "host:port" into an HTCondor sinful "<host:port>".
func sinfulFromAddr(addr string) string {
	return "<" + addr + ">"
}

func requesterName(targetDesc string) string {
	if targetDesc == "" {
		return "golang-cedar ccb client"
	}
	return "golang-cedar ccb client -> " + targetDesc
}
