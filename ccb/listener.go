package ccb

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// ConnHandler is called with each inbound reverse connection a Listener
// accepts on behalf of the registered daemon. By the time it is called the
// reverse-connect hello has been sent; the connection is now an ordinary
// inbound CEDAR command socket on which the caller is the server (the remote
// requester will drive DC_AUTHENTICATE). The handler owns the conn and must
// close it.
type ConnHandler func(conn net.Conn)

// ListenerConfig configures a CCB Listener (a daemon registering itself with
// one or more brokers so private peers can reach it).
type ListenerConfig struct {
	// BrokerAddrs are the CCB broker addresses ("host:port", brackets
	// optional) to register with. A daemon in a pool with multiple CCB
	// servers registers with all of them, and the union of the assigned
	// contacts (see Contacts) forms the ccbid list in the daemon's sinful.
	BrokerAddrs []string

	// BrokerAddr is a convenience for the single-broker case. If set, it is
	// appended to BrokerAddrs.
	BrokerAddr string

	// Security authenticates registration to the broker. Its Command is
	// overridden with CCB_REGISTER. Required.
	Security *security.SecurityConfig

	// Handler receives each reverse-connected inbound connection. Required.
	Handler ConnHandler

	// Name identifies this daemon to the broker (debugging only).
	Name string

	// HeartbeatInterval is how often to send ALIVE (default 1200s, min 30s).
	HeartbeatInterval time.Duration

	// ReconnectInterval is how long to wait before re-registering after a
	// broker connection drops (default 60s).
	ReconnectInterval time.Duration

	// DialTimeout bounds reverse-connect dials to requesters (default 30s).
	DialTimeout time.Duration
}

// SplitBrokerList splits a CCB broker list as written in configuration (e.g.
// the value of CCB_ADDRESS), which is separated by commas and/or whitespace,
// into individual broker addresses.
func SplitBrokerList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Listener maintains a persistent registration with one or more CCB brokers and
// services reverse-connect requests from any of them. Each broker is handled by
// an independent registration (its own connection, heartbeat, and reconnect
// loop), so one broker going down does not affect the others.
type Listener struct {
	cfg  ListenerConfig
	regs []*brokerReg
}

// NewListener creates a Listener for all configured brokers.
func NewListener(cfg ListenerConfig) *Listener {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 1200 * time.Second
	}
	if cfg.HeartbeatInterval < 30*time.Second {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 60 * time.Second
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}

	l := &Listener{cfg: cfg}
	addrs := append([]string{}, cfg.BrokerAddrs...)
	if cfg.BrokerAddr != "" {
		addrs = append(addrs, cfg.BrokerAddr)
	}
	for _, addr := range addrs {
		l.regs = append(l.regs, &brokerReg{addr: addr, cfg: &l.cfg})
	}
	return l
}

// Run registers with every broker and services requests until ctx is
// cancelled, reconnecting (preserving each ccbid via its reconnect cookie) on
// failure. It returns after all broker loops have stopped.
func (l *Listener) Run(ctx context.Context) error {
	if len(l.regs) == 0 {
		return fmt.Errorf("ccb: listener has no broker addresses")
	}
	var wg sync.WaitGroup
	for _, r := range l.regs {
		wg.Add(1)
		go func(r *brokerReg) {
			defer wg.Done()
			r.run(ctx)
		}(r)
	}
	wg.Wait()
	return ctx.Err()
}

// Contacts returns the CCB contact strings ("addr#id") currently assigned by
// the brokers this listener is registered with, one per registered broker.
// Together they are the ccbid list to advertise in the daemon's sinful. Brokers
// that are not currently registered are omitted.
func (l *Listener) Contacts() []string {
	out := make([]string, 0, len(l.regs))
	for _, r := range l.regs {
		if c := r.getContact(); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ContactList returns Contacts joined by spaces, i.e. the value to use for the
// "ccbid" parameter of a sinful string.
func (l *Listener) ContactList() string {
	return strings.Join(l.Contacts(), " ")
}

// Contact returns a single assigned contact (the first registered broker's),
// for convenience in the common single-broker case. Empty until registered.
func (l *Listener) Contact() string {
	if cs := l.Contacts(); len(cs) > 0 {
		return cs[0]
	}
	return ""
}

// NumRegistered returns how many of the configured brokers are currently
// registered.
func (l *Listener) NumRegistered() int {
	return len(l.Contacts())
}

// BrokerSupportsStreaming reports whether all currently-registered brokers
// advertised streaming support. Returns false if no broker is registered.
func (l *Listener) BrokerSupportsStreaming() bool {
	any := false
	for _, r := range l.regs {
		r.mu.Lock()
		reg, streaming := r.registered, r.brokerStreaming
		r.mu.Unlock()
		if reg {
			any = true
			if !streaming {
				return false
			}
		}
	}
	return any
}

// brokerReg is the per-broker registration state and loop.
type brokerReg struct {
	addr string
	cfg  *ListenerConfig

	mu              sync.Mutex
	writeMu         sync.Mutex // serializes writes to the broker stream
	stream          *stream.Stream
	conn            net.Conn
	contact         string // "addr#id" assigned by this broker
	cookie          string // reconnect cookie
	brokerStreaming bool
	registered      bool
}

func (r *brokerReg) getContact() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.registered {
		return ""
	}
	return r.contact
}

// run registers with this broker and services it until ctx is cancelled,
// reconnecting on failure.
func (r *brokerReg) run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := r.register(ctx); err != nil {
			if !sleepCtx(ctx, r.cfg.ReconnectInterval) {
				return
			}
			continue
		}
		r.serve(ctx) // returns when the broker connection drops
		r.closeConn()
		if !sleepCtx(ctx, r.cfg.ReconnectInterval) {
			return
		}
	}
}

func (r *brokerReg) register(ctx context.Context) error {
	host := strings.Trim(r.addr, "<>")
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return fmt.Errorf("ccb: dialing broker %s: %w", r.addr, err)
	}
	s := stream.NewStream(conn)
	s.SetPeerAddr(r.addr)

	cfg := *r.cfg.Security
	cfg.Command = CommandRegister
	auth := security.NewAuthenticator(&cfg, s)
	if _, err := auth.ClientHandshake(ctx); err != nil {
		_ = conn.Close()
		return fmt.Errorf("ccb: authenticating to broker %s: %w", r.addr, err)
	}

	reg := map[string]any{
		AttrCommand: CommandRegister,
		AttrName:    r.cfg.Name,
	}
	r.mu.Lock()
	if r.contact != "" && r.cookie != "" {
		// Reconnect: try to preserve our ccbid.
		reg[AttrCCBID] = r.contact
		reg[AttrClaimID] = r.cookie
	}
	r.mu.Unlock()

	if err := WriteControlAd(ctx, s, NewAd(reg)); err != nil {
		_ = conn.Close()
		return err
	}
	reply, err := ReadControlAd(ctx, s)
	if err != nil {
		_ = conn.Close()
		return err
	}
	contact := AdString(reply, AttrCCBID)
	if contact == "" {
		_ = conn.Close()
		return fmt.Errorf("ccb: registration reply from %s missing CCBID", r.addr)
	}
	streaming, _ := AdBool(reply, AttrCCBStreaming)

	r.mu.Lock()
	r.conn = conn
	r.stream = s
	r.contact = contact
	r.cookie = AdString(reply, AttrClaimID)
	r.brokerStreaming = streaming
	r.registered = true
	r.mu.Unlock()
	return nil
}

// serve reads control messages from the broker until the connection drops.
func (r *brokerReg) serve(ctx context.Context) {
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go r.heartbeatLoop(hbCtx)

	for {
		if ctx.Err() != nil {
			return
		}
		ad, err := ReadControlAd(ctx, r.stream)
		if err != nil {
			return
		}
		cmd, _ := AdInt(ad, AttrCommand)
		switch int(cmd) {
		case CommandRequest:
			go r.handleRequest(ctx, ad)
		case CommandAlive:
			// heartbeat from broker; nothing to do.
		default:
			// ignore unexpected messages.
		}
	}
}

func (r *brokerReg) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(r.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ad := NewAd(map[string]any{AttrCommand: CommandAlive})
			if err := r.writeToBroker(ctx, ad); err != nil {
				return
			}
		}
	}
}

// handleRequest performs a reverse connection to the requester named in the
// CCB_REQUEST and hands it to the user Handler, then reports the result.
func (r *brokerReg) handleRequest(ctx context.Context, ad *classad.ClassAd) {
	myAddr := AdString(ad, AttrMyAddress)
	connectID := AdString(ad, AttrClaimID)
	requestID := AdString(ad, AttrRequestID)

	result := NewAd(map[string]any{
		AttrClaimID:   connectID,
		AttrRequestID: requestID,
		AttrMyAddress: myAddr,
	})

	dialCtx, cancel := context.WithTimeout(ctx, r.cfg.DialTimeout)
	defer cancel()
	host := strings.Trim(myAddr, "<>")
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", host)
	if err != nil {
		_ = result.Set(AttrResult, false)
		_ = result.Set(AttrErrorString, "failed to connect: "+err.Error())
		_ = r.writeToBroker(ctx, result)
		return
	}

	s := stream.NewStream(conn)
	if err := WriteReverseConnect(dialCtx, s, connectID, requestID, myAddr); err != nil {
		_ = conn.Close()
		_ = result.Set(AttrResult, false)
		_ = result.Set(AttrErrorString, "failed to send reverse-connect: "+err.Error())
		_ = r.writeToBroker(ctx, result)
		return
	}

	// Hand the now-inbound command socket to the user. They own it.
	if r.cfg.Handler != nil {
		go r.cfg.Handler(conn)
	} else {
		_ = conn.Close()
	}

	_ = result.Set(AttrResult, true)
	_ = r.writeToBroker(ctx, result)
}

func (r *brokerReg) writeToBroker(ctx context.Context, ad *classad.ClassAd) error {
	r.mu.Lock()
	s := r.stream
	r.mu.Unlock()
	if s == nil {
		return fmt.Errorf("ccb: not connected to broker %s", r.addr)
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return WriteControlAd(ctx, s, ad)
}

func (r *brokerReg) closeConn() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
		r.stream = nil
	}
	r.registered = false
}

// sleepCtx waits for d or until ctx is cancelled; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
