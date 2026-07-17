// Package server provides reusable scaffolding for building CEDAR command
// servers (daemons that accept connections, authenticate, and dispatch
// HTCondor commands). It complements the client-focused packages in this
// module.
//
// Two kinds of command handlers are supported:
//
//   - Authenticated commands: the client opens the exchange with a
//     DC_AUTHENTICATE command and a security ClassAd that carries the real
//     command (e.g. CCB_REGISTER). The server performs the security handshake
//     and dispatches on the real command.
//   - Raw commands: the client sends a bare command integer with no security
//     handshake (e.g. CCB_REVERSE_CONNECT, which HTCondor registers as ALLOW
//     and sends via the "raw" command protocol). These are dispatched
//     directly with no authentication.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sort"
	"sync"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// Conn is the per-connection context handed to a command handler.
type Conn struct {
	// Stream is the CEDAR stream for the connection. For authenticated
	// commands it is authenticated (and possibly encrypted) by the time the
	// handler runs; for raw commands it is plaintext.
	Stream *stream.Stream

	// Command is the real HTCondor command being dispatched.
	Command int

	// Negotiation is the result of the security handshake, or nil for raw
	// commands.
	Negotiation *security.SecurityNegotiation

	// Message is the inbound Message the leading command integer was read
	// from. Raw-command handlers read their payload (e.g. a ClassAd) from
	// this message; authenticated handlers normally start a fresh message.
	// For a follow-on command on a kept-alive connection (see KeepAlive) it is
	// the message the follow-on command integer was read from, so the handler
	// reads that command's ad from the same message.
	Message *message.Message

	// RemoteAddr is the peer's network address.
	RemoteAddr string

	// keepAlive, set via KeepAlive, asks the server to keep the connection open
	// after this handler and read a follow-on command integer on the same
	// (already-established) session -- HTCondor's persistent command socket, how
	// a daemon streams several updates (schedd ad + submitter ads, ...) down one
	// connection without re-authenticating.
	keepAlive bool
}

// KeepAlive requests that, after this handler returns nil, the server keep the
// connection open and dispatch the next command the peer sends on the same
// session (rather than closing). Used by update handlers to serve HTCondor's
// persistent command-socket protocol. Ignored if the handler returns an error.
func (c *Conn) KeepAlive() { c.keepAlive = true }

// PeerVersion returns the peer's reported $CondorVersion$ string, or "" if it
// was not exchanged (e.g. for raw commands).
func (c *Conn) PeerVersion() string {
	if c.Negotiation != nil && c.Negotiation.ClientConfig != nil {
		return c.Negotiation.ClientConfig.RemoteVersion
	}
	return ""
}

// HandlerFunc handles a single dispatched command. Returning an error closes
// the connection unless the handler has taken ownership of it (see KeepOpen).
type HandlerFunc func(ctx context.Context, c *Conn) error

type registeredHandler struct {
	fn    HandlerFunc
	raw   bool
	perms []string
}

// Server accepts CEDAR connections and dispatches commands to handlers.
type Server struct {
	// SecurityConfig is used for the server side of the security handshake on
	// authenticated commands. It must be non-nil if any authenticated handler
	// is registered.
	SecurityConfig *security.SecurityConfig

	// SecurityConfigForCommand, if set, selects a per-command security policy for
	// the handshake: once the client's requested command is known, the returned
	// config replaces SecurityConfig for that connection's negotiation. This lets
	// a daemon serve different commands at different HTCondor authorization levels
	// (e.g. a collector negotiating a QUERY at READ but an UPDATE at ADVERTISE).
	// Returning nil falls back to SecurityConfig. Optional.
	SecurityConfigForCommand func(command int) *security.SecurityConfig

	// Authorizer, if set, reports whether an authenticated peer is allowed at a
	// given authorization level. perm is an HTCondor DCpermission name (e.g.
	// "READ", "DAEMON"); peerAddr is the peer's "host:port"; user is the mapped
	// FQU. The server consults it — for every registered authenticated command's
	// levels — to compute the session's ValidCommands after authentication, so a
	// peer can reuse the session for any command it is authorized for. Leaving it
	// nil advertises only the negotiated command (no authorization table applied).
	Authorizer func(perm, peerAddr, user string) bool

	// FQUMapper, if set, maps an authenticated identity to the fully-qualified
	// user to advertise and authorize as (e.g. via a mapfile). Returning "" keeps
	// the authenticated identity. Optional.
	FQUMapper func(authUser, peerAddr string) string

	// KeepAlive configures TCP keepalives applied to every connection accepted
	// in Serve. New() initializes it to stream.DefaultKeepAliveConfig
	// (SO_KEEPALIVE on; idle 360s, interval 5s, count 5), mirroring C++
	// HTCondor which enables keepalives on accepted daemon sockets so a
	// silently-dead peer (e.g. a powered-off execute host) is detected rather
	// than leaking a blocked handler goroutine. Set Enable=false to disable.
	KeepAlive stream.KeepAliveConfig

	mu       sync.RWMutex
	handlers map[int]registeredHandler
}

// New creates a Server with the given server-side security configuration. It
// installs the server's ValidCommands computation as the security layer's
// post-auth policy, so authenticating peers learn every command they are
// authorized for (see Authorizer).
func New(secConfig *security.SecurityConfig) *Server {
	s := &Server{
		SecurityConfig: secConfig,
		handlers:       map[int]registeredHandler{},
		KeepAlive:      stream.DefaultKeepAliveConfig(),
	}
	if secConfig != nil {
		secConfig.PostAuthPolicy = s.postAuthPolicy
	}
	return s
}

// Handle registers an authenticated handler for a command. The optional perms
// are the authorization levels (HTCondor DCpermission names, e.g. "READ" or
// "DAEMON") that authorize the command; a peer is authorized if it satisfies any
// one of them. The levels drive both the ValidCommands the server advertises
// after authentication and, for callers that enforce it, per-command
// authorization (see CommandPerms). Registering with no perms advertises the
// command only as the negotiated one and applies no authorization table.
func (s *Server) Handle(command int, fn HandlerFunc, perms ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: false, perms: perms}
}

// HandleRaw registers a handler for a raw (un-authenticated) command. The
// command integer arrives with no preceding DC_AUTHENTICATE.
func (s *Server) HandleRaw(command int, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: true}
}

// CommandPerms returns the authorization levels registered for command, or nil
// if it is unregistered or raw. Callers enforcing per-command authorization
// should verify a peer against these levels so their decision matches the
// ValidCommands the server advertises.
func (s *Server) CommandPerms(command int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.handlers[command].perms
}

// sessionSatisfies reports whether an already-established session may run
// realCmd, enforcing two properties beyond the initial handshake so that a
// permissive session cannot be reused (kept-alive or resumed) for a command that
// demands a stronger security level:
//
//   - Security level: realCmd's negotiated policy (SecurityConfigForCommand, or
//     SecurityConfig) may mandate authentication and/or encryption; the session
//     must actually provide them. A session negotiated at READ (encryption
//     optional, possibly unauthenticated/plaintext) therefore cannot run an
//     ADVERTISE command that requires authentication and encryption.
//   - Authorization: when an Authorizer gates the server, realCmd must appear in
//     the session's post-auth ValidCommands set. Without an Authorizer,
//     authorization is not enforced here and reuse is bounded by the
//     security-level check alone.
func (s *Server) sessionSatisfies(realCmd int, peerAddr string, neg *security.SecurityNegotiation) error {
	if neg == nil {
		return fmt.Errorf("no negotiated session")
	}
	// Security level, re-evaluated against CURRENT policy: a persisted/resumed
	// session may cross a reconfig or restart, so a command that now mandates
	// authentication or encryption is refused on a session that lacks it,
	// regardless of what the session was originally granted.
	if !s.commandLevelSatisfied(realCmd, neg.Authentication, neg.Encryption) {
		return fmt.Errorf("session (authenticated=%t encrypted=%t) does not meet the command's security level", neg.Authentication, neg.Encryption)
	}
	// Authorization, also re-evaluated against the CURRENT Authorizer rather than
	// the session's advertised ValidCommands (which may be stale after a policy
	// change): the identity must satisfy one of the command's registered levels.
	if s.Authorizer != nil && !s.authorized(realCmd, peerAddr, neg.User) {
		return fmt.Errorf("identity %q is not authorized for this command under current policy", neg.User)
	}
	return nil
}

// commandLevelSatisfied reports whether a session with the given negotiated
// properties meets realCmd's current security requirements (authentication and
// encryption/integrity). Reads only set-once fields, so it takes no lock.
func (s *Server) commandLevelSatisfied(realCmd int, authenticated, encrypted bool) bool {
	req := s.SecurityConfig
	if s.SecurityConfigForCommand != nil {
		if perCmd := s.SecurityConfigForCommand(realCmd); perCmd != nil {
			req = perCmd
		}
	}
	if req == nil {
		return true
	}
	if req.Authentication == security.SecurityRequired && !authenticated {
		return false
	}
	// cedar's encryption (AES-GCM) is authenticated encryption, so an encrypted
	// session also provides integrity; a command mandating either needs encryption.
	if (req.Encryption == security.SecurityRequired || req.Integrity == security.SecurityRequired) && !encrypted {
		return false
	}
	return true
}

// authorized reports whether user may run realCmd under the current Authorizer
// and the command's registered authorization levels.
func (s *Server) authorized(realCmd int, peerAddr, user string) bool {
	for _, perm := range s.CommandPerms(realCmd) {
		if s.Authorizer(perm, peerAddr, user) {
			return true
		}
	}
	return false
}

// mapFQU applies FQUMapper (if set) to resolve the identity to advertise and
// authorize as, falling back to the authenticated identity.
func (s *Server) mapFQU(authUser, peerAddr string) string {
	if s.FQUMapper != nil {
		if mapped := s.FQUMapper(authUser, peerAddr); mapped != "" {
			return mapped
		}
	}
	return authUser
}

// postAuthPolicy is installed as the security layer's PostAuthPolicy. After a
// successful handshake it returns the FQU to advertise and the set of commands
// this session is authorized for — every registered authenticated command whose
// levels the Authorizer accepts. With no Authorizer set it returns no commands,
// so the security layer advertises just the negotiated command (its default).
func (s *Server) postAuthPolicy(authUser, peerAddr string, authenticated, encrypted bool) (string, []int) {
	fqu := s.mapFQU(authUser, peerAddr)
	if s.Authorizer == nil {
		return fqu, nil
	}
	var valid []int
	s.mu.RLock()
	for cmd, h := range s.handlers {
		if h.raw || len(h.perms) == 0 {
			continue
		}
		// Only advertise a command the session could run right now: it must both
		// clear the command's security level for this session AND be authorized.
		// Advertising a command the session can't immediately use (e.g. an
		// encryption-mandating command over a plaintext session) would be an
		// overly-broad ValidCommands that the dispatch-time check then rejects.
		if !s.commandLevelSatisfied(cmd, authenticated, encrypted) {
			continue
		}
		for _, perm := range h.perms {
			if s.Authorizer(perm, peerAddr, fqu) {
				valid = append(valid, cmd)
				break
			}
		}
	}
	s.mu.RUnlock()
	sort.Ints(valid)
	return fqu, valid
}

// Serve accepts connections from l until the context is cancelled or Accept
// fails permanently. Each connection is handled in its own goroutine.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		// Enable TCP keepalives on the accepted connection so a silently-dead
		// peer is detected instead of blocking the handler goroutine forever.
		// Best-effort: a no-op for non-TCP listeners and never fatal.
		_ = s.KeepAlive.Apply(conn)
		go func() {
			// Isolate each connection: a panic in one handler must not take
			// down the whole daemon. Recover, log the stack, and drop just this
			// connection.
			defer func() {
				if r := recover(); r != nil {
					slog.Error("cedar/server: panic in connection handler; recovered",
						"panic", r, "remote", conn.RemoteAddr().String(),
						"stack", string(debug.Stack()), "destination", "cedar")
					_ = conn.Close()
				}
			}()
			if err := s.ServeConn(ctx, conn); err != nil {
				// Best-effort; connection-level errors are not fatal to the
				// server. Callers that want visibility can wrap ServeConn.
				_ = err
			}
		}()
	}
}

// errKeepOpen is a sentinel a handler can return (via KeepOpen) to indicate it
// has taken ownership of the connection and ServeConn must not close it.
var errKeepOpen = fmt.Errorf("cedar/server: connection kept open by handler")

// KeepOpen is returned by a handler that has taken ownership of the connection
// (e.g. a persistent CCB registration socket or a proxied stream). ServeConn
// will not close the underlying connection in that case.
func KeepOpen() error { return errKeepOpen }

// ServeConn handles a single already-accepted connection: it reads the leading
// command integer, performs the security handshake for authenticated commands,
// and dispatches to the registered handler.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) error {
	// Give each connection its own cancellable child context. The stream layer
	// registers a context.AfterFunc per frame write to interrupt a blocked write on
	// cancellation; anchoring those on a per-connection context (which has a single
	// writer goroutine) instead of the shared server context eliminates the
	// cross-connection contention on the parent context's mutex that per-frame
	// registration would otherwise cause. cancel() on return also tears down any
	// per-connection cancellation state.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	st := stream.NewStream(conn)
	st.SetPeerAddr(conn.RemoteAddr().String())

	msg := message.NewMessageFromStream(st)
	cmd, err := msg.GetInt(ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("cedar/server: failed to read command: %w", err)
	}

	if cmd == commands.DC_AUTHENTICATE {
		if s.SecurityConfig == nil {
			_ = conn.Close()
			return fmt.Errorf("cedar/server: authenticated command received but no SecurityConfig set")
		}
		// The handshake mutates its config per-connection (e.g. NewAuthenticator
		// stores this connection's ephemeral ECDH public key in it), so give each
		// connection a private shallow copy rather than the server's shared config.
		// A shallow copy is enough: the mutated fields are values (ECDHPublicKey,
		// negotiated levels, ...), while the shared pointer fields (credentials) are
		// read-only during the handshake. Without this, concurrent handshakes race
		// on -- and clobber each other's -- ECDH key. (Shared config = data race.)
		connConfig := *s.SecurityConfig
		auth := security.NewAuthenticator(&connConfig, st)
		if s.SecurityConfigForCommand != nil {
			// Select a per-command policy once the handshake reveals the command,
			// giving each connection its own shallow copy (same rationale as above).
			auth.ServerConfigForCommand = func(command int) *security.SecurityConfig {
				cfg := s.SecurityConfigForCommand(command)
				if cfg == nil {
					return nil
				}
				c := *cfg
				return &c
			}
		}
		neg, err := auth.ServerHandshakeWithMessage(ctx, msg, cmd)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("cedar/server: handshake failed: %w", err)
		}
		realCmd := 0
		if neg.ClientConfig != nil {
			realCmd = neg.ClientConfig.Command
		}
		// Dispatch the negotiated command, then -- if its handler opted into
		// keepalive -- keep serving follow-on commands on the same established
		// session (HTCondor's persistent command socket: the peer sends a raw
		// command integer over the still-encrypted stream, no re-handshake).
		var followMsg *message.Message // nil for the first command (ad is a fresh message)
		for {
			h, ok := s.lookup(realCmd)
			if !ok || h.raw {
				_ = conn.Close()
				return fmt.Errorf("cedar/server: no authenticated handler for command %d (%s)", realCmd, commands.GetCommandName(realCmd))
			}
			// Enforce that the established session actually satisfies THIS command's
			// security level before dispatching. The first command is covered by the
			// handshake, but a kept-alive or resumed session may carry weaker
			// properties than a follow-on command needs -- e.g. a session negotiated
			// at READ (encryption optional, maybe unauthenticated/plaintext) must not
			// be reused to run an ADVERTISE command that mandates authentication and
			// encryption. Without this, per-command negotiation could be bypassed by
			// establishing a permissive session and then sending a privileged command.
			if err := s.sessionSatisfies(realCmd, conn.RemoteAddr().String(), neg); err != nil {
				_ = conn.Close()
				return fmt.Errorf("cedar/server: command %d (%s) refused: %w", realCmd, commands.GetCommandName(realCmd), err)
			}
			c := &Conn{
				Stream:      st,
				Command:     realCmd,
				Negotiation: neg,
				Message:     followMsg,
				RemoteAddr:  conn.RemoteAddr().String(),
			}
			if err := h.fn(ctx, c); err != nil {
				if err == errKeepOpen {
					return nil
				}
				_ = conn.Close()
				return err
			}
			if !c.keepAlive {
				_ = conn.Close()
				return nil
			}
			// Read the next command integer on the same session. EOF/any error
			// means the peer finished sending updates and closed -- a clean end.
			followMsg = message.NewMessageFromStream(st)
			realCmd, err = followMsg.GetInt(ctx)
			if err != nil {
				_ = conn.Close()
				return nil
			}
		}
	}

	// Raw command path: no handshake, payload follows in the same message.
	h, ok := s.lookup(cmd)
	if !ok || !h.raw {
		_ = conn.Close()
		return fmt.Errorf("cedar/server: no raw handler for command %d (%s)", cmd, commands.GetCommandName(cmd))
	}
	return s.run(ctx, h, &Conn{
		Stream:     st,
		Command:    cmd,
		Message:    msg,
		RemoteAddr: conn.RemoteAddr().String(),
	}, conn)
}

func (s *Server) run(ctx context.Context, h registeredHandler, c *Conn, conn net.Conn) error {
	err := h.fn(ctx, c)
	if err == errKeepOpen {
		return nil
	}
	_ = conn.Close()
	return err
}

func (s *Server) lookup(command int) (registeredHandler, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.handlers[command]
	return h, ok
}
