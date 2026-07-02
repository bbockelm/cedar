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
	Message *message.Message

	// RemoteAddr is the peer's network address.
	RemoteAddr string
}

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
	fn  HandlerFunc
	raw bool
}

// Server accepts CEDAR connections and dispatches commands to handlers.
type Server struct {
	// SecurityConfig is used for the server side of the security handshake on
	// authenticated commands. It must be non-nil if any authenticated handler
	// is registered.
	SecurityConfig *security.SecurityConfig

	mu       sync.RWMutex
	handlers map[int]registeredHandler
}

// New creates a Server with the given server-side security configuration.
func New(secConfig *security.SecurityConfig) *Server {
	return &Server{
		SecurityConfig: secConfig,
		handlers:       map[int]registeredHandler{},
	}
}

// Handle registers an authenticated handler for a command.
func (s *Server) Handle(command int, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: false}
}

// HandleRaw registers a handler for a raw (un-authenticated) command. The
// command integer arrives with no preceding DC_AUTHENTICATE.
func (s *Server) HandleRaw(command int, fn HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = registeredHandler{fn: fn, raw: true}
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
		auth := security.NewAuthenticator(s.SecurityConfig, st)
		neg, err := auth.ServerHandshakeWithMessage(ctx, msg, cmd)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("cedar/server: handshake failed: %w", err)
		}
		realCmd := 0
		if neg.ClientConfig != nil {
			realCmd = neg.ClientConfig.Command
		}
		h, ok := s.lookup(realCmd)
		if !ok || h.raw {
			_ = conn.Close()
			return fmt.Errorf("cedar/server: no authenticated handler for command %d (%s)", realCmd, commands.GetCommandName(realCmd))
		}
		return s.run(ctx, h, &Conn{
			Stream:      st,
			Command:     realCmd,
			Negotiation: neg,
			RemoteAddr:  conn.RemoteAddr().String(),
		}, conn)
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
