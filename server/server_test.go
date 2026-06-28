package server

import (
	"context"
	"net"
	"os/user"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// TestRawDispatch verifies that a bare command integer (no DC_AUTHENTICATE) is
// routed to a raw handler, which can then read the payload from the same
// message — exactly the CCB_REVERSE_CONNECT path.
func TestRawDispatch(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const connectID = "00112233445566778899aabbccddeeff00112233"

	got := make(chan string, 1)
	srv := New(nil)
	srv.HandleRaw(ccb.CommandReverseConnect, func(ctx context.Context, c *Conn) error {
		ad, err := ccb.ReadReverseConnectAd(ctx, c.Message, c.Command)
		if err != nil {
			return err
		}
		got <- ccb.AdString(ad, ccb.AttrClaimID)
		return nil
	})

	go func() {
		s := stream.NewStream(c1)
		_ = ccb.WriteReverseConnect(ctx, s, connectID, "1", "<10.0.0.9:9618>")
	}()

	if err := srv.ServeConn(ctx, c2); err != nil {
		t.Fatalf("ServeConn: %v", err)
	}
	select {
	case id := <-got:
		if id != connectID {
			t.Errorf("handler saw ClaimId %q, want %q", id, connectID)
		}
	default:
		t.Fatal("handler did not run")
	}
}

// TestAuthenticatedDispatch runs a real client<->server exchange through
// Server.ServeConn: the client performs a full CEDAR security handshake (FS
// authentication), the server dispatches to the authenticated handler for the
// negotiated command, and a ClassAd request/reply round-trips over the
// authenticated stream. It verifies the server learns the client's
// authenticated identity rather than just accepting a bare command.
func TestAuthenticatedDispatch(t *testing.T) {
	const authCmd = 60123 // arbitrary authenticated command

	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
	})

	type seen struct {
		user string
		cmd  int
		hi   string
	}
	handlerDone := make(chan seen, 1)
	handlerErr := make(chan error, 1)
	srv.Handle(authCmd, func(ctx context.Context, c *Conn) error {
		req, err := ccb.ReadControlAd(ctx, c.Stream)
		if err != nil {
			handlerErr <- err
			return err
		}
		// Echo the authenticated user back to the client.
		reply := ccb.NewAd(map[string]any{
			"AuthenticatedUser": c.Negotiation.User,
		})
		if err := ccb.WriteControlAd(ctx, c.Stream, reply); err != nil {
			handlerErr <- err
			return err
		}
		handlerDone <- seen{user: c.Negotiation.User, cmd: c.Command, hi: ccb.AdString(req, "Hello")}
		return nil
	})

	go func() { _ = srv.ServeConn(ctx, serverConn) }()

	cliStream := stream.NewStream(clientConn)
	auth := security.NewAuthenticator(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		Command:        authCmd,
	}, cliStream)
	if _, err := auth.ClientHandshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Send a request and read the reply over the now-authenticated stream.
	if err := ccb.WriteControlAd(ctx, cliStream, ccb.NewAd(map[string]any{"Hello": "world"})); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := ccb.ReadControlAd(ctx, cliStream)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}

	select {
	case err := <-handlerErr:
		t.Fatalf("handler error: %v", err)
	case s := <-handlerDone:
		if s.cmd != authCmd {
			t.Errorf("handler dispatched cmd=%d, want %d", s.cmd, authCmd)
		}
		if s.user == "" {
			t.Error("server did not record an authenticated user")
		}
		if s.hi != "world" {
			t.Errorf("server saw request Hello=%q, want %q", s.hi, "world")
		}
	case <-ctx.Done():
		t.Fatalf("handler did not complete: %v", ctx.Err())
	}

	if got := ccb.AdString(reply, "AuthenticatedUser"); got == "" {
		t.Error("reply missing AuthenticatedUser")
	} else {
		t.Logf("authenticated as %q (os user %q)", got, me.Username)
	}
}

// TestUnknownRawCommand verifies an unregistered command is rejected.
func TestUnknownRawCommand(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := New(nil)

	go func() {
		s := stream.NewStream(c1)
		_ = ccb.WriteReverseConnect(ctx, s, "x", "", "")
	}()

	if err := srv.ServeConn(ctx, c2); err == nil {
		t.Fatal("expected error for unregistered command")
	}
}
