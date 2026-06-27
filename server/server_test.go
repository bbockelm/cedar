package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/ccb"
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
