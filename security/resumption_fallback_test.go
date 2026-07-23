package security

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/stream"
)

// TestResumptionExchangeFailureIsResumptionError reproduces the restart race a
// collector hits against a database that keeps no session store: the client
// holds a cached (persisted) session, sends a resumption request, and the peer
// drops the connection instead of answering. That failure must be classified a
// SessionResumptionError -- so ConnectAndAuthenticate falls back to a fresh
// connection with full authentication -- and the doomed session must leave the
// cache, so the fallback (and every later dial) does not re-attempt it.
func TestResumptionExchangeFailureIsResumptionError(t *testing.T) {
	cconn, sconn := net.Pipe()

	cache := NewSessionCache()
	entry := NewSessionEntry("test-session-id", "127.0.0.1:9618", nil, nil,
		time.Now().Add(time.Hour), time.Hour, "")
	cache.Store(entry)

	cfg := &SecurityConfig{Command: 1234}
	auth := NewAuthenticator(cfg, stream.NewStream(cconn))

	// Peer: read a little of the request, then hang up without a response --
	// the mid-restart shape (reset/EOF on the client side).
	go func() {
		buf := make([]byte, 64)
		_, _ = sconn.Read(buf)
		_ = sconn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := auth.resumeSession(ctx, entry, cache)
	if err == nil {
		t.Fatal("resumeSession succeeded against a peer that hung up")
	}
	if !IsSessionResumptionError(err) {
		t.Fatalf("exchange failure not classified as SessionResumptionError: %v", err)
	}
	if _, still := cache.Lookup("test-session-id"); still {
		t.Fatal("failed resumption left the stale session cached; every reconnect would re-attempt it")
	}
}
