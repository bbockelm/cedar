package sharedport

import (
	"context"
	"net"
	"sync"
	"time"
)

// Route is one registered shared-port id. It implements net.Listener, so a
// caller that would otherwise open its own inbound socket -- notably a CCB
// reverse-connect dial -- can take one of these instead and be reached through
// the shared port rather than through a port of its own.
//
// Close unregisters the id and fails any pending Accept. Connections already
// returned by Accept are unaffected; they belong to the caller.
type Route struct {
	srv    *Server
	id     string
	sinful string
	addr   routeAddr

	conns chan net.Conn

	closeOnce sync.Once
	closed    chan struct{}
}

// ID is the shared-port id ("sock" value) this Route is registered under.
func (r *Route) ID() string { return r.id }

// Sinful is the HTCondor address a peer uses to reach this Route through the
// shared port: "<host:port?sock=ID>".
func (r *Route) Sinful() string { return r.sinful }

// Accept returns the next connection routed to this id. The connection is
// positioned immediately after the peer's SHARED_PORT_CONNECT request, so it
// must be wrapped in a fresh CEDAR stream -- the shared-port exchange is not
// part of whatever protocol follows, and the peer has already reset its own
// stream for the same reason.
func (r *Route) Accept() (net.Conn, error) {
	select {
	case conn := <-r.conns:
		return conn, nil
	case <-r.closed:
		// Drain anything delivered before the close raced it, so a connection
		// is not silently dropped by a Close the consumer has not seen yet.
		select {
		case conn := <-r.conns:
			return conn, nil
		default:
		}
		return nil, net.ErrClosed
	}
}

// Close unregisters this id and unblocks Accept. Undelivered connections still
// queued on the Route are closed; nothing else will ever accept them.
func (r *Route) Close() error {
	r.srv.unregister(r)
	r.shutdown()
	return nil
}

// shutdown closes the Route without touching the registry, for the paths that
// have already removed it (Close, and the server's own teardown).
func (r *Route) shutdown() {
	r.closeOnce.Do(func() {
		close(r.closed)
		// Drain and close whatever is still queued. Safe against a concurrent
		// deliver: deliver selects on r.closed and gives up once it is shut.
		for {
			select {
			case conn := <-r.conns:
				_ = conn.Close()
			default:
				return
			}
		}
	})
}

// Addr reports the address peers reach this Route at.
func (r *Route) Addr() net.Addr { return r.addr }

// deliver queues conn for Accept, reporting whether it was taken. It gives up
// after timeout, or as soon as the Route closes, rather than pinning the
// connection to a consumer that has stopped accepting.
func (r *Route) deliver(ctx context.Context, conn net.Conn, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r.conns <- conn:
		// Queued, but a Close racing us here would drop it on the floor with
		// the connection still open; shutdown drains the queue for exactly
		// that reason, so ownership has transferred either way.
		return true
	case <-r.closed:
		return false
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

// routeAddr is the net.Addr a Route reports: the sinful body peers dial.
type routeAddr string

func (a routeAddr) Network() string { return "htcondor-sharedport" }
func (a routeAddr) String() string  { return string(a) }
