package ccb

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeListener is a net.Listener stand-in; nothing accepts on it.
type fakeListener struct{ closed bool }

func (f *fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not used") }
func (f *fakeListener) Close() error              { f.closed = true; return nil }
func (f *fakeListener) Addr() net.Addr            { return nil }

func TestNewReverseListenerUsesHook(t *testing.T) {
	ln := &fakeListener{}
	got, addr, err := newReverseListener(DialOptions{
		ReverseListener: func() (net.Listener, string, error) {
			return ln, "<10.0.0.1:9618?sock=abc>", nil
		},
		// Set both of the paths the hook has to take precedence over, so a
		// regression that fell through to either is caught here rather than as
		// a reverse connection to the wrong address.
		ListenAddr:         "127.0.0.1:0",
		SharedPortEndpoint: &SharedPortEndpointConfig{SharedPortAddr: "10.0.0.2:9618"},
	})
	if err != nil {
		t.Fatalf("newReverseListener: %v", err)
	}
	if got != net.Listener(ln) {
		t.Errorf("returned listener %T, want the one the hook supplied", got)
	}
	if addr != "<10.0.0.1:9618?sock=abc>" {
		t.Errorf("advertised address = %q, want the hook's", addr)
	}
}

func TestNewReverseListenerHookRespectsMyAddress(t *testing.T) {
	// An explicit MyAddress still wins: it is the caller saying it knows better
	// than the listener what peers can route to.
	_, addr, err := newReverseListener(DialOptions{
		MyAddress:       "<public.example.com:9618?sock=abc>",
		ReverseListener: func() (net.Listener, string, error) { return &fakeListener{}, "<10.0.0.1:9618?sock=abc>", nil },
	})
	if err != nil {
		t.Fatalf("newReverseListener: %v", err)
	}
	if addr != "<public.example.com:9618?sock=abc>" {
		t.Errorf("advertised address = %q, want MyAddress", addr)
	}
}

func TestNewReverseListenerHookError(t *testing.T) {
	_, _, err := newReverseListener(DialOptions{
		ReverseListener: func() (net.Listener, string, error) { return nil, "", errors.New("no route available") },
	})
	if err == nil || !strings.Contains(err.Error(), "no route available") {
		t.Fatalf("error = %v, want it to carry the hook's failure", err)
	}
}

func TestNewReverseListenerHookEmptyAddressClosesListener(t *testing.T) {
	ln := &fakeListener{}
	if _, _, err := newReverseListener(DialOptions{
		ReverseListener: func() (net.Listener, string, error) { return ln, "", nil },
	}); err == nil {
		t.Fatal("expected an error when the hook supplies no address to advertise")
	}
	if !ln.closed {
		t.Error("listener should be closed when its address is unusable; otherwise the registration leaks")
	}
}
