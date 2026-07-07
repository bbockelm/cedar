package stream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// net.Pipe is fully synchronous: a Write blocks until the peer Reads, so with no
// reader a write/read stays blocked until the context cancellation path closes the
// connection to interrupt it. These tests exercise the AfterFunc-based
// cancellation that replaced the per-call goroutine+channel.

func TestWriteWithContextCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	s := NewStream(c1)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.writeWithContext(ctx, []byte("hello")) }()

	time.Sleep(20 * time.Millisecond) // let the write block
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("write err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writeWithContext did not return after cancel")
	}
}

func TestWriteWithContextDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	s := NewStream(c1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := s.writeWithContext(ctx, []byte("hello"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write err = %v, want context.DeadlineExceeded", err)
	}
}

func TestReadWithContextCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	s := NewStream(c1)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- s.readWithContext(ctx, make([]byte, 4))
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readWithContext did not return after cancel")
	}
}

// TestWriteReadWithContextFastPath verifies the non-cancellable (Done()==nil) fast
// path still transfers data correctly.
func TestWriteReadWithContextFastPath(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	s := NewStream(c1)
	r := NewStream(c2)

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 5)
		if err := r.readWithContext(context.Background(), buf); err != nil {
			t.Errorf("read: %v", err)
		}
		got <- buf
	}()

	if err := s.writeWithContext(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case b := <-got:
		if string(b) != "hello" {
			t.Fatalf("read %q, want hello", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read did not complete")
	}
}
