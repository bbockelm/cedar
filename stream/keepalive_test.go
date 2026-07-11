package stream

import (
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// getsockoptInt reads an integer socket option from a net.Conn's underlying fd.
func getsockoptInt(t *testing.T, conn net.Conn, level, opt int) int {
	t.Helper()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("conn %T does not implement syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var val int
	var operr error
	if err := raw.Control(func(fd uintptr) {
		val, operr = syscall.GetsockoptInt(int(fd), level, opt)
	}); err != nil {
		t.Fatalf("raw.Control: %v", err)
	}
	if operr != nil {
		t.Fatalf("GetsockoptInt(level=%d opt=%d): %v", level, opt, operr)
	}
	return val
}

// loopbackPair returns a connected client/server TCP pair on 127.0.0.1.
func loopbackPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatalf("Accept: %v", a.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = a.c.Close() })
	return client, a.c
}

func TestDefaultKeepAliveConfig(t *testing.T) {
	cfg := DefaultKeepAliveConfig()
	if !cfg.Enable {
		t.Error("expected Enable=true")
	}
	if cfg.Idle != 360*time.Second {
		t.Errorf("Idle = %v, want 360s (mirrors TCP_KEEPALIVE_INTERVAL default)", cfg.Idle)
	}
	if cfg.Interval != 5*time.Second {
		t.Errorf("Interval = %v, want 5s (C++ TCP_KEEPINTVL)", cfg.Interval)
	}
	if cfg.Count != 5 {
		t.Errorf("Count = %d, want 5 (C++ TCP_KEEPCNT)", cfg.Count)
	}
}

func TestKeepAliveConfigApplyEnables(t *testing.T) {
	client, _ := loopbackPair(t)

	if err := DefaultKeepAliveConfig().Apply(client); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := getsockoptInt(t, client, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); got == 0 {
		t.Errorf("SO_KEEPALIVE = %d, want non-zero (enabled)", got)
	}

	// Where the platform exposes the idle-time knob, confirm our 360s default
	// actually reached the socket. Linux: TCP_KEEPIDLE (seconds).
	if runtime.GOOS == "linux" {
		const tcpKeepIdle = 0x4 // TCP_KEEPIDLE
		if got := getsockoptInt(t, client, syscall.IPPROTO_TCP, tcpKeepIdle); got != 360 {
			t.Errorf("TCP_KEEPIDLE = %d, want 360", got)
		}
	}
}

func TestKeepAliveConfigApplyDisables(t *testing.T) {
	client, _ := loopbackPair(t)

	// First enable, then explicitly disable, and confirm it is off.
	if err := DefaultKeepAliveConfig().Apply(client); err != nil {
		t.Fatalf("Apply(enable): %v", err)
	}
	off := KeepAliveConfig{Enable: false}
	if err := off.Apply(client); err != nil {
		t.Fatalf("Apply(disable): %v", err)
	}
	if got := getsockoptInt(t, client, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE); got != 0 {
		t.Errorf("SO_KEEPALIVE = %d, want 0 (disabled)", got)
	}
}

func TestKeepAliveConfigApplyNonTCPIsNoOp(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	// net.Pipe conns are not *net.TCPConn; Apply must be a silent no-op.
	if err := DefaultKeepAliveConfig().Apply(c1); err != nil {
		t.Errorf("Apply on non-TCP conn returned error: %v", err)
	}
}
