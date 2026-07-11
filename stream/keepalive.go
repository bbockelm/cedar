package stream

import (
	"net"
	"time"
)

// TCP keepalive defaults for CEDAR sockets.
//
// These mirror C++ HTCondor's Sock::set_keepalive() (src/condor_io/sock.cpp:955),
// which is driven by the TCP_KEEPALIVE_INTERVAL config knob. That knob defaults
// to 360 (src/condor_utils/param_info.in:4587-4589) and is interpreted as the
// idle time (seconds) before the first probe; the C++ code then hard-codes a
// probe count of 5 (TCP_KEEPCNT) and a probe interval of 5 seconds
// (TCP_KEEPINTVL). HTCondor enables SO_KEEPALIVE on outbound (client-dialed)
// TCP sockets and on server-accepted sockets so a silently-dead peer (e.g. an
// execute host that lost power) is detected instead of leaving a goroutine
// blocked in Read forever.
//
// Semantics of the knob, preserved here via KeepAliveConfig:
//   - knob < 0  => keepalive disabled entirely (KeepAliveConfig.Enable = false)
//   - knob == 0 => SO_KEEPALIVE on, OS defaults for idle/interval/count
//   - knob  > 0 => SO_KEEPALIVE on, idle = knob, interval = 5s, count = 5
const (
	// DefaultKeepAliveIdle is the idle time before the first keepalive probe.
	// Matches TCP_KEEPALIVE_INTERVAL's default of 360 seconds.
	DefaultKeepAliveIdle = 360 * time.Second
	// DefaultKeepAliveInterval is the interval between probes (C++ TCP_KEEPINTVL = 5s).
	DefaultKeepAliveInterval = 5 * time.Second
	// DefaultKeepAliveCount is the number of failed probes before the
	// connection is declared dead (C++ TCP_KEEPCNT = 5).
	DefaultKeepAliveCount = 5
)

// KeepAliveConfig controls TCP keepalive probing on a CEDAR socket. The zero
// value keeps keepalives disabled; use DefaultKeepAliveConfig for the
// HTCondor-matching defaults, then override individual fields as needed.
type KeepAliveConfig struct {
	// Enable turns SO_KEEPALIVE on (true) or off (false).
	Enable bool
	// Idle is the time a connection is idle before the first keepalive probe
	// is sent (TCP_KEEPIDLE / TCP_KEEPALIVE). A value <= 0 leaves the OS
	// default in place.
	Idle time.Duration
	// Interval is the time between successive keepalive probes
	// (TCP_KEEPINTVL). A value <= 0 leaves the OS default in place.
	Interval time.Duration
	// Count is the number of unacknowledged probes before the connection is
	// considered dead (TCP_KEEPCNT). A value <= 0 leaves the OS default.
	Count int
}

// DefaultKeepAliveConfig returns the CEDAR keepalive settings that mirror C++
// HTCondor's defaults (SO_KEEPALIVE on; idle 360s, interval 5s, count 5).
func DefaultKeepAliveConfig() KeepAliveConfig {
	return KeepAliveConfig{
		Enable:   true,
		Idle:     DefaultKeepAliveIdle,
		Interval: DefaultKeepAliveInterval,
		Count:    DefaultKeepAliveCount,
	}
}

// Apply configures TCP keepalives on conn according to k. It is a no-op that
// returns nil for connections that are not *net.TCPConn (e.g. Unix sockets used
// by the shared-port local path, or test pipes), so callers can apply it
// unconditionally. Fields set to <= 0 are translated to net.KeepAliveConfig's
// "leave unchanged" sentinel (-1) so the OS default is preserved for that knob.
func (k KeepAliveConfig) Apply(conn net.Conn) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	cfg := net.KeepAliveConfig{Enable: k.Enable}
	if k.Idle > 0 {
		cfg.Idle = k.Idle
	} else {
		cfg.Idle = -1
	}
	if k.Interval > 0 {
		cfg.Interval = k.Interval
	} else {
		cfg.Interval = -1
	}
	if k.Count > 0 {
		cfg.Count = k.Count
	} else {
		cfg.Count = -1
	}
	return tcp.SetKeepAliveConfig(cfg)
}
