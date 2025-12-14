package security

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// KeyInfo represents a cryptographic key with metadata
type KeyInfo struct {
	Data     []byte
	Protocol string // "AESGCM", "BLOWFISH", "3DES", etc.
}

// SessionEntry represents a cached security session
type SessionEntry struct {
	id              string
	addr            string // Remote address this session is for (empty for incoming sessions)
	keyInfo         *KeyInfo
	policy          *classad.ClassAd
	expiration      time.Time
	lease           time.Duration
	lastPeerVersion string
	tag             string // Security context tag
	createdAt       time.Time
}

// NewSessionEntry creates a new session cache entry
func NewSessionEntry(id, addr string, keyInfo *KeyInfo, policy *classad.ClassAd, expiration time.Time, lease time.Duration, tag string) *SessionEntry {
	return &SessionEntry{
		id:         id,
		addr:       addr,
		keyInfo:    keyInfo,
		policy:     policy,
		expiration: expiration,
		lease:      lease,
		tag:        tag,
		createdAt:  time.Now(),
	}
}

// ID returns the session ID
func (s *SessionEntry) ID() string {
	return s.id
}

// Addr returns the remote address
func (s *SessionEntry) Addr() string {
	return s.addr
}

// KeyInfo returns the session key
func (s *SessionEntry) KeyInfo() *KeyInfo {
	return s.keyInfo
}

// Policy returns the security policy
func (s *SessionEntry) Policy() *classad.ClassAd {
	return s.policy
}

// Expiration returns the expiration time
func (s *SessionEntry) Expiration() time.Time {
	return s.expiration
}

// Lease returns the lease duration
func (s *SessionEntry) Lease() time.Duration {
	return s.lease
}

// Tag returns the security context tag
func (s *SessionEntry) Tag() string {
	return s.tag
}

// LastPeerVersion returns the last known peer version
func (s *SessionEntry) LastPeerVersion() string {
	return s.lastPeerVersion
}

// SetLastPeerVersion sets the last peer version
func (s *SessionEntry) SetLastPeerVersion(version string) {
	s.lastPeerVersion = version
}

// IsExpired checks if the session has expired
func (s *SessionEntry) IsExpired() bool {
	if s.expiration.IsZero() {
		return false
	}
	return time.Now().After(s.expiration)
}

// RenewLease renews the session lease
func (s *SessionEntry) RenewLease() {
	if s.lease.Seconds() != 0 {
		s.expiration = time.Now().Add(s.lease)
	}
}

// SessionCache manages cached security sessions
type SessionCache struct {
	mu         sync.RWMutex
	sessions   map[string]*SessionEntry
	commandMap map[string]string // Maps {tag,addr,<cmd>} to session ID
}

// NewSessionCache creates a new session cache
func NewSessionCache() *SessionCache {
	return &SessionCache{
		sessions:   make(map[string]*SessionEntry),
		commandMap: make(map[string]string),
	}
}

// Store adds or updates a session in the cache
func (c *SessionCache) Store(entry *SessionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[entry.id] = entry
}

// Lookup retrieves a session by ID
func (c *SessionCache) Lookup(id string) (*SessionEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.sessions[id]
	if !ok {
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		return nil, false
	}

	return entry, true
}

// LookupNonExpired retrieves a non-expired session by ID
func (c *SessionCache) LookupNonExpired(id string) (*SessionEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.sessions[id]
	if !ok {
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		// Remove expired session
		delete(c.sessions, id)
		return nil, false
	}

	return entry, true
}

// LookupByCommand finds a session for a specific command to an address
func (c *SessionCache) LookupByCommand(tag, addr, command string) (*SessionEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var key string
	if tag != "" {
		key = fmt.Sprintf("{%s,%s,<%s>}", tag, addr, command)
	} else {
		key = fmt.Sprintf("{%s,<%s>}", addr, command)
	}

	sessionID, ok := c.commandMap[key]
	if !ok {
		return nil, false
	}

	entry, ok := c.sessions[sessionID]
	if !ok {
		return nil, false
	}

	if entry.IsExpired() {
		return nil, false
	}

	return entry, true
}

// MapCommand maps a command to a session ID
func (c *SessionCache) MapCommand(tag, addr, command, sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var key string
	if tag != "" {
		key = fmt.Sprintf("{%s,%s,<%s>}", tag, addr, command)
	} else {
		key = fmt.Sprintf("{%s,<%s>}", addr, command)
	}

	c.commandMap[key] = sessionID
}

// Invalidate removes a session from the cache
func (c *SessionCache) Invalidate(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.sessions[id]
	if !ok {
		return false
	}

	delete(c.sessions, id)

	// Remove all command mappings to this session
	for key, sessID := range c.commandMap {
		if sessID == id {
			delete(c.commandMap, key)
		}
	}

	return true
}

// InvalidateExpired removes all expired sessions from the cache
func (c *SessionCache) InvalidateExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for id, entry := range c.sessions {
		if !entry.expiration.IsZero() && now.After(entry.expiration) {
			delete(c.sessions, id)
			count++
		}
	}

	// Clean up command mappings for deleted sessions
	for key, sessID := range c.commandMap {
		if _, ok := c.sessions[sessID]; !ok {
			delete(c.commandMap, key)
		}
	}

	return count
}

// Clear removes all sessions from the cache
func (c *SessionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessions = make(map[string]*SessionEntry)
	c.commandMap = make(map[string]string)
}

// DebugDump returns a human-readable snapshot of the session cache for troubleshooting.
func (c *SessionCache) DebugDump() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var b strings.Builder
	b.WriteString("sessions:\n")
	for id, entry := range c.sessions {
		exp := "never"
		if !entry.expiration.IsZero() {
			exp = entry.expiration.Format(time.RFC3339Nano)
		}
		fmt.Fprintf(&b, "- id=%s addr=%s tag=%s lease=%s exp=%s\n", id, entry.addr, entry.tag, entry.lease, exp)
	}

	b.WriteString("command_map:\n")
	for key, sid := range c.commandMap {
		fmt.Fprintf(&b, "- %s -> %s\n", key, sid)
	}

	return b.String()
}

// Size returns the number of sessions in the cache
func (c *SessionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

// GenerateSessionID generates a unique session ID
// Format: hostname:pid:timestamp:counter
func GenerateSessionID(counter int) string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	pid := os.Getpid()
	timestamp := time.Now().Unix()

	return fmt.Sprintf("%s:%d:%d:%d", hostname, pid, timestamp, counter)
}
