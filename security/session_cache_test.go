package security

import (
	"fmt"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

func TestSessionCacheBasic(t *testing.T) {
	cache := NewSessionCache()

	// Create a test session
	keyInfo := &KeyInfo{
		Data:     []byte("test-key-data"),
		Protocol: "AESGCM",
	}

	policy := classad.New()
	_ = policy.Set("SecAuthentication", "REQUIRED")

	expiration := time.Now().Add(1 * time.Hour)
	entry := NewSessionEntry("test-session-1", "192.168.1.1:1234", keyInfo, policy, expiration, 30*time.Minute, "test-tag")

	// Store the session
	cache.Store(entry)

	// Verify size
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Lookup the session
	retrieved, ok := cache.Lookup("test-session-1")
	if !ok {
		t.Fatal("Failed to lookup stored session")
	}

	if retrieved.ID() != "test-session-1" {
		t.Errorf("Expected session ID 'test-session-1', got '%s'", retrieved.ID())
	}

	if retrieved.Addr() != "192.168.1.1:1234" {
		t.Errorf("Expected address '192.168.1.1:1234', got '%s'", retrieved.Addr())
	}

	if string(retrieved.KeyInfo().Data) != "test-key-data" {
		t.Errorf("Expected key data 'test-key-data', got '%s'", string(retrieved.KeyInfo().Data))
	}
}

func TestSessionCacheExpiration(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()

	// Create expired session
	expiration := time.Now().Add(-1 * time.Hour) // Already expired
	entry := NewSessionEntry("expired-session", "192.168.1.1:1234", keyInfo, policy, expiration, 30*time.Minute, "")

	cache.Store(entry)

	// Try to lookup expired session
	_, ok := cache.Lookup("expired-session")
	if ok {
		t.Error("Expected expired session to not be found")
	}

	// Verify it wasn't removed yet from the cache (only marked as expired)
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1 before cleanup, got %d", cache.Size())
	}

	// Use LookupNonExpired which should remove it
	_, ok = cache.LookupNonExpired("expired-session")
	if ok {
		t.Error("Expected expired session to not be found with LookupNonExpired")
	}

	// Now it should be removed
	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after LookupNonExpired, got %d", cache.Size())
	}
}

func TestSessionCacheLeaseRenewal(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()

	// Create session with short expiration but renewable lease
	expiration := time.Now().Add(1 * time.Second)
	lease := 1 * time.Hour
	entry := NewSessionEntry("renewable-session", "192.168.1.1:1234", keyInfo, policy, expiration, lease, "")

	cache.Store(entry)

	// Wait for it to almost expire
	time.Sleep(1100 * time.Millisecond)

	// Lookup and renew
	_, ok := cache.LookupNonExpired("renewable-session")
	if ok {
		t.Error("Session should have expired before renewal")
	}

	// Create new entry with renewable lease
	expiration = time.Now().Add(100 * time.Millisecond)
	entry = NewSessionEntry("renewable-session-2", "192.168.1.1:1234", keyInfo, policy, expiration, lease, "")
	cache.Store(entry)

	// Renew before expiration
	retrieved, ok := cache.Lookup("renewable-session-2")
	if !ok {
		t.Fatal("Failed to lookup session before expiration")
	}

	retrieved.RenewLease()
	cache.Store(retrieved) // Update the cache

	// Wait past original expiration
	time.Sleep(150 * time.Millisecond)

	// Should still be valid due to renewal
	_, ok = cache.Lookup("renewable-session-2")
	if !ok {
		t.Error("Expected renewed session to still be valid")
	}
}

func TestSessionCacheCommandMapping(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()
	expiration := time.Now().Add(1 * time.Hour)
	entry := NewSessionEntry("mapped-session", "192.168.1.1:1234", keyInfo, policy, expiration, 30*time.Minute, "test-tag")

	cache.Store(entry)

	// Map commands to this session
	cache.MapCommand("test-tag", "192.168.1.1:1234", "DC_NOP", "mapped-session")
	cache.MapCommand("test-tag", "192.168.1.1:1234", "QUERY_STARTD_ADS", "mapped-session")

	// Lookup by command
	retrieved, ok := cache.LookupByCommand("test-tag", "192.168.1.1:1234", "DC_NOP")
	if !ok {
		t.Fatal("Failed to lookup session by command")
	}

	if retrieved.ID() != "mapped-session" {
		t.Errorf("Expected session ID 'mapped-session', got '%s'", retrieved.ID())
	}

	// Try another command
	retrieved, ok = cache.LookupByCommand("test-tag", "192.168.1.1:1234", "QUERY_STARTD_ADS")
	if !ok {
		t.Fatal("Failed to lookup session by second command")
	}

	if retrieved.ID() != "mapped-session" {
		t.Errorf("Expected session ID 'mapped-session', got '%s'", retrieved.ID())
	}

	// Try unmapped command
	_, ok = cache.LookupByCommand("test-tag", "192.168.1.1:1234", "UNKNOWN_CMD")
	if ok {
		t.Error("Expected lookup of unmapped command to fail")
	}
}

func TestSessionCacheInvalidate(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()
	expiration := time.Now().Add(1 * time.Hour)
	entry := NewSessionEntry("invalidate-session", "192.168.1.1:1234", keyInfo, policy, expiration, 30*time.Minute, "")

	cache.Store(entry)

	// Map a command to it
	cache.MapCommand("", "192.168.1.1:1234", "DC_NOP", "invalidate-session")

	// Verify it exists
	if cache.Size() != 1 {
		t.Errorf("Expected cache size 1, got %d", cache.Size())
	}

	// Invalidate
	ok := cache.Invalidate("invalidate-session")
	if !ok {
		t.Error("Expected invalidation to succeed")
	}

	// Verify it's gone
	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after invalidation, got %d", cache.Size())
	}

	// Verify command mapping is also gone
	_, ok = cache.LookupByCommand("", "192.168.1.1:1234", "DC_NOP")
	if ok {
		t.Error("Expected command mapping to be removed after invalidation")
	}

	// Try to invalidate non-existent session
	ok = cache.Invalidate("non-existent")
	if ok {
		t.Error("Expected invalidation of non-existent session to fail")
	}
}

func TestSessionCacheClear(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()
	expiration := time.Now().Add(1 * time.Hour)

	// Add multiple sessions
	for i := 0; i < 5; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		entry := NewSessionEntry(sessionID, "192.168.1.1:1234", keyInfo, policy, expiration, 30*time.Minute, "")
		cache.Store(entry)
	}

	if cache.Size() != 5 {
		t.Errorf("Expected cache size 5, got %d", cache.Size())
	}

	// Clear the cache
	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Size())
	}
}

func TestSessionCacheInvalidateExpired(t *testing.T) {
	cache := NewSessionCache()

	keyInfo := &KeyInfo{
		Data:     []byte("test-key"),
		Protocol: "AESGCM",
	}

	policy := classad.New()

	// Add mix of expired and valid sessions
	expiredExpiration := time.Now().Add(-1 * time.Hour)
	validExpiration := time.Now().Add(1 * time.Hour)

	cache.Store(NewSessionEntry("expired-1", "192.168.1.1:1234", keyInfo, policy, expiredExpiration, 30*time.Minute, ""))
	cache.Store(NewSessionEntry("valid-1", "192.168.1.1:1234", keyInfo, policy, validExpiration, 30*time.Minute, ""))
	cache.Store(NewSessionEntry("expired-2", "192.168.1.1:1234", keyInfo, policy, expiredExpiration, 30*time.Minute, ""))
	cache.Store(NewSessionEntry("valid-2", "192.168.1.1:1234", keyInfo, policy, validExpiration, 30*time.Minute, ""))

	if cache.Size() != 4 {
		t.Errorf("Expected cache size 4, got %d", cache.Size())
	}

	// Invalidate expired sessions
	count := cache.InvalidateExpired()

	if count != 2 {
		t.Errorf("Expected 2 expired sessions to be removed, got %d", count)
	}

	if cache.Size() != 2 {
		t.Errorf("Expected cache size 2 after removing expired, got %d", cache.Size())
	}

	// Verify the valid sessions remain
	_, ok := cache.Lookup("valid-1")
	if !ok {
		t.Error("Expected valid-1 to still exist")
	}

	_, ok = cache.Lookup("valid-2")
	if !ok {
		t.Error("Expected valid-2 to still exist")
	}
}

func TestGenerateSessionID(t *testing.T) {
	// Generate a few session IDs
	id1 := GenerateSessionID(1)
	id2 := GenerateSessionID(2)

	// IDs should be unique
	if id1 == id2 {
		t.Error("Expected different session IDs")
	}

	// IDs should have the expected format: hostname:pid:timestamp:counter
	if len(id1) == 0 {
		t.Error("Expected non-empty session ID")
	}

	t.Logf("Generated session ID: %s", id1)
	t.Logf("Generated session ID: %s", id2)
}
