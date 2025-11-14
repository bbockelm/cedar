package security

import (
	"sync"
	"sync/atomic"
)

var (
	// globalSessionCache is the package-level session cache, similar to SecMan::session_cache in C++
	globalSessionCache *SessionCache
	sessionCacheMutex  sync.Once
	// sessionCounter is an atomic counter for generating unique session IDs
	sessionCounter uint64
)

// GetSessionCache returns the global session cache, initializing it if necessary
func GetSessionCache() *SessionCache {
	sessionCacheMutex.Do(func() {
		globalSessionCache = NewSessionCache()
	})
	return globalSessionCache
}

// GetNextSessionCounter returns the next session counter value
func GetNextSessionCounter() int {
	return int(atomic.AddUint64(&sessionCounter, 1))
}

// InvalidateSession removes a session from the global cache
func InvalidateSession(sessionID string) bool {
	return GetSessionCache().Invalidate(sessionID)
}

// InvalidateExpiredSessions removes all expired sessions from the global cache
func InvalidateExpiredSessions() int {
	return GetSessionCache().InvalidateExpired()
}

// ClearSessionCache removes all sessions from the global cache
func ClearSessionCache() {
	GetSessionCache().Clear()
}
