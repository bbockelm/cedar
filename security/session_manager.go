package security

import (
	"log/slog"
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

// GetSessionCache returns the global session cache, initializing it if necessary.
// On first access, this also imports any inherited sessions from the parent daemon
// (via CONDOR_PRIVATE_INHERIT environment variable).
func GetSessionCache() *SessionCache {
	sessionCacheMutex.Do(func() {
		globalSessionCache = NewSessionCache()

		// Automatically import inherited sessions from parent daemon
		// This is similar to what SecMan does in HTCondor when started as a child process
		if count, err := registerInheritedSessions(globalSessionCache); err != nil {
			slog.Warn("Failed to import inherited sessions", "error", err)
		} else if count > 0 {
			slog.Info("Imported inherited sessions from parent daemon", "count", count)
		}
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
