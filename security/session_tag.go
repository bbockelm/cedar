package security

import (
	"crypto/sha256"
	"encoding/hex"
)

// tokenSessionTagPrefix marks a client session tag derived from a token
// rather than chosen by the caller.
const tokenSessionTagPrefix = "token-sha256:"

// clientSessionTag returns the tag under which this config's client sessions
// are stored in, and looked up from, cache.
//
// An explicit SecurityTag is used as given. Otherwise a config carrying a
// Token that uses the process-global cache is tagged with the token's SHA-256
// digest: such a config acts for whoever holds the token, and the global
// cache's untagged slot belongs to every untagged config in the process --
// the daemon's own connections and the sessions it inherits from its parent
// among them -- so each side would resume sessions the other authenticated.
// A cache the caller supplied is the caller's partition, and its untagged
// slot is left to the caller. Configs with neither keep the untagged slot.
func (c *SecurityConfig) clientSessionTag(cache *SessionCache) string {
	if c.SecurityTag != "" {
		return c.SecurityTag
	}
	if c.Token != "" && cache == GetSessionCache() {
		sum := sha256.Sum256([]byte(c.Token))
		return tokenSessionTagPrefix + hex.EncodeToString(sum[:])
	}
	return ""
}
