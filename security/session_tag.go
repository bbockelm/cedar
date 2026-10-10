package security

import (
	"crypto/sha256"
	"encoding/hex"
)

// tokenSessionTagPrefix marks a client session tag derived from a token
// rather than chosen by the caller.
const tokenSessionTagPrefix = "token-sha256:"

// clientSessionTag returns the tag under which this config's client sessions
// are stored in, and looked up from, the session cache.
//
// An explicit SecurityTag is used as given. Otherwise a config carrying a
// Token is tagged with the token's SHA-256 digest: such a config acts for
// whoever holds the token, and an untagged slot is shared with every other
// untagged config in the process -- including the daemon's own connections
// and the sessions it inherits from its parent -- so each side would resume
// sessions the other authenticated. Configs with neither keep the untagged
// slot.
func (c *SecurityConfig) clientSessionTag() string {
	if c.SecurityTag != "" {
		return c.SecurityTag
	}
	if c.Token != "" {
		sum := sha256.Sum256([]byte(c.Token))
		return tokenSessionTagPrefix + hex.EncodeToString(sum[:])
	}
	return ""
}
