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

// clientAuthenticated reports whether a client handshake actually
// authenticated. handleClientAuthentication runs a method only when the
// server enacted authentication (Authentication=YES), and records AuthNone
// when it fell back to an unauthenticated session; otherwise NegotiatedAuth
// still names the method negotiateSecurity picked, which never ran.
func clientAuthenticated(n *SecurityNegotiation) bool {
	return n.ServerConfig != nil && n.ServerConfig.Authentication == "YES" &&
		n.NegotiatedAuth != "" && n.NegotiatedAuth != AuthNone
}

// clientAuthenticatedAttr records, on a session this process negotiated as a
// client, whether it authenticated to the peer. It is deliberately not
// "Authenticated", which records that a peer authenticated to this process
// and is what server-side resumption trusts; a client session must never be
// readable as that.
const clientAuthenticatedAttr = "MyAuthenticated"

// clientSessionAuthenticated reports whether a cached session may be treated
// as authenticated by the client side. A negotiated client session says so
// in clientAuthenticatedAttr. Claim, inherited and minted sessions are
// authenticated by possession of their key on both sides and record
// "Authenticated"; that is honoured only on entries that carry no
// clientAuthenticatedAttr. A session recording neither is unauthenticated.
func clientSessionAuthenticated(entry *SessionEntry) bool {
	pol := entry.Policy()
	if pol == nil {
		return false
	}
	if authed, ok := pol.EvaluateAttrBool(clientAuthenticatedAttr); ok {
		return authed
	}
	authed, _ := pol.EvaluateAttrBool("Authenticated")
	return authed
}

// mayResume reports whether a cached client session meets this config's
// requirements. A session is shared by every config with the same tag, peer
// and command, and those configs need not agree on policy: one negotiated
// under OPTIONAL authentication must not carry a REQUIRED config's command
// unauthenticated, nor an unencrypted one a config that requires encryption.
// A session recorded without an Authenticated outcome counts as
// unauthenticated.
func (c *SecurityConfig) mayResume(entry *SessionEntry) bool {
	if c.Authentication == SecurityRequired && !clientSessionAuthenticated(entry) {
		return false
	}
	if c.Encryption == SecurityRequired || c.Integrity == SecurityRequired {
		ki := entry.KeyInfo()
		if ki == nil || len(ki.Data) == 0 || !isAESGCM(CryptoMethod(ki.Protocol)) {
			return false
		}
	}
	return true
}
