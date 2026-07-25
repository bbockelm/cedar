package security

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// MintInheritableSession mints a standalone, non-negotiated security session for a child
// process to inherit, registers it in the process-global session cache (which the local
// server resumes connections from), and returns the session id plus the CONDOR_PRIVATE_INHERIT
// token to place in the child's environment.
//
// The child imports the token via GetSessionCache()/GetParentSessionID() and resumes the
// session (SecurityConfig.SessionID) instead of running an authentication handshake; the local
// server accepts it from the global cache and maps it to the identity condor@parent.
//
// The session is:
//   - a normal (condor@parent) session, deliberately DISTINCT from any inherited family
//     (condor@family) session, so a child gets its own dedicated credential rather than the
//     daemon's family key;
//   - NOT persisted (SetInherited: re-minted on each launch, never written to a session file);
//   - NON-expiring (no SessionExpires): it lives as long as the child, since the parent supervises
//     the child's lifetime.
//
// validCommands scopes the command ids the session may be resumed for (e.g. an htcondordb
// DB-session command). Pass a single command; a claim id cannot carry ',' in some fields, so a
// one-command scope is the safe, common case.
func MintInheritableSession(peerAddr string, validCommands ...int) (sessionID, inheritToken string, err error) {
	key, err := GenerateSecuritySessionKey()
	if err != nil {
		return "", "", fmt.Errorf("mint session: generating key: %w", err)
	}
	sessionID = GenerateSessionID(GetNextSessionCounter())

	policy := classad.New()
	_ = policy.Set("Encryption", "YES")
	_ = policy.Set("Integrity", "YES")
	_ = policy.Set("CryptoMethods", "AES") // cedar keys sessions on AES-GCM
	if len(validCommands) > 0 {
		cmds := make([]string, len(validCommands))
		for i, c := range validCommands {
			cmds[i] = strconv.Itoa(c)
		}
		_ = policy.Set("ValidCommands", strings.Join(cmds, ","))
	}
	// No SessionExpires -> the session never auto-expires.
	sessionInfo, err := ExportSecSessionInfo(policy)
	if err != nil {
		return "", "", fmt.Errorf("mint session: exporting session info: %w", err)
	}

	entry, err := CreateNonNegotiatedSession(&InheritedSession{
		Type:        SessionTypeNormal,
		SessionID:   sessionID,
		SessionInfo: sessionInfo,
		SessionKey:  key,
	}, peerAddr)
	if err != nil {
		return "", "", fmt.Errorf("mint session: %w", err)
	}
	entry.SetInherited(true) // never persist; re-minted each child launch

	cache := GetSessionCache()
	cache.Store(entry)
	// Map the command(s) to this session on the peer address so a server-side command_map
	// lookup can also resume it (the child resumes by explicit SessionID, but this makes the
	// mapping symmetric with an inherited family session).
	for _, c := range validCommands {
		cache.MapCommand("", peerAddr, strconv.Itoa(c), sessionID)
	}

	inheritToken = "SessionKey:" + ExportClaimID(sessionID, sessionInfo, key)
	return sessionID, inheritToken, nil
}
