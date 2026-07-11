// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file implements claim-id-derived (a.k.a. "match password") security
// sessions.  With SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION (default on in
// modern HTCondor), the claim id handed out by a startd embeds a security
// session: a session id, an exported policy (session_info), and a secret key.
// Every subsequent claim command (REQUEST_CLAIM, ACTIVATE_CLAIM, ALIVE,
// RELEASE_CLAIM, file transfer, ...) rides that pre-shared session in BOTH
// directions rather than performing a fresh DC_AUTHENTICATE handshake.
//
// The C++ ground truth for this file lives in:
//   - src/condor_utils/condor_claimid_parser.h
//       (claim id grammar; secSessionId/secSessionInfo/secSessionKey)
//   - src/condor_io/condor_secman.cpp
//       (SecMan::ImportSecSessionInfo, CreateNonNegotiatedSecuritySession,
//        ExportSecSessionInfo)
//   - src/condor_startd.V6/claim.cpp, src/condor_schedd.V6/schedd.cpp
//       (how each side registers the same session symmetrically)
//   - src/condor_shadow.V6.1/remoteresource.cpp
//       (the derived "filetrans." file-transfer session)

package security

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// Match-session identities and auth method, mirroring the constants in
// src/condor_io/authentication.cpp.  When a startd hands out a claim it
// registers the session tagged with the SUBMIT side identity (the peer it
// expects to talk to is the schedd), and the schedd registers the mirror-image
// session tagged with the EXECUTE side identity (its peer is the startd).  A
// Go schedd importing a startd claim therefore attributes the peer as
// execute-side@matchsession, exactly matching what the startd sees on its end.
const (
	// SubmitSideMatchSessionFQU is the identity a startd attributes to the
	// schedd over a claim session.
	SubmitSideMatchSessionFQU = "submit-side@matchsession"
	// ExecuteSideMatchSessionFQU is the identity a schedd attributes to the
	// startd over a claim session.
	ExecuteSideMatchSessionFQU = "execute-side@matchsession"
	// NegotiatorSideMatchSessionFQU is the identity used for negotiator claim
	// sessions.
	NegotiatorSideMatchSessionFQU = "negotiator-side@matchsession"
	// AuthMethodMatch is the authentication method recorded on a claim session
	// (AUTH_METHOD_MATCH in C++).
	AuthMethodMatch = "MATCH"

	// fileTransferSessionPrefix is prepended to a claim's session id to derive
	// the separate file-transfer session id (remoteresource.cpp).
	fileTransferSessionPrefix = "filetrans."
)

// ParseClaimIDStrict parses a claim id using the exact semantics of HTCondor's
// ClaimIdParser (src/condor_utils/condor_claimid_parser.h), which differ from
// the more permissive ParseClaimID used by the CONDOR_INHERIT path.
//
// A startd claim id has the form
//
//	<sinful>#startd_bday#sequence_num#[session_info]session_key
//
// where the session id itself contains '#'.  The C++ parser therefore splits
// on the LAST '#':
//
//   - secSessionInfo() is the "[...]" block, present only when the character
//     immediately after the last '#' is '['.
//   - secSessionId() is everything before the last '#' (but only when session
//     info is present; otherwise there is no security session).
//   - secSessionKey() is everything after the trailing ']' (or after the last
//     '#' when there is no session info).
//
// ParseClaimID's SplitN-on-first-'#' approach cannot represent a session id
// containing '#', so it is unsuitable for real startd claim ids; hence this
// dedicated, C++-faithful parser.
func ParseClaimIDStrict(claimID string) *ClaimID {
	c := &ClaimID{raw: claimID}

	lastHash := strings.LastIndex(claimID, "#")
	if lastHash < 0 {
		return c
	}
	afterHash := claimID[lastHash+1:]

	if strings.HasPrefix(afterHash, "[") {
		if lastBracket := strings.LastIndex(claimID, "]"); lastBracket > lastHash {
			c.sessionID = claimID[:lastHash]
			c.sessionInfo = claimID[lastHash+1 : lastBracket+1]
			c.sessionKey = claimID[lastBracket+1:]
			return c
		}
	}

	// No session info: C++ secSessionId() reports "" (no security session), but
	// secSessionKey() still returns everything after the last '#'.  Leaving
	// sessionInfo empty makes SecSessionID() return "" to match.
	c.sessionKey = afterHash
	return c
}

// ImportSecSessionInfo parses the bracketed session_info string carried in a
// claim id (e.g. `[Encryption="YES";Integrity="YES";CryptoMethods="AES";
// SessionExpires=1700000000;ValidCommands="443,444";]`) into a policy ClassAd.
//
// It mirrors SecMan::ImportSecSessionInfo: only a specific, trusted set of
// attributes is copied over (Integrity, Encryption, CryptoMethods,
// SessionExpires, ValidCommands), a present CryptoMethodsList overrides
// CryptoMethods, the '.'-delimited crypto list is converted back to ','
// (because ',' is not permitted inside a claim id), and ShortVersion is mapped
// to RemoteVersion.
//
// An empty string yields an empty policy (no session info was exported); a
// non-empty string that is not bracketed is an error.
func ImportSecSessionInfo(sessionInfo string) (*classad.ClassAd, error) {
	policy := classad.New()

	if sessionInfo == "" {
		return policy, nil
	}
	if !strings.HasPrefix(sessionInfo, "[") || !strings.HasSuffix(sessionInfo, "]") {
		return nil, fmt.Errorf("invalid session info (must be bracketed): %q", sessionInfo)
	}

	attrs, err := ImportSessionInfoAttributes(sessionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session info attributes: %w", err)
	}

	copyIf := func(name string) {
		if v, ok := attrs[name]; ok {
			_ = policy.Set(name, v)
		}
	}
	copyIf("Integrity")
	copyIf("Encryption")
	copyIf("CryptoMethods")
	copyIf("SessionExpires")
	copyIf("ValidCommands")

	// A present CryptoMethodsList overrides CryptoMethods (ImportSecSessionInfo).
	// The list uses '.' as the delimiter inside a claim id; restore ','.
	if list, ok := attrs["CryptoMethodsList"]; ok && list != "" {
		_ = policy.Set("CryptoMethods", strings.ReplaceAll(list, ".", ","))
	} else if cm, ok := attrs["CryptoMethods"]; ok {
		_ = policy.Set("CryptoMethods", strings.ReplaceAll(cm, ".", ","))
	}

	// ShortVersion (e.g. "25.4.0") is the peer's version, exported without the
	// spaces of a full $CondorVersion$ string so it survives claim-id parsing.
	if sv, ok := attrs["ShortVersion"]; ok {
		_ = policy.Set("RemoteVersion", sv)
	}

	return policy, nil
}

// ClaimSessionOptions configures how a claim-derived session is registered.
type ClaimSessionOptions struct {
	// PeerAddr is the sinful/address string of the peer this session talks to
	// (for a schedd importing a startd claim, the startd's sinful).  It is
	// stored on the session entry and used as the key for command_map entries
	// so the outbound client can find the session by command.  It should match
	// the address the client will dial.  When empty, no command mappings are
	// created (the session can still be used via SecurityConfig.SessionID).
	PeerAddr string

	// PeerFQU is the authenticated identity attributed to the peer over this
	// session.  Defaults to ExecuteSideMatchSessionFQU (the schedd's view of a
	// startd) when empty.
	PeerFQU string

	// Duration is a fallback session lifetime, used only when the claim's
	// session_info does not carry SessionExpires.  Zero means the session does
	// not auto-expire.
	Duration time.Duration

	// Tag is the security context tag used for command_map lookups (usually "").
	Tag string

	// ExtraValidCommands are command integers to map to this session in
	// addition to any ValidCommands carried in the session_info.  A stock
	// startd claim's exported session_info typically omits ValidCommands (the
	// startd instead names the session explicitly via setSecSessionId when it
	// sends a command), so a caller that wants command_map-based resumption
	// should list the claim commands it will send (REQUEST_CLAIM, ALIVE, ...).
	ExtraValidCommands []int
}

// ImportClaimSession parses a claim id, derives the pre-shared security session
// it embeds exactly as HTCondor's SecMan::CreateNonNegotiatedSecuritySession
// does, and registers it in cache so it works in BOTH directions:
//
//   - Outbound: an outbound connect with SecurityConfig.SessionID set to the
//     returned id (or a command that ImportClaimSession mapped) resumes this
//     session instead of authenticating.
//   - Inbound: the server side resumes this session when the peer presents its
//     id in a DC_AUTHENTICATE resumption request.
//
// It returns the security session id.  The key is derived from the claim
// secret with HKDF (salt "htcondor", info "keygen", 32 bytes) for AES-256-GCM,
// identical to Condor_Crypt_Base::hkdf for CONDOR_AESGCM.  cedar implements
// only AES-GCM, so a claim keyed on any other cipher is rejected.
func ImportClaimSession(cache *SessionCache, claimID string, opts ClaimSessionOptions) (string, error) {
	if cache == nil {
		return "", fmt.Errorf("nil session cache")
	}

	cid := ParseClaimIDStrict(claimID)
	sesid := cid.SecSessionID()
	if sesid == "" {
		return "", fmt.Errorf("claim id carries no security session (no session_info)")
	}
	secret := cid.SecSessionKey()
	if secret == "" {
		return "", fmt.Errorf("claim id carries no session key")
	}

	policy, err := ImportSecSessionInfo(cid.SecSessionInfo())
	if err != nil {
		return "", fmt.Errorf("failed to import session info: %w", err)
	}

	keyInfo, err := deriveClaimKeyInfo(policy, secret)
	if err != nil {
		return "", err
	}

	peerFQU := opts.PeerFQU
	if peerFQU == "" {
		peerFQU = ExecuteSideMatchSessionFQU
	}

	// Finish the policy the way CreateNonNegotiatedSecuritySession does.
	_ = policy.Set("SecUseSession", "YES")
	_ = policy.Set("Sid", sesid)
	_ = policy.Set("Enact", "YES")
	_ = policy.Set("NegotiatedSession", false)
	_ = policy.Set("AuthMethods", AuthMethodMatch)
	_ = policy.Set("User", peerFQU)
	// The session is keyed on AES-GCM (validated above); record it as the
	// negotiated crypto so the resumption path re-applies the AES key.
	_ = policy.Set("CryptoMethods", keyInfo.Protocol)

	expiration := claimExpiration(policy, opts.Duration)

	entry := NewSessionEntry(sesid, opts.PeerAddr, keyInfo, policy, expiration, 0, opts.Tag)
	entry.SetInherited(true) // derived from a claim id at runtime; never persist to disk
	cache.Store(entry)

	mapClaimCommands(cache, policy, sesid, opts)

	return sesid, nil
}

// ImportFileTransferSession registers the separate file-transfer session a
// shadow derives from a claim id (src/condor_shadow.V6.1/remoteresource.cpp).
// The session id is the claim's session id prefixed with "filetrans." and the
// key is the SAME claim secret, but the startd's exported policy is discarded:
// file transfer uses the importer's own WRITE-level policy (encryption and
// integrity on, AES-GCM), which is why it is a distinct session.
//
// It returns the derived file-transfer session id.
func ImportFileTransferSession(cache *SessionCache, claimID string, opts ClaimSessionOptions) (string, error) {
	if cache == nil {
		return "", fmt.Errorf("nil session cache")
	}

	cid := ParseClaimIDStrict(claimID)
	baseID := cid.SecSessionID()
	if baseID == "" {
		return "", fmt.Errorf("claim id carries no security session (no session_info)")
	}
	secret := cid.SecSessionKey()
	if secret == "" {
		return "", fmt.Errorf("claim id carries no session key")
	}

	ftID := fileTransferSessionPrefix + baseID

	key, err := deriveSessionKey(secret, 32)
	if err != nil {
		return "", fmt.Errorf("failed to derive file-transfer session key: %w", err)
	}
	keyInfo := &KeyInfo{Data: key, Protocol: "AESGCM"}

	peerFQU := opts.PeerFQU
	if peerFQU == "" {
		peerFQU = ExecuteSideMatchSessionFQU
	}

	// File transfer uses the importer's own WRITE policy, not the startd's:
	// encryption and integrity on, AES-GCM.
	policy := classad.New()
	_ = policy.Set("SecUseSession", "YES")
	_ = policy.Set("Sid", ftID)
	_ = policy.Set("Enact", "YES")
	_ = policy.Set("NegotiatedSession", false)
	_ = policy.Set("AuthMethods", AuthMethodMatch)
	_ = policy.Set("User", peerFQU)
	_ = policy.Set("Encryption", "YES")
	_ = policy.Set("Integrity", "YES")
	_ = policy.Set("CryptoMethods", "AESGCM")

	var expiration time.Time
	if opts.Duration > 0 {
		expiration = time.Now().Add(opts.Duration)
	}

	entry := NewSessionEntry(ftID, opts.PeerAddr, keyInfo, policy, expiration, 0, opts.Tag)
	entry.SetInherited(true)
	cache.Store(entry)

	mapClaimCommands(cache, policy, ftID, opts)

	return ftID, nil
}

// deriveClaimKeyInfo validates the claim's crypto method and derives the
// AES-256-GCM key from the claim secret.  cedar implements only AES-GCM.
func deriveClaimKeyInfo(policy *classad.ClassAd, secret string) (*KeyInfo, error) {
	cryptoMethod := "AESGCM"
	if cm, ok := policy.EvaluateAttrString("CryptoMethods"); ok && cm != "" {
		if first := strings.TrimSpace(strings.Split(cm, ",")[0]); first != "" {
			cryptoMethod = first
		}
	}
	if cryptoMethod != "AES" && cryptoMethod != "AESGCM" {
		return nil, fmt.Errorf("claim session is keyed on crypto method %q, but cedar only implements AES-GCM; ensure the pool's SEC_*_CRYPTO_METHODS lists AES first", cryptoMethod)
	}

	// AES-GCM: 32-byte key via HKDF (matches Condor_Crypt_Base::hkdf for
	// CONDOR_AESGCM in CreateNonNegotiatedSecuritySession).
	key, err := deriveSessionKey(secret, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive claim session key: %w", err)
	}
	return &KeyInfo{Data: key, Protocol: "AESGCM"}, nil
}

// claimExpiration extracts the session expiration: SessionExpires (an absolute
// unix time) from the imported policy takes precedence, matching C++; otherwise
// the fallback duration is applied (zero = no expiration).
func claimExpiration(policy *classad.ClassAd, fallback time.Duration) time.Time {
	if v, ok := policy.EvaluateAttrString("SessionExpires"); ok {
		if secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && secs > 0 {
			return time.Unix(secs, 0)
		}
	}
	if fallback > 0 {
		return time.Now().Add(fallback)
	}
	return time.Time{}
}

// mapClaimCommands installs command_map entries ({tag,addr,<cmd>} -> sesid) for
// every ValidCommands entry in the policy plus any ExtraValidCommands, so an
// outbound client can find the session by command.  No-op when PeerAddr is
// empty (mirrors CreateNonNegotiatedSecuritySession, which skips command
// mappings without a peer sinful).
func mapClaimCommands(cache *SessionCache, policy *classad.ClassAd, sesid string, opts ClaimSessionOptions) {
	if opts.PeerAddr == "" {
		return
	}

	var cmds []string
	if vc, ok := policy.EvaluateAttrString("ValidCommands"); ok && vc != "" {
		for _, c := range strings.Split(vc, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cmds = append(cmds, c)
			}
		}
	}
	for _, c := range opts.ExtraValidCommands {
		cmds = append(cmds, strconv.Itoa(c))
	}

	for _, c := range cmds {
		cache.MapCommand(opts.Tag, opts.PeerAddr, c, sesid)
	}
}
