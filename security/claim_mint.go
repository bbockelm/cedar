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

// This file implements the startd side of "match password" security sessions:
// MINTING a claim id.  It is the mirror image of claim_session.go, which
// implements the schedd/shadow side (ImportClaimSession).  Where the import
// path PARSES a claim id handed out by a startd and re-derives the pre-shared
// session it embeds, this file GENERATES that claim id and registers the same
// session on the startd end so both peers can talk over it without a fresh
// DC_AUTHENTICATE handshake.
//
// The C++ ground truth for this file lives in:
//   - src/condor_startd.V6/claim.cpp
//       (newIdString + ClaimId ctor: mint the id with a random hex key, create
//        the non-negotiated session with SUBMIT_SIDE_MATCHSESSION_FQU, then
//        rewrite the id to embed the exported session_info)
//   - src/condor_io/condor_secman.cpp
//       (SecMan::CreateNonNegotiatedSecuritySession, SecMan::ExportSecSessionInfo)
//   - src/condor_io/condor_crypt.cpp
//       (Condor_Crypt_Base::randomHexKey -- the key is randomKey(N) rendered as
//        2N lowercase hex chars)
//   - src/condor_includes/condor_secman.h
//       (SEC_SESSION_KEY_LENGTH_V9 == 32: the byte length fed to randomHexKey
//        for CONDOR_AESGCM, i.e. a 64-hex-character session key)
//   - src/condor_utils/condor_claimid_parser.h
//       (claim id grammar; the ClaimIdParser this file's output must round-trip)

package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// secSessionKeyLengthV9 is the number of random bytes a modern startd feeds to
// randomHexKey when minting an AES-GCM claim session (SEC_SESSION_KEY_LENGTH_V9
// in src/condor_includes/condor_secman.h).  The secret embedded in the claim id
// is therefore this many bytes rendered as 2x lowercase hex characters (64).
const secSessionKeyLengthV9 = 32

// randomHexKey generates a claim-session secret exactly as
// Condor_Crypt_Base::randomHexKey does: nbytes of CSPRNG output rendered as
// 2*nbytes lowercase hex characters.  The result contains no '#' or ']', so it
// is a legal trailing session key in a claim id.
func randomHexKey(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random claim key: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ExportSecSessionInfo renders a session policy into the bracketed session_info
// blob embedded in a claim id, mirroring SecMan::ExportSecSessionInfo.  It is
// the exact inverse of ImportSecSessionInfo: only the trusted, claim-id-safe
// attributes are exported, and
//
//   - CryptoMethods with more than one method (comma-separated) is split into a
//     single preferred method (the first) plus a '.'-delimited CryptoMethodsList
//     (',' is not a legal character inside a claim id).  A single method is
//     emitted verbatim as CryptoMethods.
//   - RemoteVersion (a full "$CondorVersion$" string) is emitted as the compact
//     ShortVersion (e.g. "25.4.0") so its spaces do not break claim-id parsing.
//
// Attributes are emitted in sorted (alphabetical) order, matching the iteration
// order of a C++ ClassAd, so a minted blob is byte-identical to what a C++
// startd of the same configuration would produce.  String values are quoted and
// integer values (SessionExpires) are bare, matching ExprTreeToString.  The
// result is always bracketed; passing a policy with none of the exported
// attributes yields "[]".
//
// Round-trip guarantee: ImportSecSessionInfo(ExportSecSessionInfo(p)) reproduces
// the crypto/encryption/integrity/expiry/commands policy carried by p.
func ExportSecSessionInfo(policy *classad.ClassAd) (string, error) {
	if policy == nil {
		return "", fmt.Errorf("nil policy")
	}

	// Collect exported attributes in a name->rendered-value map, then emit them
	// in sorted order for a deterministic, C++-compatible wire form.
	out := make(map[string]string)

	// Straight string copies (quoted on the wire).
	for _, name := range []string{"Integrity", "Encryption", "ValidCommands"} {
		if v, ok := policy.EvaluateAttrString(name); ok && v != "" {
			out[name] = quote(v)
		}
	}

	// SessionExpires is an integer (an absolute unix time); emit it bare.  Accept
	// either a native integer or a string-typed value in the source policy.
	if v, ok := policy.EvaluateAttrInt("SessionExpires"); ok {
		if v != 0 {
			out["SessionExpires"] = strconv.FormatInt(v, 10)
		}
	} else if s, ok := policy.EvaluateAttrString("SessionExpires"); ok && s != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && n != 0 {
			out["SessionExpires"] = strconv.FormatInt(n, 10)
		}
	}

	// CryptoMethods: split a multi-method list into preferred + CryptoMethodsList
	// (dot-delimited) exactly as C++ does, because ',' cannot appear in a claim
	// id.  A single method is emitted as-is.
	if cm, ok := policy.EvaluateAttrString("CryptoMethods"); ok && cm != "" {
		if strings.Contains(cm, ",") {
			methods := strings.Split(cm, ",")
			out["CryptoMethods"] = quote(strings.TrimSpace(methods[0]))
			out["CryptoMethodsList"] = quote(strings.ReplaceAll(cm, ",", "."))
		} else {
			out["CryptoMethods"] = quote(cm)
		}
	}

	// RemoteVersion -> ShortVersion (numeric-only so it survives claim-id parsing).
	if rv, ok := policy.EvaluateAttrString("RemoteVersion"); ok && rv != "" {
		out["ShortVersion"] = quote(shortVersion(rv))
	}

	names := make([]string, 0, len(out))
	for name := range out {
		names = append(names, name)
	}
	sortStrings(names)

	var b strings.Builder
	b.WriteByte('[')
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(out[name])
		b.WriteByte(';')
	}
	b.WriteByte(']')

	info := b.String()
	if strings.Contains(info, "#") {
		return "", fmt.Errorf("exported session info contains '#', which is illegal in a claim id: %q", info)
	}
	return info, nil
}

// quote wraps a value in double quotes, matching ExprTreeToString's rendering of
// a ClassAd string literal.
func quote(v string) string { return `"` + v + `"` }

// shortVersion extracts the compact "maj.min.sub" form from a version string.
// A full HTCondor version is like "$CondorVersion: 25.4.0 ...$"; the exported
// ShortVersion must be numeric-only (no spaces) or it breaks claim-id parsing.
// If the input already looks compact (no spaces) it is returned unchanged.
func shortVersion(full string) string {
	if !strings.ContainsAny(full, " $") {
		return full
	}
	for _, tok := range strings.Fields(full) {
		// The first token containing a '.' and starting with a digit is the
		// numeric version (e.g. "25.4.0").
		if strings.Contains(tok, ".") && len(tok) > 0 && tok[0] >= '0' && tok[0] <= '9' {
			// Trim any trailing punctuation.
			return strings.TrimRight(tok, ";,")
		}
	}
	return full
}

// sortStrings sorts a slice of strings in place (avoids importing sort for a
// single call; the slices are tiny).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// MintClaimOptions configures how a startd mints a claim id and registers the
// pre-shared security session it embeds.  The zero value (apart from the
// required Sinful field) produces a stock modern-HTCondor claim: AES-GCM,
// encryption and integrity on, DAEMON auth level.
type MintClaimOptions struct {
	// Sinful is the startd's advertised address, the full bracketed sinful
	// string (e.g. "<127.0.0.1:9618?addrs=...&noUDP&sock=startd_1234_abcd>").
	// It may itself contain '#'; parsers scan to the first '>' to recover it.
	// It becomes the leading component of the claim id.  Required.
	Sinful string

	// Birthdate is the startd's startup time (unix seconds), the second
	// component of the claim id (startd_bday).
	Birthdate int64

	// SequenceNum is the per-startd monotonically increasing claim counter, the
	// third component of the claim id.
	SequenceNum int

	// PeerFQU is the identity the startd attributes to whoever presents this
	// claim (the schedd).  Defaults to SubmitSideMatchSessionFQU when empty,
	// matching SUBMIT_SIDE_MATCHSESSION_FQU in claim.cpp.
	PeerFQU string

	// PeerAddr, when non-empty, installs command_map entries so an OUTBOUND dial
	// from the startd to that address (e.g. SendAlive to the schedd) resumes this
	// session by command.  A stock startd leaves this empty at mint time (C++
	// passes peer_sinful=NULL): the schedd resumes INBOUND by naming the session
	// id explicitly, and command mappings are added later once the peer address
	// is known.
	PeerAddr string

	// Encryption toggles on-the-wire encryption in the exported policy.  Nil
	// means the default (on).  Point it at a false value to mint an
	// integrity-only or plaintext session.
	Encryption *bool

	// Integrity toggles on-the-wire integrity (MAC) in the exported policy.  Nil
	// means the default (on).
	Integrity *bool

	// CryptoMethods is the comma-separated cipher preference list recorded in the
	// session_info (e.g. "AES" or "AES,BLOWFISH").  Defaults to "AES".  cedar can
	// only key sessions on AES/AES-GCM, so the first method must be AES.
	CryptoMethods string

	// RemoteVersion, when set, is exported as ShortVersion so the peer learns the
	// minting daemon's version.  A full "$CondorVersion$" string or a compact
	// "25.4.0" are both accepted.
	RemoteVersion string

	// Lifetime bounds the session's validity.  When > 0 the absolute expiry
	// (now+Lifetime) is both embedded in the session_info as SessionExpires (so
	// the importing peer expires it in lockstep) and applied to the local cache
	// entry.  Zero means the session does not auto-expire.
	Lifetime time.Duration

	// ExtraValidCommands are command integers mapped to this session (in addition
	// to any ValidCommands carried in the policy), used only when PeerAddr is set.
	ExtraValidCommands []int

	// ValidCommands, when non-empty, is exported in the session_info so the
	// importing peer can command-map it.  A stock startd omits this.
	ValidCommands []int

	// Tag is the security context tag used for command_map lookups (usually "").
	Tag string
}

// MintedClaim is the result of MintClaimSession: the freshly generated claim id
// (which carries the secret) plus its derived identifiers.
type MintedClaim struct {
	claimID       string
	publicClaimID string
	sessionID     string
}

// ClaimID returns the full, SECRET claim id, of the form
//
//	<sinful>#startd_bday#sequence_num#[session_info]session_key
//
// This is the capability the startd hands to the negotiator/schedd; anyone who
// holds it can resume the session, so it must be transmitted only over an
// already-secured channel and never logged.
func (m *MintedClaim) ClaimID() string { return m.claimID }

// PublicClaimID returns the claim id with the secret elided, safe for logging
// (ClaimIdParser::publicClaimId): everything up to the last '#', plus "#...".
func (m *MintedClaim) PublicClaimID() string { return m.publicClaimID }

// SessionID returns the security session id embedded in the claim id
// (ClaimIdParser::secSessionId): everything before the last '#'.
func (m *MintedClaim) SessionID() string { return m.sessionID }

// MintClaimSession mints a claim id the way a startd does and registers the
// pre-shared security session it embeds in cache, so the session works in BOTH
// directions without a fresh handshake:
//
//   - Inbound: when the schedd presents this claim id in a DC_AUTHENTICATE
//     resumption request, the startd's server side resumes the session by id.
//   - Outbound: an outbound connect from the startd whose SecurityConfig.SessionID
//     is this session id (or a command MintClaimSession mapped via PeerAddr)
//     resumes the session instead of authenticating (e.g. SendAlive).
//
// It is the mint-side mirror of ImportClaimSession and derives identical key
// material: a random hex secret (SEC_SESSION_KEY_LENGTH_V9 bytes) is embedded in
// the claim id and run through the same HKDF (salt "htcondor", info "keygen",
// 32 bytes for AES-256-GCM) that the importing peer applies, so both ends hold
// the same AES-GCM key.  cedar implements only AES-GCM.
//
// The returned MintedClaim's ClaimID() is the secret capability; the session is
// registered under SessionID().
func MintClaimSession(cache *SessionCache, opts MintClaimOptions) (*MintedClaim, error) {
	if cache == nil {
		return nil, fmt.Errorf("nil session cache")
	}
	if opts.Sinful == "" {
		return nil, fmt.Errorf("MintClaimSession requires a startd sinful address")
	}

	// 1. Build the exported (wire) policy and derive the session_info blob.
	cryptoMethods := opts.CryptoMethods
	if cryptoMethods == "" {
		cryptoMethods = "AES"
	}
	// cedar can only key on AES; reject anything whose preferred method is not
	// AES up front rather than minting a claim no cedar peer can join.
	if first := strings.TrimSpace(strings.Split(cryptoMethods, ",")[0]); first != "AES" && first != "AESGCM" {
		return nil, fmt.Errorf("MintClaimSession: CryptoMethods must list AES first, got %q", cryptoMethods)
	}

	wire := classad.New()
	_ = wire.Set("Encryption", boolYesNo(opts.Encryption))
	_ = wire.Set("Integrity", boolYesNo(opts.Integrity))
	_ = wire.Set("CryptoMethods", cryptoMethods)
	if opts.RemoteVersion != "" {
		_ = wire.Set("RemoteVersion", opts.RemoteVersion)
	}
	if len(opts.ValidCommands) > 0 {
		_ = wire.Set("ValidCommands", joinInts(opts.ValidCommands))
	}
	var expiration time.Time
	if opts.Lifetime > 0 {
		expiration = time.Now().Add(opts.Lifetime)
		_ = wire.Set("SessionExpires", expiration.Unix())
	}

	sessionInfo, err := ExportSecSessionInfo(wire)
	if err != nil {
		return nil, fmt.Errorf("failed to export session info: %w", err)
	}

	// 2. Generate the secret and assemble the claim id.
	secret, err := randomHexKey(secSessionKeyLengthV9)
	if err != nil {
		return nil, err
	}

	sessionID := fmt.Sprintf("%s#%d#%d", opts.Sinful, opts.Birthdate, opts.SequenceNum)
	claimID := fmt.Sprintf("%s#%s%s", sessionID, sessionInfo, secret)

	// 3. Register the pre-shared session, mirroring ImportClaimSession's setup so
	// the mint and import sides converge on identical policy + key material.  The
	// only difference is who generated the secret and the default peer identity.
	peerFQU := opts.PeerFQU
	if peerFQU == "" {
		peerFQU = SubmitSideMatchSessionFQU
	}

	// Re-import our own session_info so the registered policy is bit-identical to
	// what the importing peer will build from the same blob.
	policy, err := ImportSecSessionInfo(sessionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to re-import minted session info: %w", err)
	}

	keyInfo, err := deriveClaimKeyInfo(policy, secret)
	if err != nil {
		return nil, err
	}

	_ = policy.Set("SecUseSession", "YES")
	_ = policy.Set("Sid", sessionID)
	_ = policy.Set("Enact", "YES")
	_ = policy.Set("NegotiatedSession", false)
	_ = policy.Set("AuthMethods", AuthMethodMatch)
	_ = policy.Set("User", peerFQU)
	// Authenticated by possession of the claim secret (see ImportClaimSession);
	// the minting (startd) side must record it too, or the resumed session it
	// serves REQUEST_CLAIM/ACTIVATE_CLAIM on comes back authenticated=false.
	_ = policy.Set("Authenticated", true)
	_ = policy.Set("CryptoMethods", keyInfo.Protocol)

	entry := NewSessionEntry(sessionID, opts.PeerAddr, keyInfo, policy, claimExpiration(policy, opts.Lifetime), 0, opts.Tag)
	entry.SetInherited(true) // minted at runtime; never persist to disk
	cache.Store(entry)

	mapClaimCommands(cache, policy, sessionID, ClaimSessionOptions{
		PeerAddr:           opts.PeerAddr,
		Tag:                opts.Tag,
		ExtraValidCommands: opts.ExtraValidCommands,
	})

	return &MintedClaim{
		claimID:       claimID,
		publicClaimID: sessionID + "#...",
		sessionID:     sessionID,
	}, nil
}

// boolYesNo renders an optional policy toggle as the "YES"/"NO" strings the
// C++ security policy uses.  A nil pointer means the default, "YES".
func boolYesNo(v *bool) string {
	if v == nil || *v {
		return "YES"
	}
	return "NO"
}

// joinInts renders a slice of command integers as the comma-separated string
// form used for the ValidCommands policy attribute.
func joinInts(vals []int) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}
