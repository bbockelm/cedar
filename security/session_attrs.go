package security

import (
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// Application session attributes: how a protocol layered on top of cedar tells
// its peer, once per session, what it can do.
//
// The problem they exist for is capability discovery. A client that cannot ask
// the server what it supports has to find out by trying: issue the new request,
// recognise the "I don't know that" rejection, and reissue the old one. That
// works, but it puts a fallback path behind every feature, each reachable only
// against a peer old enough to refuse -- so the paths that matter most are the
// ones a current test deployment cannot reach at all, and they rot unnoticed.
//
// These attributes move the answer into the handshake, where it costs no round
// trip: the server advertises them in its post-authentication ad, the client
// captures the ones it asked for by name, and both sides keep them with the
// cached session so a RESUMED session answers the same way a fresh one does.
// Without that last part they would be worth little: all but the first
// connection to a peer resumes, and a resumed session exchanges no post-auth ad.
//
// Two properties are worth knowing before relying on them.
//
// A peer that sets none is indistinguishable from a peer too old to set any.
// Both arrive as an absent attribute, so absence must mean "assume the oldest
// behaviour", never "assume the newest".
//
// A cached session outlives the advertisement that filled it. Sessions persist
// across a daemon restart (SEC_PERSIST_SESSIONS), so a client can hold a
// session whose attributes predate a server UPGRADE and keep reading the older
// answer until that session expires. This is safe only because it errs toward
// the older behaviour; a capability that is unsafe to under-claim does not
// belong here.

// reservedSessionAttrs are the handshake's own attribute names. An application
// may not advertise these: the security layer and the peers that read it
// (including C++ HTCondor's SECMAN) assign them meaning, and letting an
// application set them would let it rewrite the session's identity or
// authorization rather than describe its own protocol.
var reservedSessionAttrs = map[string]bool{
	"authcommand": true, "authmethods": true, "authentication": true,
	"command": true, "cryptomethods": true, "ecdhpublickey": true,
	"enact": true, "encryption": true, "errorstring": true, "integrity": true,
	"negotiatedsession": true, "newsession": true, "nonce": true,
	"outgoingnegotiation": true, "remoteversion": true, "returncode": true,
	"serverpid": true, "sessionduration": true, "sessionlease": true,
	"sid": true, "subsystem": true, "triedauthentication": true,
	"trustdomain": true, "user": true, "validcommands": true,
	strings.ToLower(AttrLimitAuthorization): true,
}

// ReservedSessionAttr reports whether name is one the handshake owns, and so
// cannot be used for an application attribute. Names are compared without
// regard to case, as ClassAd attribute names are.
func ReservedSessionAttr(name string) bool {
	return reservedSessionAttrs[strings.ToLower(name)]
}

// sortedAttrNames returns attrs' names in a stable order, so a handshake ad and
// a session policy are byte-identical for identical input -- worth having when
// comparing two captures in a test or a log.
func sortedAttrNames(attrs map[string]string) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// setSessionAttrs writes an application's attributes into an outgoing ad,
// skipping any name the handshake reserves. Values are written as strings: a
// peer may be C++ or an older Go build, and a string reads back the same way
// everywhere, where an integer's type survives only if both ends agree.
func setSessionAttrs(ad *classad.ClassAd, attrs map[string]string) {
	if ad == nil {
		return
	}
	for _, name := range sortedAttrNames(attrs) {
		if ReservedSessionAttr(name) {
			continue
		}
		_ = ad.Set(name, attrs[name])
	}
}

// captureSessionAttrs reads the attributes named in want out of a peer's ad.
//
// Capture is by name rather than "everything unrecognised" on purpose. The ad
// may come from a C++ peer, or from a newer cedar, and carry attributes this
// build has no meaning for; collecting those and handing them to the
// application as its own would turn an unrelated handshake attribute into a
// capability claim. An attribute that is absent is simply not in the result,
// which is how a caller tells "the peer said nothing" from "the peer said no".
func captureSessionAttrs(ad *classad.ClassAd, want []string) map[string]string {
	if ad == nil || len(want) == 0 {
		return nil
	}
	var out map[string]string
	for _, name := range want {
		if ReservedSessionAttr(name) {
			continue
		}
		v, ok := ad.EvaluateAttrString(name)
		if !ok {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(want))
		}
		out[name] = v
	}
	return out
}

// storeSessionAttrs keeps an application's attributes with the cached session,
// so resuming it restores what the post-auth ad said. The policy ad is already
// what both sides persist and reload, so the attributes travel with the session
// across a restart exactly as the identity and authorization bounds do.
func storeSessionAttrs(policy *classad.ClassAd, attrs map[string]string) {
	setSessionAttrs(policy, attrs)
}

// sessionAttrsFromPolicy restores the attributes named in want from a resumed
// session's policy ad. It is captureSessionAttrs against the cache rather than
// the wire, and returns nil for a session cached before the application asked
// for any -- which reads, correctly, as a peer that advertised nothing.
func sessionAttrsFromPolicy(policy *classad.ClassAd, want []string) map[string]string {
	return captureSessionAttrs(policy, want)
}
