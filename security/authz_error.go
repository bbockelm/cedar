package security

import (
	"fmt"
	"strings"
)

// AuthorizationError reports a command the peer refused after the security
// handshake had already succeeded.
//
// It exists because the two failures look alike from the outside and are fixed
// in completely different places. An authentication failure means the peer could
// not tell who we are: the fix is a credential -- a token, a certificate, a
// mapfile entry. An authorization failure means it knows exactly who we are and
// will not let that identity run this command: the fix is the peer's ALLOW_*
// policy for the command's authorization level. Reporting the second as
// "authentication failed: DENIED" sends an operator to look at the wrong half of
// their configuration, with no clue about which identity was rejected -- even
// though the peer said so in the same ClassAd that carried the refusal.
//
// HTCondor's daemon core builds that reply under the comment "what happened with
// command authorization?", and fills in the authenticated user, whether it
// authenticated at all, and the commands the session may use. All of it is
// repeated here, because each one answers a different question an operator would
// otherwise have to guess at.
type AuthorizationError struct {
	// ReturnCode is the peer's verdict, verbatim: DENIED when the identity
	// is not permitted to run the command, CMD_NOT_FOUND when the peer has
	// no handler for it at all.
	ReturnCode string

	// Command is the command number we asked to run.
	Command int

	// Peer is the address we were talking to, when known.
	Peer string

	// User is the identity the peer says it authenticated us as. Empty, or
	// an unmapped placeholder, when the peer did not authenticate us --
	// which is itself the usual cause of a denial, since an unauthenticated
	// session lands in whatever the peer allows anonymously.
	User string

	// Method is the authentication method that was negotiated, and
	// Encrypted whether the session was encrypted.
	Method    string
	Encrypted bool

	// TriedAuthentication is the peer's own report of whether it attempted
	// to authenticate us; TriedAuthKnown records whether it said so at all,
	// since a peer that omits the attribute is different from one that
	// reports false.
	TriedAuthentication bool
	TriedAuthKnown      bool

	// ValidCommands is the peer's ValidCommands attribute: the commands a
	// reused session would cover, which HTCondor builds from the command's
	// authorization level rather than from what this identity may run. The
	// refused command is normally in it, so it does not say what was
	// permitted -- it is kept for callers that want the session's scope, and
	// deliberately left out of Error(), where it would read as a list of
	// things we were allowed to do.
	ValidCommands string
}

func (e *AuthorizationError) Error() string {
	var b strings.Builder

	switch e.ReturnCode {
	case "CMD_NOT_FOUND":
		fmt.Fprintf(&b, "command %d is not registered on the peer", e.Command)
	default:
		fmt.Fprintf(&b, "command %d refused by the peer (%s)", e.Command, e.ReturnCode)
	}
	if e.Peer != "" {
		fmt.Fprintf(&b, " at %s", e.Peer)
	}

	// Who the peer thinks we are is the fact an operator needs; that it
	// authenticated at all is implied by naming the identity, and spelling
	// out which configuration to go and read is the sort of advice that ages
	// badly in a log line.
	switch {
	case e.TriedAuthKnown && !e.TriedAuthentication:
		b.WriteString("; the peer did not authenticate us")
	case e.User != "":
		fmt.Fprintf(&b, "; authenticated as %q", e.User)
		if e.Method != "" {
			fmt.Fprintf(&b, " via %s", e.Method)
		}
	default:
		b.WriteString("; the peer reported no authenticated identity")
	}
	b.WriteString(".")
	return b.String()
}
