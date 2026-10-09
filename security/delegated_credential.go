package security

import (
	"errors"
	"fmt"
)

// DelegatedCredentialError reports that a connection carrying somebody
// else's credential could not use it, and that this host's own
// credentials were not offered in its place.
//
// Typed, because the two readings of the same failure lead to
// different places. To an operator it is an authentication failure of
// the caller's credential -- a trust domain or a signing key that does
// not match, or a token that has expired -- and not a fault in the
// peer's authorization policy. To the server that holds the
// credential it may be a bug: a request that reached CEDAR with a
// credential it never managed to mint. Either way it is not a reason
// to authenticate as this host, which is the thing the untyped
// version of this used to do silently.
type DelegatedCredentialError struct {
	// Reason says which of the cases this is, in the words a log
	// reader needs.
	Reason string
	// Err is the underlying failure, when there was one.
	Err error
}

func (e *DelegatedCredentialError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (%v), and this host's own tokens may not be used in its place", e.Reason, e.Err)
	}
	return e.Reason + ", and this host's own tokens may not be used in its place"
}

func (e *DelegatedCredentialError) Unwrap() error { return e.Err }

// IsDelegatedCredentialRefused reports whether err is one of these,
// anywhere in its chain.
//
// Exported so a transport can answer with the status it actually
// means: the caller's credential was not usable, which is an
// authentication failure and not a server fault.
func IsDelegatedCredentialRefused(err error) bool {
	var target *DelegatedCredentialError
	return errors.As(err, &target)
}
