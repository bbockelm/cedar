package security

import (
	"os"
	"strings"
)

// HTCondor names an authenticated peer by its fully-qualified user,
// "user@domain" (Condor_Auth_Base::getRemoteFQU, condor_auth.cpp). Each
// authentication method sets the user and the domain; setRemoteDomain
// lowercases the domain, and a method that sets no domain leaves the FQU as the
// bare user. ALLOW_*/DENY_* lists are matched against the whole FQU, while the
// user part alone is what C++ calls the owner (Sock::getOwner), e.g. a job's
// Owner attribute.

// UnmappedDomain is the domain C++ gives an SSL or SCITOKENS identity that no
// map file renamed (UNMAPPED_DOMAIN, authentication.cpp).
const UnmappedDomain = "unmapped"

// SplitFQU splits a fully-qualified user at its last '@' into the user and
// domain parts, as Authentication::split_canonical_name does. A name with no
// '@' is all user, with an empty domain.
func SplitFQU(fqu string) (user, domain string) {
	if i := strings.LastIndexByte(fqu, '@'); i >= 0 {
		return fqu[:i], fqu[i+1:]
	}
	return fqu, ""
}

// UserName returns the user part of User, the name before its last '@' -- what
// C++ calls the owner (Sock::getOwner). Use it, not User, wherever HTCondor
// stores a bare user name, such as a job's Owner; User is the identity to
// authorize.
func (sn *SecurityNegotiation) UserName() string {
	user, _ := SplitFQU(sn.User)
	return user
}

// UserDomain returns the domain part of User, the name after its last '@', or
// "" when User has no domain.
func (sn *SecurityNegotiation) UserDomain() string {
	_, domain := SplitFQU(sn.User)
	return domain
}

// joinFQU builds the FQU for a method that set user and domain, as getRemoteFQU
// does: "user@domain" with the domain lowercased, or user alone when there is no
// domain.
func joinFQU(user, domain string) string {
	if domain == "" {
		return user
	}
	return user + "@" + strings.ToLower(domain)
}

// canonicalFQU returns the FQU for a "user@domain" name, splitting it at the
// last '@' and lowercasing the domain. A name with no '@' takes defaultDomain
// (Authentication::split_canonical_name gives a mapped name UID_DOMAIN), or
// stays bare when defaultDomain is "" (an IDTOKENS subject with no '@').
func canonicalFQU(name, defaultDomain string) string {
	if i := strings.LastIndexByte(name, '@'); i >= 0 {
		return name[:i+1] + strings.ToLower(name[i+1:])
	}
	return joinFQU(name, defaultDomain)
}

// CanonicalUser returns the FQU HTCondor records for a canonical user name, the
// result of a map file: a name with an '@' keeps its domain (lowercased), and a
// name without one takes the UID domain (see LocalUIDDomain).
func (c *SecurityConfig) CanonicalUser(name string) string {
	return canonicalFQU(name, c.LocalUIDDomain())
}

// LocalUIDDomain returns UIDDomain, or, when it is unset, the host's name:
// HTCondor's UID_DOMAIN defaults to $(FULL_HOSTNAME).
func (c *SecurityConfig) LocalUIDDomain() string {
	if c != nil && c.UIDDomain != "" {
		return c.UIDDomain
	}
	host, _ := os.Hostname()
	return host
}
