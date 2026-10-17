package security

import (
	"strings"
)

// AttrLimitAuthorization is the session policy attribute that carries a
// session's authorization bounding set (ATTR_SEC_LIMIT_AUTHORIZATION,
// condor_attributes.h): the comma-separated authorization levels the
// credential was limited to, before the implied levels are added.
const AttrLimitAuthorization = "LimitAuthorization"

// permissionLevels are HTCondor's DCpermission names, in enum order
// (condor_perms.h).
var permissionLevels = []string{
	"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "CONFIG", "DAEMON",
	"SOAP", "DEFAULT", "CLIENT", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER",
}

// impliedPermission maps a level to the next level it implies:
// DCpermissionHierarchy::aImpliedNext (condor_perms.cpp). A level absent here
// implies nothing further.
var impliedPermission = map[string]string{
	"WRITE":            "READ",
	"NEGOTIATOR":       "READ",
	"ADMINISTRATOR":    "WRITE",
	"CONFIG":           "READ",
	"DAEMON":           "WRITE",
	"ADVERTISE_STARTD": "READ",
	"ADVERTISE_SCHEDD": "READ",
	"ADVERTISE_MASTER": "READ",
}

// permissionLevel returns the canonical name of the level name, which matches
// case-insensitively as getPermissionFromString does, or false if name is not
// a level.
func permissionLevel(name string) (string, bool) {
	for _, p := range permissionLevels {
		if strings.EqualFold(p, name) {
			return p, true
		}
	}
	return "", false
}

// ImpliedPermissions returns perm followed by every level it implies, in the
// order DCpermissionHierarchy::nextImplied visits them (e.g. DAEMON, WRITE,
// READ). It returns nil if perm is not a level.
func ImpliedPermissions(perm string) []string {
	p, ok := permissionLevel(perm)
	if !ok {
		return nil
	}
	out := []string{p}
	for {
		next, ok := impliedPermission[p]
		if !ok {
			return out
		}
		out = append(out, next)
		p = next
	}
}

// AuthorizationLimitsPermit reports whether a session whose authorization
// bounding set is limits may run a command registered at perms (its level and
// any alternates). A nil limits is no bounding set: everything is permitted.
// Otherwise the command is permitted if any of perms is ALLOW, or is in the
// bounding set expanded with the levels each limit implies; limits that name no
// level are ignored, so a set of only those permits ALLOW commands alone. This
// is the check daemon_command.cpp makes before authorizing a command.
func AuthorizationLimitsPermit(limits, perms []string) bool {
	if limits == nil {
		return true
	}
	bound := map[string]bool{}
	for _, l := range limits {
		for _, p := range ImpliedPermissions(l) {
			bound[p] = true
		}
	}
	for _, perm := range perms {
		p, ok := permissionLevel(perm)
		if ok && (p == "ALLOW" || bound[p]) {
			return true
		}
	}
	return false
}

// splitAuthorizationList splits a list the way StringTokenIterator does by
// default: on commas and whitespace, dropping empty items.
func splitAuthorizationList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

// parseLimitAuthorization reads a session's LimitAuthorization value back into
// a bounding set. The attribute is present only on a limited session, so the
// result is never nil, even for an empty value.
func parseLimitAuthorization(s string) []string {
	limits := splitAuthorizationList(s)
	if limits == nil {
		limits = []string{}
	}
	return limits
}

// tokenAuthorizationLimits returns the bounding set an IDTOKEN's scope claim
// sets: the level named by each "condor:/<LEVEL>" scope. It returns nil, no
// bounding set, if no scope names one (condor_auth_passwd.cpp sets
// LimitAuthorization only when there are some).
func tokenAuthorizationLimits(scope string) []string {
	var limits []string
	for _, s := range splitAuthorizationList(scope) {
		if level, ok := strings.CutPrefix(s, "condor:/"); ok && level != "" {
			limits = append(limits, level)
		}
	}
	return limits
}
