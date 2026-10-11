package security

import "strings"

// featureAction is the outcome of reconciling one security feature between a
// client's and a server's policy: HTCondor's SecMan::sec_feat_act.
type featureAction int

const (
	featureNo featureAction = iota
	featureYes
	featureFail
)

// peerSecurityLevel reads a level as condor_secman.cpp sec_alpha_to_sec_req
// does: by its first letter, so the YES/NO of a reconciled ad read back as a
// level means REQUIRED/NEVER. A missing level is NEVER (ReconcileSecurityAttribute
// treats an attribute an older peer did not send as unsupported), and an
// unrecognized one is "" (SEC_REQ_INVALID).
func peerSecurityLevel(level SecurityLevel) SecurityLevel {
	s := strings.TrimSpace(string(level))
	if s == "" {
		return SecurityNever
	}
	switch s[0] {
	case 'R', 'r', 'Y', 'y', 'T', 't':
		return SecurityRequired
	case 'P', 'p':
		return SecurityPreferred
	case 'O', 'o':
		return SecurityOptional
	case 'N', 'n', 'F', 'f':
		return SecurityNever
	}
	return ""
}

// ownSecurityLevel is peerSecurityLevel for the local policy, where an unset
// level takes HTCondor's default for SEC_<level>_ENCRYPTION and
// SEC_<level>_INTEGRITY, OPTIONAL (SecMan::FillInSecurityPolicyAd), rather
// than NEVER.
func ownSecurityLevel(level SecurityLevel) SecurityLevel {
	if strings.TrimSpace(string(level)) == "" {
		return SecurityOptional
	}
	return peerSecurityLevel(level)
}

// reconcileSecurityAttribute is condor_secman.cpp
// SecMan::ReconcileSecurityAttribute: the server's decision for one feature
// from the client's (rows) and the server's (columns) levels. The chart
// is symmetric:
//
//	      R     P     O     N
//	R    YES   YES   YES   FAIL
//	P    YES   YES   YES   NO
//	O    YES   YES   NO    NO
//	N    FAIL  NO    NO    NO
//
// An unrecognized client level fails, as it does in C++.
func reconcileSecurityAttribute(cli, srv SecurityLevel) featureAction {
	switch cli {
	case SecurityRequired:
		if srv == SecurityNever {
			return featureFail
		}
		return featureYes
	case SecurityPreferred:
		if srv == SecurityNever {
			return featureNo
		}
		return featureYes
	case SecurityOptional:
		if srv == SecurityRequired || srv == SecurityPreferred {
			return featureYes
		}
		return featureNo
	case SecurityNever:
		if srv == SecurityRequired {
			return featureFail
		}
		return featureNo
	}
	return featureFail
}
