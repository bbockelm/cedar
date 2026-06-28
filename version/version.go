// Package version parses and compares HTCondor version strings of the form
// "$CondorVersion: X.Y.Z <date> ...$", as exchanged during the CEDAR security
// handshake (the RemoteVersion attribute).
package version

import (
	"strconv"
	"strings"
)

// CondorVersion is a parsed major.minor.sub HTCondor version.
type CondorVersion struct{ Major, Minor, Sub int }

// AtLeast reports whether v >= other.
func (v CondorVersion) AtLeast(other CondorVersion) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Sub >= other.Sub
}

// String renders the version as "Major.Minor.Sub".
func (v CondorVersion) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Sub)
}

// Parse extracts the X.Y.Z from a "$CondorVersion: X.Y.Z ...$" string (or a
// bare "X.Y.Z"). It returns ok=false if no version-looking token is found.
func Parse(s string) (CondorVersion, bool) {
	// Find the first token that looks like X.Y or X.Y.Z.
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ':' || r == '$' || r == '\t'
	})
	for _, f := range fields {
		parts := strings.Split(f, ".")
		if len(parts) < 2 {
			continue
		}
		maj, err1 := strconv.Atoi(parts[0])
		min, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		sub := 0
		if len(parts) >= 3 {
			sub, _ = strconv.Atoi(parts[2])
		}
		return CondorVersion{maj, min, sub}, true
	}
	return CondorVersion{}, false
}
