package security

import (
	"strconv"
	"strings"
	"testing"
)

// parseCondorMajorMinor pulls major.minor out of a "$CondorVersion: X.Y.Z ...$"
// string, for the >= 9.9.0 assertion below.
func parseCondorMajorMinor(t *testing.T, v string) (int, int) {
	t.Helper()
	const pfx = "$CondorVersion:"
	s := strings.TrimSpace(strings.TrimPrefix(v, pfx))
	fields := strings.Fields(s)
	if len(fields) == 0 {
		t.Fatalf("no version number in %q", v)
	}
	parts := strings.Split(fields[0], ".")
	if len(parts) < 2 {
		t.Fatalf("version %q not X.Y.Z", fields[0])
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		t.Fatalf("unparseable version %q", fields[0])
	}
	return maj, min
}

// TestDefaultRemoteVersionIsModern guards the constant: it must parse as >= 9.9.0,
// or a C++ peer's putClassAd falls back to the SECRET_MARKER private-attribute path.
func TestDefaultRemoteVersionIsModern(t *testing.T) {
	maj, min := parseCondorMajorMinor(t, DefaultRemoteVersion)
	if maj < 9 || (maj == 9 && min < 9) {
		t.Fatalf("DefaultRemoteVersion is %d.%d, must be >= 9.9 so C++ peers avoid the SECRET_MARKER path", maj, min)
	}
}

// TestServerAdAdvertisesRemoteVersion is the regression guard for the version fix:
// the server handshake ad must ALWAYS carry a RemoteVersion. Previously the server
// set it only when explicitly configured, so a Go collector advertised no version
// and a connecting C++ startd took the legacy private-attribute path (SECRET_MARKER
// + put_secret), desyncing the collector's raw reader.
func TestServerAdAdvertisesRemoteVersion(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		auth := &Authenticator{config: &SecurityConfig{}}
		ad := auth.createServerSecurityAd(&SecurityNegotiation{})
		got, ok := ad.EvaluateAttrString("RemoteVersion")
		if !ok || got == "" {
			t.Fatal("server ad has no RemoteVersion; a C++ peer would take the SECRET_MARKER path")
		}
		if got != DefaultRemoteVersion {
			t.Errorf("RemoteVersion = %q, want the default %q", got, DefaultRemoteVersion)
		}
	})

	t.Run("configured value wins", func(t *testing.T) {
		want := "$CondorVersion: 24.0.1 2024-01-01 $"
		auth := &Authenticator{config: &SecurityConfig{RemoteVersion: want}}
		ad := auth.createServerSecurityAd(&SecurityNegotiation{})
		if got, _ := ad.EvaluateAttrString("RemoteVersion"); got != want {
			t.Errorf("RemoteVersion = %q, want configured %q", got, want)
		}
	})
}
