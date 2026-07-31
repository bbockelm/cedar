package security

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestParseAuthRequiredTriState verifies ATTR_SEC_AUTH_REQUIRED parses as a
// tri-state: absent -> nil (treated as required), explicit true/false honored.
func TestParseAuthRequiredTriState(t *testing.T) {
	a := &Authenticator{config: &SecurityConfig{}}

	absent := a.parseServerSecurityAd(classad.New())
	if absent.AuthRequired != nil {
		t.Errorf("absent AuthRequired = %v, want nil", *absent.AuthRequired)
	}

	adFalse := classad.New()
	adFalse.InsertAttrBool("AuthRequired", false)
	if got := a.parseServerSecurityAd(adFalse); got.AuthRequired == nil || *got.AuthRequired {
		t.Errorf("AuthRequired=false not parsed as non-nil false: %v", got.AuthRequired)
	}

	adTrue := classad.New()
	adTrue.InsertAttrBool("AuthRequired", true)
	if got := a.parseServerSecurityAd(adTrue); got.AuthRequired == nil || !*got.AuthRequired {
		t.Errorf("AuthRequired=true not parsed as non-nil true: %v", got.AuthRequired)
	}
}

// TestServerAllowsUnauthenticated verifies the fallback gate: only an explicit
// AuthRequired=false permits proceeding unauthenticated.
func TestServerAllowsUnauthenticated(t *testing.T) {
	a := &Authenticator{config: &SecurityConfig{}}
	f, t2 := false, true
	cases := []struct {
		name string
		req  *bool
		want bool
	}{
		{"absent(nil) -> required", nil, false},
		{"false -> allowed", &f, true},
		{"true -> required", &t2, false},
	}
	for _, tc := range cases {
		neg := &SecurityNegotiation{ServerConfig: &SecurityConfig{AuthRequired: tc.req}}
		if got := a.serverAllowsUnauthenticated(neg); got != tc.want {
			t.Errorf("%s: serverAllowsUnauthenticated = %v, want %v", tc.name, got, tc.want)
		}
	}
	// nil ServerConfig must not panic and must be treated as required.
	if a.serverAllowsUnauthenticated(&SecurityNegotiation{}) {
		t.Error("nil ServerConfig should not allow unauthenticated")
	}
}
