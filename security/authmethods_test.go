package security

import (
	"strings"
	"testing"
)

func TestAuthMethodImplemented(t *testing.T) {
	for _, m := range []AuthMethod{AuthFS, AuthIDTokens, AuthToken, AuthSciTokens, AuthSSL, AuthClaimToBe, AuthNone} {
		if !m.Implemented() {
			t.Errorf("%s should report implemented", m)
		}
	}
	// KERBEROS and PASSWORD are declared but stubbed (performAuthentication returns
	// "not yet implemented"); they must report false so callers do not offer them.
	for _, m := range []AuthMethod{AuthKerberos, AuthPassword} {
		if m.Implemented() {
			t.Errorf("%s is a stub and must report NOT implemented", m)
		}
	}
}

func TestDefaultAuthMethods(t *testing.T) {
	got := DefaultAuthMethods()
	var names []string
	for _, m := range got {
		names = append(names, string(m))
	}
	if strings.Join(names, ",") != "FS,IDTOKENS,SCITOKENS,SSL" {
		t.Errorf("DefaultAuthMethods() = %v, want [FS IDTOKENS SCITOKENS SSL]", got)
	}
}
