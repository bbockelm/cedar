package security

import (
	"strings"
	"testing"
)

func TestAuthMethodImplemented(t *testing.T) {
	for _, m := range []AuthMethod{AuthFS, AuthIDTokens, AuthToken, AuthSciTokens, AuthSSL, AuthKerberos, AuthClaimToBe, AuthNone} {
		if !m.Implemented() {
			t.Errorf("%s should report implemented", m)
		}
	}
	// PASSWORD is declared but stubbed (performAuthentication returns "not yet
	// implemented"); it must report false so callers do not offer it.
	if AuthPassword.Implemented() {
		t.Errorf("%s is a stub and must report NOT implemented", AuthPassword)
	}
}

func TestDefaultAuthMethods(t *testing.T) {
	got := DefaultAuthMethods()
	var names []string
	for _, m := range got {
		names = append(names, string(m))
	}
	if strings.Join(names, ",") != "FS,IDTOKENS,KERBEROS,SCITOKENS,SSL" {
		t.Errorf("DefaultAuthMethods() = %v, want [FS IDTOKENS KERBEROS SCITOKENS SSL]", got)
	}
}
