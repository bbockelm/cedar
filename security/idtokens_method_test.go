package security

import "testing"

// TestIDTokensWireName: IDTOKENS takes TOKEN's bit and is offered as TOKEN,
// as HTCondor does (SecMan::sec_char_to_auth_method and
// filterAuthenticationMethods); an HTCondor server does not recognize an offer
// of IDTOKENS.
func TestIDTokensWireName(t *testing.T) {
	if got := authMethodToBitmask(AuthIDTokens); got != AuthBitmaskToken {
		t.Errorf("authMethodToBitmask(IDTOKENS) = %d, want %d (TOKEN)", got, AuthBitmaskToken)
	}

	client := &Authenticator{config: &SecurityConfig{AuthMethods: []AuthMethod{AuthIDTokens, AuthFS, AuthToken}}}
	if got, _ := client.createClientSecurityAd().EvaluateAttrString("AuthMethods"); got != "TOKEN,FS" {
		t.Errorf("client AuthMethods = %q, want TOKEN,FS", got)
	}

	server := &Authenticator{config: &SecurityConfig{AuthMethods: []AuthMethod{AuthSSL, AuthIDTokens}}}
	ad := server.createServerSecurityAd(&SecurityNegotiation{
		NegotiatedAuth: AuthIDTokens,
		ClientConfig:   &SecurityConfig{AuthMethods: []AuthMethod{AuthToken}},
	})
	if got, _ := ad.EvaluateAttrString("AuthMethodsList"); got != "TOKEN" {
		t.Errorf("server AuthMethodsList = %q, want TOKEN", got)
	}
	if got, _ := ad.EvaluateAttrString("AuthMethods"); got != "TOKEN" {
		t.Errorf("server AuthMethods = %q, want TOKEN", got)
	}
}
