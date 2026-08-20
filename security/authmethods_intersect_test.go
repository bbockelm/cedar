package security

import (
	"testing"
)

// TestServerAuthMethodsListIntersectsClient verifies the server advertises only
// the intersection of its own methods with what the client offered (in server
// preference order), not its full list. Otherwise a peer can try a method it
// never offered -- the bug observed where a client offering only SCITOKENS,SSL
// was handed back the server's full FS,TOKEN,KERBEROS,SCITOKENS,SSL list.
func TestServerAuthMethodsListIntersectsClient(t *testing.T) {
	serverFull := []AuthMethod{AuthFS, AuthToken, AuthKerberos, AuthSciTokens, AuthSSL}

	cases := []struct {
		name         string
		clientConfig *SecurityConfig
		want         string
	}{
		{
			name:         "reported scenario: intersect, server order preserved",
			clientConfig: &SecurityConfig{AuthMethods: []AuthMethod{AuthSciTokens, AuthSSL}},
			want:         "SCITOKENS,SSL",
		},
		{
			name:         "client order does not matter; server order wins",
			clientConfig: &SecurityConfig{AuthMethods: []AuthMethod{AuthSSL, AuthSciTokens}},
			want:         "SCITOKENS,SSL",
		},
		{
			name:         "single overlap",
			clientConfig: &SecurityConfig{AuthMethods: []AuthMethod{AuthFS, AuthNone}},
			want:         "FS",
		},
		{
			name:         "no overlap => empty list",
			clientConfig: &SecurityConfig{AuthMethods: []AuthMethod{AuthNone, AuthPassword}},
			want:         "",
		},
		{
			name:         "client offered none => fall back to server full list",
			clientConfig: &SecurityConfig{AuthMethods: nil},
			want:         "FS,TOKEN,KERBEROS,SCITOKENS,SSL",
		},
		{
			name:         "nil ClientConfig => fall back to server full list",
			clientConfig: nil,
			want:         "FS,TOKEN,KERBEROS,SCITOKENS,SSL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Authenticator{config: &SecurityConfig{
				AuthMethods:   serverFull,
				CryptoMethods: []CryptoMethod{CryptoAES},
			}}
			neg := &SecurityNegotiation{
				NegotiatedAuth:   AuthSciTokens,
				NegotiatedCrypto: CryptoAES,
				ClientConfig:     tc.clientConfig,
			}
			ad := a.createServerSecurityAd(neg)
			got, _ := ad.EvaluateAttrString("AuthMethodsList")
			if got != tc.want {
				t.Errorf("AuthMethodsList = %q, want %q", got, tc.want)
			}
			// The single negotiated method must never be dropped by the intersection.
			if m, _ := ad.EvaluateAttrString("AuthMethods"); m != string(AuthSciTokens) {
				t.Errorf("negotiated AuthMethods = %q, want SCITOKENS", m)
			}
		})
	}
}
