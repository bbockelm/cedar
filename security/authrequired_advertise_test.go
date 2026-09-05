package security

import "testing"

// A cedar server that ENACTS authentication but does not REQUIRE it must
// tell the client so, by advertising AuthRequired=false. Without it the
// client assumes auth is mandatory (the documented default), and when
// its enacted methods all fail it errors with "all authentication
// methods failed" instead of falling through to the unauthenticated
// session the server would have granted.
//
// This is the server half of the existing client-side
// serverAllowsUnauthenticated fallback, which was dead code for a
// cedar-to-cedar connection: a C++ collector advertises AuthRequired,
// but cedar's own server did not. An htcondordb (a Go daemon on cedar's
// server) with anonymous ALLOW_READ hit exactly this -- observed on
// ospool-ap2140: the server sent Authentication=YES with no
// AuthRequired, so the web app's mirror client, whose FS/Kerberos/SSL
// all fail in a container, could not fall through to the anonymous read
// the server permits.
func TestServerAdvertisesAuthRequiredWhenNotRequired(t *testing.T) {
	build := func(serverLevel SecurityLevel) *Authenticator {
		return &Authenticator{config: &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: serverLevel,
		}}
	}
	enacted := &SecurityNegotiation{
		Authentication:   true, // auth was enacted (methods matched)
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
	}

	for _, level := range []SecurityLevel{SecurityOptional, SecurityPreferred} {
		t.Run("server "+string(level)+" advertises AuthRequired=false", func(t *testing.T) {
			ad := build(level).createServerSecurityAd(enacted)

			v, ok := ad.EvaluateAttrBool("AuthRequired")
			if !ok {
				t.Fatalf("server did not advertise AuthRequired at all; a %s server "+
					"that enacts auth but does not require it must say so", level)
			}
			if v {
				t.Errorf("AuthRequired = true, want false for a %s server", level)
			}
		})
	}

	// A server that genuinely REQUIRES auth must NOT advertise
	// AuthRequired=false: absent means required, and a client that
	// exhausts its methods against a required server must fail closed.
	t.Run("required server does not weaken the client", func(t *testing.T) {
		ad := build(SecurityRequired).createServerSecurityAd(enacted)
		if v, ok := ad.EvaluateAttrBool("AuthRequired"); ok && !v {
			t.Errorf("a REQUIRED server advertised AuthRequired=false, which would let a " +
				"client proceed unauthenticated against a server that requires auth")
		}
	})

	// When no authentication is enacted at all, AuthRequired is moot and
	// should not appear.
	t.Run("no AuthRequired when auth not enacted", func(t *testing.T) {
		notEnacted := &SecurityNegotiation{Authentication: false, NegotiatedCrypto: CryptoAES}
		ad := build(SecurityOptional).createServerSecurityAd(notEnacted)
		if _, ok := ad.EvaluateAttrBool("AuthRequired"); ok {
			t.Error("AuthRequired should be absent when Authentication=NO")
		}
	})
}

// The attribute the server writes has to be the one the client reads
// back, or the round trip is silently broken.
func TestAuthRequiredRoundTrips(t *testing.T) {
	server := &Authenticator{config: &SecurityConfig{
		AuthMethods:    []AuthMethod{AuthFS},
		CryptoMethods:  []CryptoMethod{CryptoAES},
		Authentication: SecurityOptional,
	}}
	ad := server.createServerSecurityAd(&SecurityNegotiation{
		Authentication: true, NegotiatedAuth: AuthFS, NegotiatedCrypto: CryptoAES,
	})

	client := &Authenticator{config: &SecurityConfig{}}
	parsed := client.parseServerSecurityAd(ad)
	if parsed.AuthRequired == nil {
		t.Fatal("client parsed no AuthRequired from a server that advertised it")
	}
	if *parsed.AuthRequired {
		t.Error("client parsed AuthRequired=true from a server that advertised false")
	}
	// And that feeds the fallback predicate.
	if !server.serverAllowsUnauthenticated(&SecurityNegotiation{ServerConfig: parsed}) {
		t.Error("serverAllowsUnauthenticated is false despite AuthRequired=false; the fallback stays dead")
	}
}
