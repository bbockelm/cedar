package security

import (
	"strings"
	"testing"
	"time"
)

// claimsAged builds the timing claims for a token issued age ago that expires
// expiresIn from now -- the shape condor_token_fetch produces (a long exp, and an
// iat that only gets older).
func claimsAged(age, expiresIn time.Duration) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iat": float64(now.Add(-age).Unix()),
		"exp": float64(now.Add(expiresIn).Unix()),
	}
}

// TestTokenMaxAgeDefaultsToDisabled pins the default to HTCondor's: the issued-at
// check is off unless an admin opts in. A day-old IDTOKEN with a valid exp -- what
// `condor_token_fetch -lifetime 86400` mints and what sits in ~/.condor/tokens.d --
// must authenticate, or Go daemons reject credentials the C++ daemons in the same
// pool accept.
func TestTokenMaxAgeDefaultsToDisabled(t *testing.T) {
	t.Setenv("SEC_TOKEN_MAX_AGE", "")
	a := &Authenticator{}

	for _, age := range []time.Duration{30 * time.Minute, 2 * time.Hour, 23 * time.Hour} {
		claims := claimsAged(age, time.Hour)
		if err := a.validateTokenTiming(claims, nil); err != nil {
			t.Errorf("nil config, token aged %v: %v", age, err)
		}
		if err := a.validateTokenTiming(claims, &SecurityConfig{}); err != nil {
			t.Errorf("zero config, token aged %v: %v", age, err)
		}
	}
}

// TestTokenMaxAgeEnforcedWhenConfigured is the other half: an admin who sets a
// positive value still gets the check.
func TestTokenMaxAgeEnforcedWhenConfigured(t *testing.T) {
	t.Setenv("SEC_TOKEN_MAX_AGE", "")
	a := &Authenticator{}
	cfg := &SecurityConfig{TokenMaxAge: 3600}

	if err := a.validateTokenTiming(claimsAged(30*time.Minute, time.Hour), cfg); err != nil {
		t.Errorf("token within max age rejected: %v", err)
	}
	err := a.validateTokenTiming(claimsAged(75*time.Minute, 24*time.Hour), cfg)
	if err == nil {
		t.Fatal("token older than the configured max age was accepted")
	}
	if !strings.Contains(err.Error(), "max age") {
		t.Errorf("error should name the max age, got: %v", err)
	}
}

// TestTokenMaxAgeConfigCanDisable covers HTCondor's documented way to turn the
// check off. A negative value must win over the env var, not fall through to it.
func TestTokenMaxAgeConfigCanDisable(t *testing.T) {
	t.Setenv("SEC_TOKEN_MAX_AGE", "60")
	a := &Authenticator{}
	old := claimsAged(24*time.Hour, time.Hour)

	if err := a.validateTokenTiming(old, &SecurityConfig{TokenMaxAge: -1}); err != nil {
		t.Errorf("SEC_TOKEN_MAX_AGE = -1 should disable the check: %v", err)
	}
	// With no config value the env var still applies.
	if err := a.validateTokenTiming(old, &SecurityConfig{}); err == nil {
		t.Error("env SEC_TOKEN_MAX_AGE=60 should still bound an unconfigured server")
	}
}

// TestTokenExpiryStillEnforced guards against the max-age fix loosening exp too.
func TestTokenExpiryStillEnforced(t *testing.T) {
	t.Setenv("SEC_TOKEN_MAX_AGE", "")
	a := &Authenticator{}
	err := a.validateTokenTiming(claimsAged(2*time.Hour, -time.Minute), nil)
	if err == nil {
		t.Fatal("expired token was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should say expired, got: %v", err)
	}
}
