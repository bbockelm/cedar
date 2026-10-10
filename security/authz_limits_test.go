package security

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestImpliedPermissionsMatchesHTCondor checks the implied-level chain of every
// level against HTCondor's DCpermissionHierarchy::aImpliedNext, transcribed
// from condor_perms.cpp in enum order (condor_perms.h). An index of -1 is
// LAST_PERM: the level implies nothing further.
func TestImpliedPermissionsMatchesHTCondor(t *testing.T) {
	enum := []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "CONFIG", "DAEMON",
		"SOAP", "DEFAULT", "CLIENT", "ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"}
	const last = -1
	aImpliedNext := []int{
		/*            ALLOW */ last,
		/*             READ */ last,
		/*            WRITE */ 1, // READ
		/*       NEGOTIATOR */ 1, // READ
		/*    ADMINISTRATOR */ 2, // WRITE
		/*           CONFIG */ 1, // READ
		/*           DAEMON */ 2, // WRITE
		/*             SOAP */ last,
		/*          DEFAULT */ last,
		/*           CLIENT */ last,
		/* ADVERTISE_STARTD */ 1, // READ
		/* ADVERTISE_SCHEDD */ 1, // READ
		/* ADVERTISE_MASTER */ 1, // READ
	}
	for i, perm := range enum {
		want := []string{perm}
		for p := aImpliedNext[i]; p != last; p = aImpliedNext[p] {
			want = append(want, enum[p])
		}
		if got := ImpliedPermissions(perm); !slices.Equal(got, want) {
			t.Errorf("ImpliedPermissions(%s) = %q, want %q", perm, got, want)
		}
		if got := ImpliedPermissions(strings.ToLower(perm)); !slices.Equal(got, want) {
			t.Errorf("ImpliedPermissions(%s) = %q, want %q", strings.ToLower(perm), got, want)
		}
	}
	if got := ImpliedPermissions("DENY"); got != nil {
		t.Errorf("ImpliedPermissions(DENY) = %q, want nil", got)
	}
}

func TestAuthorizationLimitsPermit(t *testing.T) {
	for _, tc := range []struct {
		limits  []string
		perms   []string
		permits bool
	}{
		// No bounding set.
		{nil, []string{"ADMINISTRATOR"}, true},
		{nil, nil, true},
		// The limit, the levels it implies, and ALLOW.
		{[]string{"ADVERTISE_STARTD"}, []string{"ADVERTISE_STARTD"}, true},
		{[]string{"ADVERTISE_STARTD"}, []string{"READ"}, true},
		{[]string{"ADVERTISE_STARTD"}, []string{"ALLOW"}, true},
		{[]string{"advertise_startd"}, []string{"Read"}, true},
		{[]string{"ADVERTISE_STARTD"}, []string{"WRITE"}, false},
		{[]string{"ADVERTISE_STARTD"}, []string{"NEGOTIATOR"}, false},
		{[]string{"ADVERTISE_STARTD"}, []string{"ADMINISTRATOR"}, false},
		{[]string{"ADVERTISE_STARTD"}, []string{"DAEMON"}, false},
		{[]string{"ADVERTISE_STARTD"}, []string{"ADVERTISE_SCHEDD"}, false},
		{[]string{"DAEMON"}, []string{"WRITE"}, true},
		{[]string{"ADMINISTRATOR"}, []string{"READ"}, true},
		{[]string{"ADMINISTRATOR"}, []string{"DAEMON"}, false},
		{[]string{"READ", "WRITE"}, []string{"WRITE"}, true},
		// Any alternate level will do.
		{[]string{"ADVERTISE_STARTD"}, []string{"DAEMON", "ADVERTISE_STARTD"}, true},
		{[]string{"READ"}, []string{"DAEMON", "ALLOW"}, true},
		// A set naming no level, or empty, permits ALLOW alone.
		{[]string{"DENY"}, []string{"ALLOW"}, true},
		{[]string{"DENY"}, []string{"READ"}, false},
		{[]string{}, []string{"ALLOW"}, true},
		{[]string{}, []string{"READ"}, false},
		// A limited session cannot run a command with no registered level.
		{[]string{"ADMINISTRATOR"}, nil, false},
	} {
		if got := AuthorizationLimitsPermit(tc.limits, tc.perms); got != tc.permits {
			t.Errorf("AuthorizationLimitsPermit(%q, %q) = %t, want %t", tc.limits, tc.perms, got, tc.permits)
		}
	}
}

func TestTokenAuthorizationLimitsFromScope(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  []string
	}{
		{"", nil},
		{"openid profile", nil},
		{"condor:/", nil},
		{"condor:/READ", []string{"READ"}},
		{"condor:/READ condor:/ADVERTISE_STARTD", []string{"READ", "ADVERTISE_STARTD"}},
		{"condor:/READ,condor:/WRITE\tcompute.read", []string{"READ", "WRITE"}},
		// Kept verbatim, as HTCondor does; it names no level.
		{"condor://READ", []string{"/READ"}},
		{"Condor:/READ", nil},
	} {
		if got := tokenAuthorizationLimits(tc.scope); !slices.Equal(got, tc.want) || (got == nil) != (tc.want == nil) {
			t.Errorf("tokenAuthorizationLimits(%q) = %#v, want %#v", tc.scope, got, tc.want)
		}
	}
}

func TestSciTokenAuthorizationLimitsFromScope(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  []string
	}{
		{"", []string{"DENY"}},
		{"compute.read compute.create", []string{"DENY"}},
		{"condor:/READ", []string{"DENY", "READ"}},
		{"condor://WRITE condor:/ condor:/READ", []string{"DENY", "WRITE", "READ"}},
	} {
		if got := sciTokenAuthorizationLimits(tc.scope); !slices.Equal(got, tc.want) {
			t.Errorf("sciTokenAuthorizationLimits(%q) = %q, want %q", tc.scope, got, tc.want)
		}
	}
	// No condor scope still limits the session, to ALLOW commands.
	if AuthorizationLimitsPermit(sciTokenAuthorizationLimits("compute.read"), []string{"READ"}) {
		t.Error("a SciToken without condor scopes is permitted READ")
	}
}

func TestParseLimitAuthorization(t *testing.T) {
	if got := parseLimitAuthorization(""); got == nil || len(got) != 0 {
		t.Errorf(`parseLimitAuthorization("") = %#v, want a non-nil empty set`, got)
	}
	if got := parseLimitAuthorization("ADVERTISE_STARTD,READ"); !slices.Equal(got, []string{"ADVERTISE_STARTD", "READ"}) {
		t.Errorf("parseLimitAuthorization = %q", got)
	}
}

// TestTokenScopeNotStringRefused: a token whose scope claim is not a string is
// refused rather than treated as unlimited.
func TestTokenScopeNotStringRefused(t *testing.T) {
	poolKeyFile, namedKeyDir, cleanup := setupTestSigningKeys(t)
	defer cleanup()

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now().Unix()
	token := func(scope any) string {
		return enc(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "POOL"}) + "." +
			enc(map[string]any{"sub": "alice@test.domain", "iss": "test.domain", "iat": now, "exp": now + 3600, "scope": scope})
	}
	cfg := &SecurityConfig{TrustDomain: "test.domain", TokenPoolSigningKeyFile: poolKeyFile, TokenSigningKeyDir: namedKeyDir}
	a := &Authenticator{config: cfg}

	data := &TokenAuthData{Token: token([]string{"condor:/READ"})}
	if err := a.validateTokenAndDeriveKeys(data, &SecurityNegotiation{ServerConfig: cfg}); err == nil {
		t.Errorf("token with a list scope validated (limits %q), want it refused", data.AuthorizationLimits)
	}

	data = &TokenAuthData{Token: token("condor:/READ")}
	if err := a.validateTokenAndDeriveKeys(data, &SecurityNegotiation{ServerConfig: cfg}); err != nil {
		t.Fatalf("token with a string scope: %v", err)
	}
	if !slices.Equal(data.AuthorizationLimits, []string{"READ"}) {
		t.Errorf("AuthorizationLimits = %q, want [READ]", data.AuthorizationLimits)
	}
}
