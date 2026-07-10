package security

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// IDTokenClaims holds the validated claims of an HTCondor IDTOKEN.
type IDTokenClaims struct {
	Subject  string                 // "sub"
	Issuer   string                 // "iss"
	Scope    string                 // "scope"
	Expiry   int64                  // "exp"
	IssuedAt int64                  // "iat"
	Raw      map[string]interface{} // all claims, for callers that need more
}

// VerifyIDToken verifies a complete HTCondor IDTOKEN -- a 3-part JWT whose
// signature is HMAC-SHA256 over "header.payload" using a key derived from the
// pool/named signing key via HKDF (salt "htcondor", info "master jwt"), matching
// condor_auth_passwd and GenerateJWT -- and returns its claims.
//
// The signing key is located from cfg (TokenPoolSigningKeyFile / TokenSigningKeyDir,
// or the SEC_TOKEN_POOL_SIGNING_KEY_FILE / SEC_PASSWORD_DIRECTORY env fallbacks);
// the key ID is the JWT "kid" header ("" => "POOL"). Expiration and issued-at
// max-age (SEC_TOKEN_MAX_AGE / cfg.TokenMaxAge, default 1h) are enforced.
//
// This is the standalone equivalent of the server side of the IDTOKENS CEDAR
// handshake, for validating an IDTOKEN presented as a bearer token OUTSIDE a
// CEDAR session -- e.g. the WebSocket CCB carrier. It does NOT perform the AKEP2
// key agreement; it is a pure token check.
func VerifyIDToken(tokenStr string, cfg *SecurityConfig) (*IDTokenClaims, error) {
	parts := strings.Split(strings.TrimSpace(tokenStr), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("security: not a signed JWT (expected 3 parts, got %d)", len(parts))
	}

	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("security: bad JWT header: %w", err)
	}
	keyID := "POOL"
	if kid, ok := header["kid"].(string); ok && kid != "" {
		keyID = kid
	}

	// loadSigningKey/computeTokenSignature/validateTokenTiming are stateless w.r.t.
	// the Authenticator receiver, so a zero value suffices for a standalone verify.
	a := &Authenticator{}
	signingKey, err := a.loadSigningKey(keyID, cfg)
	if err != nil {
		return nil, fmt.Errorf("security: loading signing key %q: %w", keyID, err)
	}

	signingInput := parts[0] + "." + parts[1]
	expected := a.computeTokenSignature(signingKey, signingInput)
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("security: bad JWT signature encoding: %w", err)
	}
	if !hmac.Equal(expected, actual) {
		return nil, fmt.Errorf("security: IDTOKEN signature verification failed")
	}

	claims, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("security: bad JWT payload: %w", err)
	}
	if err := a.validateTokenTiming(claims, cfg); err != nil {
		return nil, fmt.Errorf("security: IDTOKEN %w", err)
	}

	out := &IDTokenClaims{Raw: claims}
	if s, ok := claims["sub"].(string); ok {
		out.Subject = s
	}
	if s, ok := claims["iss"].(string); ok {
		out.Issuer = s
	}
	if s, ok := claims["scope"].(string); ok {
		out.Scope = s
	}
	out.Expiry = claimInt64(claims, "exp")
	out.IssuedAt = claimInt64(claims, "iat")
	if out.Subject == "" {
		return nil, fmt.Errorf("security: IDTOKEN missing required subject (sub) claim")
	}
	return out, nil
}

func decodeJWTSegment(seg string) (map[string]interface{}, error) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func claimInt64(claims map[string]interface{}, key string) int64 {
	switch v := claims[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}
