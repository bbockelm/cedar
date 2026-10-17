// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package security provides SCITOKENS authentication implementation
// for CEDAR streams using SSL + SciToken exchange.
//
// This file implements HTCondor's SCITOKENS authentication method based on
// SSL authentication followed by SciToken verification as documented in
// HTCondor's condor_auth_ssl.cpp.
package security

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SciTokenClaims holds the claims of a verified SciToken.
//
// It is a jwt.Claims through its own fields. It does not embed
// jwt.RegisteredClaims: these fields would shadow the embedded ones when
// decoding, leaving a validator that read the embedded copy with no expiry.
type SciTokenClaims struct {
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
	Scope   string `json:"scope,omitempty"`
	// Audience accepts both forms RFC 7519 allows: one string or an array.
	Audience  jwt.ClaimStrings `json:"aud,omitempty"`
	ExpiresAt int64            `json:"exp"`
	IssuedAt  int64            `json:"iat"`
	NotBefore int64            `json:"nbf,omitempty"`
	JWTID     string           `json:"jti,omitempty"`

	// AuthorizationLimits is the bounding set the token grants, as
	// validate_scitoken (condor_scitokens.cpp) builds it: "DENY", which names
	// no level, followed by each authorization level the token's scopes name.
	// VerifySciToken sets it.
	AuthorizationLimits []string `json:"-"`
}

func numericDate(sec int64) *jwt.NumericDate {
	if sec == 0 {
		return nil
	}
	return jwt.NewNumericDate(time.Unix(sec, 0))
}

// GetExpirationTime implements jwt.Claims.
func (c *SciTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDate(c.ExpiresAt), nil
}

// GetIssuedAt implements jwt.Claims.
func (c *SciTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDate(c.IssuedAt), nil
}

// GetNotBefore implements jwt.Claims.
func (c *SciTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return numericDate(c.NotBefore), nil
}

// GetIssuer implements jwt.Claims.
func (c *SciTokenClaims) GetIssuer() (string, error) { return c.Issuer, nil }

// GetSubject implements jwt.Claims.
func (c *SciTokenClaims) GetSubject() (string, error) { return c.Subject, nil }

// GetAudience implements jwt.Claims.
func (c *SciTokenClaims) GetAudience() (jwt.ClaimStrings, error) { return c.Audience, nil }

// OIDCConfiguration represents the OIDC discovery document
type OIDCConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key type (RSA, EC, etc.)
	Kid string `json:"kid"`           // Key ID
	Use string `json:"use"`           // Key use (sig, enc)
	Alg string `json:"alg"`           // Algorithm
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // EC X coordinate
	Y   string `json:"y,omitempty"`   // EC Y coordinate
	Crv string `json:"crv,omitempty"` // EC curve name
}

// IsSciToken determines if a JWT token is a SciToken by checking its signature algorithm
// SciTokens use asymmetric signatures (RS*, ES*, PS*), not HMAC (HS*)
func IsSciToken(tokenStr string) bool {
	// Parse token without verification to extract header
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return false
	}

	// Parse just the header to check algorithm
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return false
	}

	// Check if algorithm is asymmetric (not HS*)
	alg := token.Method.Alg()
	return !strings.HasPrefix(alg, "HS")
}

// SciTokenVerifyOptions says which SciTokens VerifySciToken accepts. The zero
// value accepts none.
type SciTokenVerifyOptions struct {
	// Accept decides from a token's issuer and subject, before anything is
	// fetched from the issuer, whether the token could be accepted at all.
	// HTCondor accepts a SciToken only when the SCITOKENS entries of its map
	// file map "issuer,subject" (condor_auth_ssl.cpp); asking first means an
	// issuer no entry names is refused without contacting it. Nil accepts
	// nothing. AcceptIssuers builds one from a list of issuers.
	Accept func(issuer, subject string) bool

	// Audiences is SCITOKENS_SERVER_AUDIENCE. A token naming an audience must
	// name one of these; one with no "aud" claim is accepted only when this
	// is empty. "ANY" in a scitokens:2.0 token, and
	// "https://wlcg.cern.ch/jwt/v1/any" in a WLCG token, match any server.
	Audiences []string

	// ForeignTokenIssuers is SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS when
	// SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES is true, and nil when it is
	// false; the single entry "*" names every issuer. A correctly signed,
	// current token from one of these issuers is accepted even when its
	// claims fail the SciTokens checks (audience, scope, unknown claims),
	// and its authorization comes from "condor:/" and "compute.*" scopes.
	// HTCondor's defaults are true and https://aai-dev.egi.eu/auth/realms/egi.
	ForeignTokenIssuers []string

	// HTTPClient fetches issuer metadata and keys; nil uses a client trusting
	// the system roots. Whatever the client, only https URLs are fetched,
	// redirects included, each response is read to at most 1 MiB, and each
	// request is bounded by ctx and a 10 second timeout.
	HTTPClient *http.Client

	// Now is the clock tokens are checked against; nil means time.Now.
	Now func() time.Time
}

// AcceptIssuers returns a SciTokenVerifyOptions.Accept that admits a token
// from exactly these issuers, whatever its subject.
func AcceptIssuers(issuers ...string) func(issuer, subject string) bool {
	issuers = slices.Clone(issuers)
	return func(issuer, _ string) bool {
		return slices.Contains(issuers, issuer)
	}
}

const (
	// sciTokenMaxResponse bounds an issuer's metadata and key set, as
	// scitokens-cpp bounds each download.
	sciTokenMaxResponse = 1 << 20
	// sciTokenFetchTimeout bounds each request to an issuer.
	sciTokenFetchTimeout = 10 * time.Second
	sciTokenMaxRedirects = 10

	wlcgAnyAudience = "https://wlcg.cern.ch/jwt/v1/any"
)

// sciTokenProfile is the token profile scitokens-cpp identifies.
type sciTokenProfile int

const (
	sciTokenProfile1     sciTokenProfile = iota // scitokens:1.0, or no version claim
	sciTokenProfile2                            // scitokens:2.0
	sciTokenProfileWLCG                         // wlcg.ver 1.0
	sciTokenProfileATJWT                        // typ at+jwt
)

// VerifySciToken verifies a SciToken the way HTCondor's validate_scitoken
// (condor_scitokens.cpp, through scitokens-cpp) does, and returns its claims.
//
// Every check that needs only the token is made first: the iat, exp and iss
// claims are required, exp and nbf must not have passed or be yet to come and
// iat must not be in the future, with no leeway; the issuer must be an https
// URL; the token profile, audience and scope rules must hold; and
// opts.Accept must admit the issuer and subject. Only then are the issuer's
// metadata and key set fetched, and the signature checked with the key the
// token names. As in scitokens-cpp, only RS256 and ES256 (P-256) keys are
// used.
func VerifySciToken(ctx context.Context, tokenStr string, opts SciTokenVerifyOptions) (*SciTokenClaims, error) {
	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}

	payload := jwt.MapClaims{}
	unverified, _, err := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(tokenStr, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, err := checkSciTokenPayload(unverified.Header, payload, now, &opts)
	if err != nil {
		return nil, err
	}

	issuerURL, err := url.Parse(claims.Issuer)
	if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
		return nil, fmt.Errorf("SciToken issuer %q is not an https URL", claims.Issuer)
	}
	if opts.Accept == nil || !opts.Accept(claims.Issuer, claims.Subject) {
		return nil, fmt.Errorf("SciToken from issuer %q with subject %q is not accepted", claims.Issuer, claims.Subject)
	}

	kid := ""
	if v, ok := unverified.Header["kid"]; ok {
		if kid, ok = v.(string); !ok {
			return nil, fmt.Errorf("token kid header is not a string")
		}
	}

	client := sciTokenHTTPClient(opts.HTTPClient)
	pub, alg, err := fetchSciTokenKey(ctx, client, issuerURL, kid)
	if err != nil {
		return nil, err
	}

	_, err = jwt.NewParser(jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation()).
		Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return pub, nil })
	if err != nil {
		return nil, fmt.Errorf("token signature verification failed: %w", err)
	}
	return claims, nil
}

// checkSciTokenPayload makes every check of VerifySciToken that needs only the
// token itself, and returns its claims.
func checkSciTokenPayload(header map[string]interface{}, payload jwt.MapClaims, now time.Time, opts *SciTokenVerifyOptions) (*SciTokenClaims, error) {
	// A typ of at+jwt selects that profile (RFC 8725 section 3.11).
	atJWT := false
	if v, ok := header["typ"]; ok {
		typ, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("token typ header is not a string")
		}
		atJWT = typ == "at+jwt" || typ == "application/at+jwt"
	}

	claims := &SciTokenClaims{}
	var err error
	if claims.IssuedAt, err = sciTokenDate(payload, "iat", true); err != nil {
		return nil, err
	}
	if claims.ExpiresAt, err = sciTokenDate(payload, "exp", true); err != nil {
		return nil, err
	}
	if claims.NotBefore, err = sciTokenDate(payload, "nbf", false); err != nil {
		return nil, err
	}
	if claims.Issuer, err = sciTokenString(payload, "iss"); err != nil {
		return nil, err
	}
	if claims.Subject, err = sciTokenString(payload, "sub"); err != nil {
		return nil, err
	}

	// jwt-cpp's checks, with no leeway.
	if now.After(time.Unix(claims.ExpiresAt, 0)) {
		return nil, fmt.Errorf("token has expired")
	}
	if now.Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, fmt.Errorf("token was issued in the future")
	}
	if _, ok := payload["nbf"]; ok && now.Before(time.Unix(claims.NotBefore, 0)) {
		return nil, fmt.Errorf("token is not valid yet")
	}

	// The profile, from the version claims (Validator::verify_async_continue).
	profile := sciTokenProfile1
	verifyAll := true
	_, hasAud := payload["aud"]
	if v, ok := payload["ver"]; ok {
		ver, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("token ver claim is not a string")
		}
		switch ver {
		case "scitokens:2.0", "scitoken:2.0":
			profile, verifyAll = sciTokenProfile2, false
			if !hasAud {
				return nil, fmt.Errorf("token aud claim is required for the SciTokens 2.0 profile")
			}
		case "scitokens:1.0":
		default:
			return nil, fmt.Errorf("unknown profile version in token: %s", ver)
		}
	} else if v, ok := payload["wlcg.ver"]; ok {
		ver, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("token wlcg.ver claim is not a string")
		}
		if ver != "1.0" {
			return nil, fmt.Errorf("unknown WLCG profile version in token: %s", ver)
		}
		profile, verifyAll = sciTokenProfileWLCG, false
		if !hasAud {
			return nil, fmt.Errorf("token aud claim is required for the WLCG profile")
		}
	} else if atJWT {
		profile, verifyAll = sciTokenProfileATJWT, false
	}

	// Values the checks below do not depend on, read leniently: a claim of
	// the wrong type fails those checks for a SciToken, and is simply absent
	// from a foreign token.
	claims.Scope, _ = payload["scope"].(string)
	claims.JWTID, _ = payload["jti"].(string)
	claims.Audience, _ = sciTokenAudience(payload["aud"])

	// The checks the scitokens-cpp Enforcer adds. A foreign token may fail
	// them (validate_scitoken).
	enforcerErr := checkSciTokenEnforcer(payload, profile, verifyAll, opts.Audiences)
	foreign := false
	if enforcerErr != nil {
		if !sciTokenForeignIssuer(opts.ForeignTokenIssuers, claims.Issuer) {
			return nil, enforcerErr
		}
		foreign = true
	}
	claims.AuthorizationLimits = sciTokenAuthorizationLimits(claims.Scope, profile == sciTokenProfileWLCG, foreign)
	return claims, nil
}

// checkSciTokenEnforcer makes the scitokens-cpp Enforcer's checks: the scope
// claim, and with configured audiences the aud claim, are required; aud must
// name an accepted audience; sub, jti and scope must be strings; and a
// SciTokens 1.0 token may carry no claim the Enforcer does not check.
func checkSciTokenEnforcer(payload jwt.MapClaims, profile sciTokenProfile, verifyAll bool, audiences []string) error {
	if _, ok := payload["scope"]; !ok {
		return fmt.Errorf("token scope claim is required")
	}
	if _, ok := payload["aud"]; !ok && len(audiences) > 0 {
		return fmt.Errorf("token aud claim is required")
	}
	// In a stable order, so the error a token gets does not vary.
	names := make([]string, 0, len(payload))
	for name := range payload {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value := payload[name]
		switch name {
		case "iat", "nbf", "exp", "ver", "iss", "opt":
		case "sub", "jti", "scope":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("token %s claim is not a string", name)
			}
		case "aud":
			if !sciTokenAudienceAccepted(value, profile, audiences) {
				return fmt.Errorf("token audience %v is not accepted by this server", value)
			}
		default:
			if verifyAll {
				return fmt.Errorf("token %s claim cannot be verified", name)
			}
		}
	}
	return nil
}

// sciTokenAudience reads an aud claim, a string or an array of strings.
func sciTokenAudience(value interface{}) (jwt.ClaimStrings, bool) {
	switch v := value.(type) {
	case string:
		return jwt.ClaimStrings{v}, true
	case []interface{}:
		auds := make(jwt.ClaimStrings, 0, len(v))
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				return nil, false
			}
			auds = append(auds, s)
		}
		return auds, true
	}
	return nil, false
}

// sciTokenAudienceAccepted is the Enforcer's aud check: some audience the
// token names is one of ours, or is the profile's wildcard.
func sciTokenAudienceAccepted(value interface{}, profile sciTokenProfile, audiences []string) bool {
	auds, ok := sciTokenAudience(value)
	if !ok {
		return false
	}
	for _, aud := range auds {
		if (profile == sciTokenProfile2 && aud == "ANY") ||
			(profile == sciTokenProfileWLCG && aud == wlcgAnyAudience) ||
			slices.Contains(audiences, aud) {
			return true
		}
	}
	return false
}

func sciTokenForeignIssuer(foreignIssuers []string, issuer string) bool {
	if len(foreignIssuers) == 1 && foreignIssuers[0] == "*" {
		return true
	}
	return slices.Contains(foreignIssuers, issuer)
}

// sciTokenDate reads a NumericDate claim. jwt-cpp accepts an integer or a
// number, rounding the latter.
func sciTokenDate(payload jwt.MapClaims, name string, required bool) (int64, error) {
	value, ok := payload[name]
	if !ok {
		if required {
			return 0, fmt.Errorf("token %s claim is required", name)
		}
		return 0, nil
	}
	n, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("token %s claim is not a number", name)
	}
	if i, err := n.Int64(); err == nil {
		return i, nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1<<62 {
		return 0, fmt.Errorf("token %s claim is not a valid date", name)
	}
	return int64(math.Round(f)), nil
}

func sciTokenString(payload jwt.MapClaims, name string) (string, error) {
	value, ok := payload[name]
	if !ok {
		return "", fmt.Errorf("token %s claim is required", name)
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("token %s claim is not a string", name)
	}
	return s, nil
}

// sciTokenAuthorizationLimits returns the bounding set validate_scitoken
// (condor_scitokens.cpp) builds from a SciToken's scope claim. A SciToken is
// always limited: the set starts with "DENY", which names no level, so a token
// with no condor scope may run only ALLOW commands.
//
// For a SciToken the levels come from the scitokens-cpp ACLs: each
// space-separated "condor:<path>" scope adds its path, normalized, with its
// leading slashes removed. A WLCG token's "compute.read" counts as
// condor:/READ, and "compute.create", "compute.modify" and "compute.cancel"
// together as condor:/WRITE. A foreign token has no ACLs; its levels come from
// "condor:/<LEVEL>" scopes as written, and from the compute scopes as for WLCG.
func sciTokenAuthorizationLimits(scope string, wlcg, foreign bool) []string {
	limits := []string{"DENY"}
	var create, modify, cancel bool
	if foreign {
		for _, s := range splitAuthorizationList(scope) {
			switch {
			case strings.HasPrefix(s, "condor:/"):
				limits = append(limits, s[len("condor:/"):])
			case s == "compute.read":
				limits = append(limits, "READ")
			case s == "compute.create":
				create = true
			case s == "compute.modify":
				modify = true
			case s == "compute.cancel":
				cancel = true
			}
		}
	} else {
		for _, s := range strings.Split(scope, " ") {
			if s == "" {
				continue
			}
			authz, p, found := strings.Cut(s, ":")
			if !found {
				p = "/"
			}
			if wlcg {
				switch authz {
				case "compute.read":
					authz, p = "condor", "/READ"
				case "compute.create":
					create = true
				case "compute.modify":
					modify = true
				case "compute.cancel":
					cancel = true
				}
			}
			if authz != "condor" {
				continue
			}
			if level := strings.TrimLeft(path.Clean("/"+p), "/"); level != "" {
				limits = append(limits, level)
			}
		}
	}
	if create && modify && cancel {
		limits = append(limits, "WRITE")
	}
	return limits
}

// fetchSciTokenKey fetches the issuer's metadata, then its key set, and returns
// the key the token names with the algorithm it signs (Validator::
// get_public_keys_from_web and get_public_key_pem_continue in scitokens-cpp).
func fetchSciTokenKey(ctx context.Context, client *http.Client, issuer *url.URL, kid string) (interface{}, string, error) {
	issuerStr := issuer.String()
	openid := strings.TrimSuffix(issuerStr, "/") + "/.well-known/openid-configuration"
	status, body, err := sciTokenGet(ctx, client, openid)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch metadata for issuer %s: %w", issuerStr, err)
	}
	if status != http.StatusOK {
		// RFC 8414 metadata, at the host's root with the issuer's path appended.
		issuerPath := issuer.EscapedPath()
		if issuerPath == "/" {
			issuerPath = ""
		}
		oauth := "https://" + strings.ToLower(issuer.Host) + "/.well-known/oauth-authorization-server" + issuerPath
		status, body, err = sciTokenGet(ctx, client, oauth)
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch metadata for issuer %s: %w", issuerStr, err)
		}
		if status != http.StatusOK {
			return nil, "", fmt.Errorf("failed to fetch metadata for issuer %s: status %d", issuerStr, status)
		}
	}
	var metadata OIDCConfiguration
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, "", fmt.Errorf("failed to parse metadata for issuer %s: %w", issuerStr, err)
	}
	if metadata.JWKSURI == "" {
		return nil, "", fmt.Errorf("metadata for issuer %s has no jwks_uri", issuerStr)
	}

	status, body, err = sciTokenGet(ctx, client, metadata.JWKSURI)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch key set for issuer %s: %w", issuerStr, err)
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("failed to fetch key set for issuer %s: status %d", issuerStr, status)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, "", fmt.Errorf("failed to parse key set for issuer %s: %w", issuerStr, err)
	}

	jwk, err := findSciTokenKey(set.Keys, kid)
	if err != nil {
		return nil, "", fmt.Errorf("issuer %s: %w", issuerStr, err)
	}
	alg := jwk.Alg
	if alg == "" {
		switch {
		case jwk.Kty == "RSA":
			alg = "RS256"
		case jwk.Kty == "EC" && jwk.Crv == "P-256":
			alg = "ES256"
		default:
			return nil, "", fmt.Errorf("issuer %s key %q is of unsupported type %s %s", issuerStr, kid, jwk.Kty, jwk.Crv)
		}
	}
	pub, err := ConvertJWKToPublicKey(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("issuer %s key %q: %w", issuerStr, kid, err)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg == "RS256" {
			return k, alg, nil
		}
	case *ecdsa.PublicKey:
		if alg == "ES256" && k.Curve == elliptic.P256() {
			return k, alg, nil
		}
	}
	return nil, "", fmt.Errorf("issuer %s key %q uses unsupported algorithm %s", issuerStr, kid, alg)
}

// findSciTokenKey picks the key a token names from a key set; a token naming
// none may use the set's only key (find_key_id in scitokens-cpp).
func findSciTokenKey(keys []json.RawMessage, kid string) (*JWK, error) {
	if kid == "" {
		if len(keys) != 1 {
			return nil, fmt.Errorf("token names no key and the key set has %d", len(keys))
		}
		var jwk JWK
		if err := json.Unmarshal(keys[0], &jwk); err != nil {
			return nil, fmt.Errorf("failed to parse key: %w", err)
		}
		return &jwk, nil
	}
	for _, raw := range keys {
		var jwk JWK
		if json.Unmarshal(raw, &jwk) == nil && jwk.Kid == kid {
			return &jwk, nil
		}
	}
	return nil, fmt.Errorf("no key with kid %q", kid)
}

// sciTokenGet fetches an https URL, returning the status and, on 200, the
// body. The body is limited to sciTokenMaxResponse bytes.
func sciTokenGet(ctx context.Context, client *http.Client, rawURL string) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return 0, nil, fmt.Errorf("refusing to fetch non-https URL %q", rawURL)
	}
	ctx, cancel := context.WithTimeout(ctx, sciTokenFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sciTokenMaxResponse+1))
	if err != nil {
		return 0, nil, fmt.Errorf("reading %s: %w", u.Redacted(), err)
	}
	if len(body) > sciTokenMaxResponse {
		return 0, nil, fmt.Errorf("response from %s is larger than %d bytes", u.Redacted(), sciTokenMaxResponse)
	}
	return resp.StatusCode, body, nil
}

var defaultSciTokenHTTPClient = sync.OnceValue(func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport}
})

// sciTokenHTTPClient returns a copy of c (or the default client) that follows
// only https redirects, and few of them.
func sciTokenHTTPClient(c *http.Client) *http.Client {
	if c == nil {
		c = defaultSciTokenHTTPClient()
	}
	cc := *c
	next := c.CheckRedirect
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
		}
		if len(via) >= sciTokenMaxRedirects {
			return errors.New("too many redirects")
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	return &cc
}

// verifyPeerSciToken is the server's half of the SciToken phase
// (server_verify_scitoken and the map file check after it, condor_auth_ssl.cpp).
// HTCondor fails the authentication unless the SCITOKENS map file entries map
// the token's "issuer,subject"; the peer then authenticates as the mapped
// user. It returns that user, as an FQU, and the token's bounding set.
func verifyPeerSciToken(ctx context.Context, cfg *SecurityConfig, token string) (string, []string, error) {
	if cfg == nil || cfg.SciTokensMapper == nil {
		return "", nil, errors.New("no SCITOKENS mapping is configured, so no SciToken is accepted")
	}
	// Accept runs once, on the issuer and subject the verified claims carry.
	var user string
	claims, err := VerifySciToken(ctx, token, SciTokenVerifyOptions{
		Accept: func(issuer, subject string) bool {
			mapped, ok := cfg.SciTokensMapper(issuer + "," + subject)
			if !ok || mapped == "" {
				return false
			}
			user = mapped
			return true
		},
		Audiences:           cfg.SciTokensServerAudience,
		ForeignTokenIssuers: cfg.SciTokensForeignTokenIssuers,
		HTTPClient:          cfg.SciTokensHTTPClient,
	})
	if err != nil {
		return "", nil, err
	}
	return cfg.CanonicalUser(user), claims.AuthorizationLimits, nil
}

// ConvertJWKToPublicKey converts a JWK to a public key for verification
func ConvertJWKToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		// Decode RSA modulus and exponent from base64url
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
		}

		// Convert to big.Int
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)

		// big.Int.Int64 is undefined for values that do not fit, so an
		// oversized exponent used to become whatever the low word happened
		// to be -- a ten-byte exponent lands on E=1. Nothing then says the
		// JWK was malformed: crypto/rsa refuses E < 2, so verification
		// fails much later complaining that the issuer's exponent is too
		// small, which is not what went wrong. Refuse it here instead, and
		// bound it the way crypto/rsa does.
		if !e.IsInt64() || e.Int64() < 2 || e.Int64() > math.MaxInt32 {
			return nil, fmt.Errorf("invalid RSA public exponent in JWK: %s", e.String())
		}

		// Create RSA public key
		return &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}, nil

	case "EC":
		// Decode EC coordinates from base64url
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
		}

		// Determine the curve
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

		// Build the key through ParseUncompressedPublicKey rather than
		// assigning X and Y directly. Setting the coordinates accepts any
		// pair of integers, including a point that is not on the curve;
		// parsing rejects those, and the point at infinity, before the key
		// is ever used to verify a token signature. Go deprecated the
		// coordinate fields in 1.26 for exactly this reason.
		//
		// Producers disagree about how to spell a coordinate. RFC 7518
		// section 6.2.1.2 asks for exactly the curve's byte length, but some
		// strip leading zeros and others sign-extend -- Java's
		// BigInteger.toByteArray prepends a zero byte whenever the high bit
		// is set, so a P-256 coordinate arrives in 33 bytes. Neither spells a
		// different number, so normalise both: drop leading zeros, then
		// left-pad to the curve width below. Refusing the sign-extended form
		// while accepting the stripped one would break working deployments
		// over a leading zero.
		//
		// What is still refused is a value too wide once the padding is gone.
		// That is a different number, not a differently spelled one.
		xBytes = bytes.TrimLeft(xBytes, "\x00")
		yBytes = bytes.TrimLeft(yBytes, "\x00")
		byteLen := (curve.Params().BitSize + 7) / 8
		if len(xBytes) > byteLen || len(yBytes) > byteLen {
			return nil, fmt.Errorf("EC coordinates too large for curve %s: x=%d y=%d bytes, want at most %d",
				jwk.Crv, len(xBytes), len(yBytes), byteLen)
		}
		point := make([]byte, 1+2*byteLen)
		point[0] = 4 // uncompressed point, SEC 1 section 2.3.3
		copy(point[1+byteLen-len(xBytes):1+byteLen], xBytes)
		copy(point[1+2*byteLen-len(yBytes):], yBytes)

		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("invalid EC public key for curve %s: %w", jwk.Crv, err)
		}
		return pub, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}
