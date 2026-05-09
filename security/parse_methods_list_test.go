// Copyright 2026 Morgridge Institute for Research
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

package security

import (
	"slices"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestParseServerSecurityAd_PrefersAuthMethodsList locks in the
// parser-side fix for the production schedd-ping regression: when the
// server response carries both `AuthMethods` (the single negotiated
// method) and `AuthMethodsList` (the full list of supported methods),
// the client must use the FULL list to drive the bitmask-exchange
// retry loop in handleClientAuthentication. Reading just `AuthMethods`
// — as the parser used to — left `availableMethods` with one entry,
// killed the retry loop, and surfaced as
// "all authentication methods failed: FS: server verification failed"
// in production even when the server had advertised SSL alongside FS.
//
// The four sub-tests cover the matrix of fields the parser may see:
//
//   - both present  → use AuthMethodsList (server response shape)
//   - list-only     → use AuthMethodsList (defensive; should always be
//     paired with AuthMethods, but if not we still want
//     the full list)
//   - methods-only  → fall back to AuthMethods (client request shape;
//     also covers older server peers that predate
//     AuthMethodsList in the response)
//   - neither       → empty result, not a panic
func TestParseServerSecurityAd_PrefersAuthMethodsList(t *testing.T) {
	auth := &Authenticator{}

	cases := []struct {
		name    string
		methods string // value for "AuthMethods", "" to omit
		list    string // value for "AuthMethodsList", "" to omit
		want    []AuthMethod
	}{
		{
			name:    "server response: list wins",
			methods: "FS",     // singular negotiated outcome
			list:    "FS,SSL", // full list of what server supports
			want:    []AuthMethod{AuthFS, AuthSSL},
		},
		{
			name: "list only",
			list: "TOKEN,SSL",
			want: []AuthMethod{AuthToken, AuthSSL},
		},
		{
			name:    "methods only (client request shape / pre-AuthMethodsList server)",
			methods: "FS,SSL,TOKEN",
			want:    []AuthMethod{AuthFS, AuthSSL, AuthToken},
		},
		{
			name: "neither field set",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			if tc.methods != "" {
				_ = ad.Set("AuthMethods", tc.methods)
			}
			if tc.list != "" {
				_ = ad.Set("AuthMethodsList", tc.list)
			}
			got := auth.parseServerSecurityAd(ad).AuthMethods
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseServerSecurityAd → AuthMethods = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseServerSecurityAd_PrefersCryptoMethodsList mirrors the
// AuthMethodsList parse fix for the crypto-method side. createServerSecurityAd
// also sets both `CryptoMethods` (single negotiated) and
// `CryptoMethodsList` (full list); same hazard, same fix.
func TestParseServerSecurityAd_PrefersCryptoMethodsList(t *testing.T) {
	auth := &Authenticator{}

	cases := []struct {
		name   string
		single string
		list   string
		want   []CryptoMethod
	}{
		{
			name:   "list wins over single",
			single: "AES",
			list:   "AES,BLOWFISH",
			want:   []CryptoMethod{CryptoAES, CryptoBlowfish},
		},
		{
			name:   "single only",
			single: "AES",
			want:   []CryptoMethod{CryptoAES},
		},
		{
			name: "list only",
			list: "AES,3DES",
			want: []CryptoMethod{CryptoAES, Crypto3DES},
		},
		{
			name: "neither",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			if tc.single != "" {
				_ = ad.Set("CryptoMethods", tc.single)
			}
			if tc.list != "" {
				_ = ad.Set("CryptoMethodsList", tc.list)
			}
			got := auth.parseServerSecurityAd(ad).CryptoMethods
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseServerSecurityAd → CryptoMethods = %v, want %v", got, tc.want)
			}
		})
	}
}
