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

package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// systemCertPool returns the platform's default trust store. A variable so
// tests can substitute a known pool.
var systemCertPool = x509.SystemCertPool

// useDefaultCAs reports whether the system trust store is trusted in addition
// to CAFile/CADir (AUTH_SSL_*_USE_DEFAULT_CAS, default true).
func (c *SecurityConfig) useDefaultCAs() bool {
	return c.UseDefaultCAs == nil || *c.UseDefaultCAs
}

// loadCertKeyPair selects the certificate/key pair the way C++
// Condor_Auth_SSL::setup_ssl_ctx does. CertFile and KeyFile are walked
// index-wise; a pair either of whose files cannot be read is skipped; every
// readable pair is loaded, and a readable pair that fails to load is an error.
// Each load replaces the previous one in the SSL_CTX, so the last readable pair
// is the one used.
//
// OpenSSL keeps one certificate per key type, so a readable RSA pair followed
// by a readable EC pair leaves both installed. This keeps only the last pair:
// HTCondor configurations list alternative locations for one host credential,
// not one credential per key type.
//
// Files are read through readCredential, which may elevate to root for a
// root-owned key, as C++ opens them under PRIV_ROOT.
//
// It returns nil (and no error) when no pair is readable; the caller decides
// whether that is acceptable.
func (c *SecurityConfig) loadCertKeyPair() (*tls.Certificate, string, error) {
	certPaths := splitCommaList(c.CertFile)
	keyPaths := splitCommaList(c.KeyFile)
	n := min(len(certPaths), len(keyPaths))
	var chosen *tls.Certificate
	var chosenPath string
	for i := 0; i < n; i++ {
		certPEM, err := c.readCredential(certPaths[i])
		if err != nil {
			slog.Debug(fmt.Sprintf("🔐 SSL: skipping certificate %s: %v", certPaths[i], err), "destination", "cedar")
			continue
		}
		keyPEM, err := c.readCredential(keyPaths[i])
		if err != nil {
			slog.Debug(fmt.Sprintf("🔐 SSL: skipping key %s: %v", keyPaths[i], err), "destination", "cedar")
			continue
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("load certificate/key pair %s/%s: %w", certPaths[i], keyPaths[i], err)
		}
		chosen, chosenPath = &cert, certPaths[i]
	}
	return chosen, chosenPath, nil
}

// preferredCAFile returns the CAFile candidate C++ would load: it open()s each
// entry in turn and keeps the last one that opened. "" when none is readable.
func preferredCAFile(list string) string {
	preferred := ""
	for _, path := range splitCommaList(list) {
		f, err := os.Open(path) //nolint:gosec // operator-configured CA path
		if err != nil {
			continue
		}
		_ = f.Close()
		preferred = path
	}
	return preferred
}

// buildCAPool returns the trust anchors for verifying the peer, following C++
// setup_ssl_ctx: the preferred CAFile and CADir are loaded (as by
// SSL_CTX_load_verify_locations), then the system defaults are added when
// UseDefaultCAs allows (SSL_CTX_set_default_verify_paths).
//
// A nil pool with a nil error means "the system defaults only", which is what
// crypto/tls does with a nil RootCAs.
func (c *SecurityConfig) buildCAPool() (*x509.CertPool, error) {
	caFile := preferredCAFile(c.CAFile)
	caDirs := filepath.SplitList(c.CADir)
	if caFile == "" && strings.TrimSpace(c.CADir) == "" {
		if c.useDefaultCAs() {
			return nil, nil
		}
		// Nothing configured and defaults disabled: no trust anchors, so
		// every peer certificate fails verification, as in C++.
		return x509.NewCertPool(), nil
	}

	pool := x509.NewCertPool()
	if c.useDefaultCAs() {
		sys, err := systemCertPool()
		if err != nil {
			// OpenSSL's set_default_verify_paths does not fail on a missing
			// default store; neither do we.
			slog.Warn(fmt.Sprintf("🔐 SSL: system CA pool unavailable: %v", err), "destination", "cedar")
		} else if sys != nil {
			pool = sys.Clone()
		}
	}

	if caFile != "" {
		pem, err := loadCAFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificates", caFile)
		}
		slog.Info(fmt.Sprintf("🔐 SSL: Loaded CA certificate(s) from %s", caFile), "destination", "cedar")
	}

	for _, dir := range caDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		n := appendCADir(pool, dir)
		slog.Info(fmt.Sprintf("🔐 SSL: Loaded CA certificate(s) from %d file(s) in %s", n, dir), "destination", "cedar")
	}
	return pool, nil
}

// appendCADir adds the PEM certificates in every regular file of dir (symlinks
// followed) to pool and returns how many files contributed. OpenSSL's CApath
// looks certificates up lazily by subject-hash file name; reading every file
// trusts the same CAs for a directory maintained with c_rehash or as an IGTF
// bundle (whose hashed *.0 links duplicate the *.pem files, which is harmless),
// and also a directory without hash links. Files that are not PEM certificates
// (CRLs, *.signing_policy, *.namespaces, *.info, ...) are skipped. Like
// OpenSSL, which does not examine the directory until a lookup, a directory
// that is missing or unreadable contributes nothing rather than failing.
func appendCADir(pool *x509.CertPool, dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn(fmt.Sprintf("🔐 SSL: cannot read CA directory %s: %v", dir, err), "destination", "cedar")
		return 0
	}
	n := 0
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // file in an operator-configured CA directory
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			n++
		}
	}
	return n
}
