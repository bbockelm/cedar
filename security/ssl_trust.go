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
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
//
// The parsed certificates are cached per directory (see caDirCerts), so an
// unchanged directory is listed and stat'ed but not re-read or re-parsed.
func appendCADir(pool *x509.CertPool, dir string) int {
	certs, files := caDirCerts(dir)
	for _, c := range certs {
		pool.AddCert(c)
	}
	return files
}

// caDirFile is what caDirCerts compares to decide whether a CA directory
// changed: each entry's name and, through any symlink, its target's type,
// size and modification time. Adding, removing or renaming a file changes the
// list; rewriting one in place, which leaves the directory's own mtime alone,
// changes its size or mtime.
type caDirFile struct {
	name    string
	regular bool
	size    int64
	modTime time.Time
}

type caDirEntry struct {
	sig   []caDirFile
	certs []*x509.Certificate
	files int
}

var (
	caDirCacheMu sync.Mutex
	caDirCache   = map[string]*caDirEntry{}

	// caDirLoads counts directory (re)loads, for tests.
	caDirLoads atomic.Int64
)

// caDirCerts returns the certificates in dir's regular files and how many files
// held at least one, reading and parsing them only when dir's listing or a
// file's size or mtime differs from the cached load.
func caDirCerts(dir string) ([]*x509.Certificate, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn(fmt.Sprintf("🔐 SSL: cannot read CA directory %s: %v", dir, err), "destination", "cedar")
		return nil, 0
	}
	sig := make([]caDirFile, 0, len(entries))
	for _, e := range entries {
		f := caDirFile{name: e.Name()}
		if fi, err := os.Stat(filepath.Join(dir, e.Name())); err == nil {
			f.regular, f.size, f.modTime = fi.Mode().IsRegular(), fi.Size(), fi.ModTime()
		}
		sig = append(sig, f)
	}

	caDirCacheMu.Lock()
	cached := caDirCache[dir]
	caDirCacheMu.Unlock()
	if cached != nil && slices.EqualFunc(cached.sig, sig, func(a, b caDirFile) bool {
		return a.name == b.name && a.regular == b.regular && a.size == b.size && a.modTime.Equal(b.modTime)
	}) {
		return cached.certs, cached.files
	}

	caDirLoads.Add(1)
	entry := &caDirEntry{sig: sig}
	for _, f := range sig {
		if !f.regular {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, f.name)) //nolint:gosec // file in an operator-configured CA directory
		if err != nil {
			continue
		}
		if certs := parsePEMCertificates(data); len(certs) > 0 {
			entry.certs = append(entry.certs, certs...)
			entry.files++
		}
	}
	caDirCacheMu.Lock()
	caDirCache[dir] = entry
	caDirCacheMu.Unlock()
	return entry.certs, entry.files
}

// parsePEMCertificates returns the certificates x509.CertPool.AppendCertsFromPEM
// would add from data: every CERTIFICATE block without headers that parses.
func parsePEMCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

// loadCAFile reads a CA bundle. CA material is public, so it is read under the
// process's own identity, as C++ does.
func loadCAFile(caFile string) ([]byte, error) {
	caCert, err := os.ReadFile(caFile) //nolint:gosec // operator-configured CA path
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", caFile, err)
	}
	return caCert, nil
}
