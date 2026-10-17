package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// trustTestCA is an in-memory CA for the trust/credential selection tests.
type trustTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var trustTestSerial int64 = 1000

func nextSerial() *big.Int {
	trustTestSerial++
	return big.NewInt(trustTestSerial)
}

func newTrustTestCA(t *testing.T, cn string) *trustTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &trustTestCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a leaf signed by ca, as parsed certificate plus cert/key PEM.
func (ca *trustTestCA) issue(t *testing.T, cn string) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// trusts reports whether leaf chains to an anchor in pool. A nil pool would
// mean the real system store, which no test certificate chains to.
func trusts(t *testing.T, pool *x509.CertPool, leaf *x509.Certificate) bool {
	t.Helper()
	if pool == nil {
		t.Fatal("pool is nil (system default); test expected an explicit pool")
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

// fakeSystemPool replaces the system trust store with one holding only sys.
func fakeSystemPool(t *testing.T, sys *trustTestCA) {
	t.Helper()
	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AddCert(sys.cert)
		return p, nil
	}
	t.Cleanup(func() { systemCertPool = orig })
}

func boolPtr(b bool) *bool { return &b }

// TestCAFileLastReadableWins: C++ open()s every CAFILE candidate and keeps the
// last that opened; only that one is loaded.
func TestCAFileLastReadableWins(t *testing.T) {
	dir := t.TempDir()
	caA, caB := newTrustTestCA(t, "CA A"), newTrustTestCA(t, "CA B")
	leafA, _, _ := caA.issue(t, "a.example")
	leafB, _, _ := caB.issue(t, "b.example")
	fileA := writeFile(t, filepath.Join(dir, "a.pem"), caA.pem)
	fileB := writeFile(t, filepath.Join(dir, "b.pem"), caB.pem)
	missing := filepath.Join(dir, "missing.pem")

	cfg := &SecurityConfig{CAFile: fileA + "," + fileB + "," + missing, UseDefaultCAs: boolPtr(false)}
	pool, err := cfg.buildCAPool()
	if err != nil {
		t.Fatal(err)
	}
	if !trusts(t, pool, leafB) {
		t.Error("last readable CA file (B) not trusted")
	}
	if trusts(t, pool, leafA) {
		t.Error("earlier CA file (A) trusted; only the last readable one should be loaded")
	}
}

// TestCAFileLastReadableUnparseable: the last readable candidate is the one
// loaded, so if it holds no certificate the setup fails, as
// SSL_CTX_load_verify_locations does.
func TestCAFileLastReadableUnparseable(t *testing.T) {
	dir := t.TempDir()
	caA := newTrustTestCA(t, "CA A")
	fileA := writeFile(t, filepath.Join(dir, "a.pem"), caA.pem)
	junk := writeFile(t, filepath.Join(dir, "junk.pem"), []byte("not a certificate\n"))
	cfg := &SecurityConfig{CAFile: fileA + "," + junk}
	if _, err := cfg.buildCAPool(); err == nil {
		t.Fatal("expected an error when the last readable CA file holds no certificates")
	}
}

// TestCAFileNoneReadable: with no readable CAFILE candidate C++ loads nothing
// from it and carries on with the defaults.
func TestCAFileNoneReadable(t *testing.T) {
	dir := t.TempDir()
	cfg := &SecurityConfig{CAFile: filepath.Join(dir, "x.pem") + "," + filepath.Join(dir, "y.pem")}
	pool, err := cfg.buildCAPool()
	if err != nil {
		t.Fatalf("unreadable CAFILE candidates should not be an error: %v", err)
	}
	if pool != nil {
		t.Error("expected the system default store (nil pool) when no CA file is readable")
	}

	cfg.UseDefaultCAs = boolPtr(false)
	pool, err = cfg.buildCAPool()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected an explicit empty pool with defaults disabled")
	}
	if !pool.Equal(x509.NewCertPool()) {
		t.Error("expected no trust anchors with nothing readable and defaults disabled")
	}
}

// TestCADirMixedContents loads an IGTF-style directory: CA PEMs, hashed
// symlinks duplicating them, and assorted non-certificate files.
func TestCADirMixedContents(t *testing.T) {
	dir := t.TempDir()
	caA, caB, caOut := newTrustTestCA(t, "CA A"), newTrustTestCA(t, "CA B"), newTrustTestCA(t, "CA Outside")
	leafA, _, _ := caA.issue(t, "a.example")
	leafB, _, _ := caB.issue(t, "b.example")
	leafOut, _, _ := caOut.issue(t, "out.example")

	writeFile(t, filepath.Join(dir, "CA-A.pem"), caA.pem)
	writeFile(t, filepath.Join(dir, "CA-B.pem"), caB.pem)
	if err := os.Symlink("CA-A.pem", filepath.Join(dir, "abcdef01.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("CA-B.pem", filepath.Join(dir, "abcdef02.0")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "CA-A.signing_policy"), []byte("access_id_CA X509 '/CN=CA A'\npos_rights globus CA:sign\n"))
	writeFile(t, filepath.Join(dir, "CA-A.namespaces"), []byte("TO Issuer \"/CN=CA A\" PERMIT Subject \"/.*\"\n"))
	writeFile(t, filepath.Join(dir, "CA-A.info"), []byte("alias = CA-A\nversion = 1.0\n"))
	writeFile(t, filepath.Join(dir, "CA-A.crl_url"), []byte("http://crl.example/ca-a.crl\n"))
	writeFile(t, filepath.Join(dir, "abcdef01.r0"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("garbage")}))
	writeFile(t, filepath.Join(dir, "empty"), nil)
	if err := os.Symlink("does-not-exist", filepath.Join(dir, "dangling.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A certificate in a subdirectory is not part of the CA directory.
	writeFile(t, filepath.Join(dir, "subdir", "out.pem"), caOut.pem)

	cfg := &SecurityConfig{CADir: dir, UseDefaultCAs: boolPtr(false)}
	pool, err := cfg.buildCAPool()
	if err != nil {
		t.Fatalf("CA directory with non-certificate files: %v", err)
	}
	if !trusts(t, pool, leafA) || !trusts(t, pool, leafB) {
		t.Error("CAs in the directory are not trusted")
	}
	if trusts(t, pool, leafOut) {
		t.Error("CA from a subdirectory was trusted")
	}
	if n := appendCADir(x509.NewCertPool(), dir); n != 4 {
		t.Errorf("appendCADir counted %d certificate files, want 4 (2 PEMs + 2 hash links)", n)
	}
}

// TestCADirCombinesWithCAFile: CAFILE and CADIR are both loaded, like
// SSL_CTX_load_verify_locations(ctx, cafile, cadir); several directories may
// be listed, as OpenSSL's CApath allows.
func TestCADirCombinesWithCAFile(t *testing.T) {
	dir := t.TempDir()
	dir1, dir2 := filepath.Join(dir, "d1"), filepath.Join(dir, "d2")
	for _, d := range []string{dir1, dir2} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	caF, ca1, ca2 := newTrustTestCA(t, "CA File"), newTrustTestCA(t, "CA Dir1"), newTrustTestCA(t, "CA Dir2")
	leafF, _, _ := caF.issue(t, "f.example")
	leaf1, _, _ := ca1.issue(t, "1.example")
	leaf2, _, _ := ca2.issue(t, "2.example")
	file := writeFile(t, filepath.Join(dir, "file.pem"), caF.pem)
	writeFile(t, filepath.Join(dir1, "ca.pem"), ca1.pem)
	writeFile(t, filepath.Join(dir2, "ca.pem"), ca2.pem)

	cfg := &SecurityConfig{
		CAFile:        file,
		CADir:         dir1 + string(os.PathListSeparator) + dir2,
		UseDefaultCAs: boolPtr(false),
	}
	pool, err := cfg.buildCAPool()
	if err != nil {
		t.Fatal(err)
	}
	for name, leaf := range map[string]*x509.Certificate{"file": leafF, "dir1": leaf1, "dir2": leaf2} {
		if !trusts(t, pool, leaf) {
			t.Errorf("CA from %s not trusted", name)
		}
	}
}

// TestCADirMissing: OpenSSL does not examine a CApath until a lookup, so a
// missing directory is not a setup failure.
func TestCADirMissing(t *testing.T) {
	cfg := &SecurityConfig{CADir: filepath.Join(t.TempDir(), "nope"), UseDefaultCAs: boolPtr(false)}
	pool, err := cfg.buildCAPool()
	if err != nil {
		t.Fatalf("missing CA directory: %v", err)
	}
	if !pool.Equal(x509.NewCertPool()) {
		t.Error("expected no trust anchors from a missing directory")
	}
}

// TestDefaultCAsAddedToConfigured: USE_DEFAULT_CAS (default true) adds the
// system store to CAFILE/CADIR rather than being replaced by them.
func TestDefaultCAsAddedToConfigured(t *testing.T) {
	dir := t.TempDir()
	sys, caA := newTrustTestCA(t, "System CA"), newTrustTestCA(t, "CA A")
	fakeSystemPool(t, sys)
	leafSys, _, _ := sys.issue(t, "sys.example")
	leafA, _, _ := caA.issue(t, "a.example")
	fileA := writeFile(t, filepath.Join(dir, "a.pem"), caA.pem)
	cadir := filepath.Join(dir, "cadir")
	if err := os.Mkdir(cadir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cadir, "a.pem"), caA.pem)

	for _, tc := range []struct {
		name    string
		cfg     SecurityConfig
		wantSys bool
	}{
		{"cafile/default", SecurityConfig{CAFile: fileA}, true},
		{"cafile/true", SecurityConfig{CAFile: fileA, UseDefaultCAs: boolPtr(true)}, true},
		{"cafile/false", SecurityConfig{CAFile: fileA, UseDefaultCAs: boolPtr(false)}, false},
		{"cadir/default", SecurityConfig{CADir: cadir}, true},
		{"cadir/false", SecurityConfig{CADir: cadir, UseDefaultCAs: boolPtr(false)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := tc.cfg.buildCAPool()
			if err != nil {
				t.Fatal(err)
			}
			if !trusts(t, pool, leafA) {
				t.Error("configured CA not trusted")
			}
			if got := trusts(t, pool, leafSys); got != tc.wantSys {
				t.Errorf("system CA trusted = %v, want %v", got, tc.wantSys)
			}
		})
	}
}

// TestDefaultCAsOnly: with no CAFILE/CADIR, the defaults are the store (nil
// pool for crypto/tls), or nothing at all when disabled.
func TestDefaultCAsOnly(t *testing.T) {
	sys := newTrustTestCA(t, "System CA")
	fakeSystemPool(t, sys)
	leafSys, _, _ := sys.issue(t, "sys.example")

	pool, err := (&SecurityConfig{}).buildCAPool()
	if err != nil || pool != nil {
		t.Fatalf("buildCAPool() = %v, %v; want nil pool (system default)", pool, err)
	}
	pool, err = (&SecurityConfig{UseDefaultCAs: boolPtr(false)}).buildCAPool()
	if err != nil {
		t.Fatal(err)
	}
	if trusts(t, pool, leafSys) {
		t.Error("system CA trusted with UseDefaultCAs=false")
	}
}

// TestCertPairLastReadableWins: every readable pair is loaded and the last
// replaces the earlier ones, as in the C++ SSL_CTX loop.
func TestCertPairLastReadableWins(t *testing.T) {
	dir := t.TempDir()
	ca := newTrustTestCA(t, "CA")
	_, c1, k1 := ca.issue(t, "first.example")
	_, c2, k2 := ca.issue(t, "second.example")
	cert1 := writeFile(t, filepath.Join(dir, "1.crt"), c1)
	key1 := writeFile(t, filepath.Join(dir, "1.key"), k1)
	cert2 := writeFile(t, filepath.Join(dir, "2.crt"), c2)
	key2 := writeFile(t, filepath.Join(dir, "2.key"), k2)
	missing := filepath.Join(dir, "missing")

	for _, tc := range []struct {
		name, certs, keys, wantCN string
	}{
		{"both readable", cert1 + "," + cert2, key1 + "," + key2, "second.example"},
		{"last unreadable", cert1 + "," + cert2 + "," + missing + ".crt", key1 + "," + key2 + "," + missing + ".key", "second.example"},
		{"second key unreadable", cert1 + "," + cert2, key1 + "," + missing, "first.example"},
		{"first unreadable", missing + ".crt," + cert2, missing + ".key," + key2, "second.example"},
		{"extra cert without key", cert1 + "," + cert2, key1, "first.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssl := &SSLAuthenticator{authenticator: &Authenticator{config: &SecurityConfig{CertFile: tc.certs, KeyFile: tc.keys}}}
			cfg, err := ssl.createTLSConfig("localhost", false)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Certificates) != 1 {
				t.Fatalf("got %d certificates, want 1", len(cfg.Certificates))
			}
			leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if leaf.Subject.CommonName != tc.wantCN {
				t.Errorf("loaded %q, want %q", leaf.Subject.CommonName, tc.wantCN)
			}
		})
	}
}

// TestCertPairReadableButInvalid: a pair whose files are readable but do not
// load is a hard error even when another pair would load.
func TestCertPairReadableButInvalid(t *testing.T) {
	dir := t.TempDir()
	ca := newTrustTestCA(t, "CA")
	_, c1, k1 := ca.issue(t, "good.example")
	_, _, otherKey := ca.issue(t, "other.example")
	good := writeFile(t, filepath.Join(dir, "good.crt"), c1)
	goodKey := writeFile(t, filepath.Join(dir, "good.key"), k1)
	garbage := writeFile(t, filepath.Join(dir, "garbage.crt"), []byte("garbage"))
	garbageKey := writeFile(t, filepath.Join(dir, "garbage.key"), []byte("garbage"))
	wrongKey := writeFile(t, filepath.Join(dir, "wrong.key"), otherKey)

	for _, tc := range []struct{ name, certs, keys string }{
		{"garbage first", garbage + "," + good, garbageKey + "," + goodKey},
		{"garbage last", good + "," + garbage, goodKey + "," + garbageKey},
		{"mismatched key", good, wrongKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, isClient := range []bool{false, true} {
				ssl := &SSLAuthenticator{authenticator: &Authenticator{config: &SecurityConfig{CertFile: tc.certs, KeyFile: tc.keys}}}
				_, err := ssl.createTLSConfig("localhost", isClient)
				if err == nil {
					t.Fatalf("isClient=%v: expected an error for a readable pair that does not load", isClient)
				}
				if !strings.Contains(err.Error(), "load certificate/key pair") {
					t.Errorf("isClient=%v: unexpected error: %v", isClient, err)
				}
			}
		})
	}
}

// TestClientNoReadableCertIsAnonymous: a client whose configured certificate
// candidates are all unreadable proceeds without one, as C++ does.
func TestClientNoReadableCertIsAnonymous(t *testing.T) {
	dir := t.TempDir()
	ssl := &SSLAuthenticator{authenticator: &Authenticator{config: &SecurityConfig{
		CertFile: filepath.Join(dir, "a.crt"),
		KeyFile:  filepath.Join(dir, "a.key"),
	}}}
	cfg, err := ssl.createTLSConfig("localhost", true)
	if err != nil {
		t.Fatalf("client with no readable certificate: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("got %d certificates, want none", len(cfg.Certificates))
	}
}
