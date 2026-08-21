package security

import (
	"path/filepath"
	"testing"
)

// TestCreateTLSConfigCommaSeparatedCandidates is the regression guard for the
// stall observed against a cedar server: AUTH_SSL_*_CERTFILE/_KEYFILE/_CAFILE are
// comma-separated candidate lists in HTCondor (default
// "/etc/pki/tls/certs/localhost.crt,/etc/condor/hostcert.pem"). cedar read the
// raw joined string as one path -> ENOENT -> no server cert -> the peer's TLS
// handshake hung. Each candidate must be tried; the first readable pair wins.
func TestCreateTLSConfigCommaSeparatedCandidates(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	hostCert := filepath.Join(dir, "host.crt")
	hostKey := filepath.Join(dir, "host.key")
	if err := GenerateTestHostCert(hostCert, hostKey, caCert, caKey, "localhost"); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nope")

	ssl := &SSLAuthenticator{authenticator: &Authenticator{config: &SecurityConfig{
		// First candidate missing, real one second -- the HTCondor default shape.
		CertFile: missing + ".crt," + hostCert,
		KeyFile:  missing + ".key," + hostKey,
		CAFile:   missing + ".ca," + caCert,
	}}}

	cfg, err := ssl.createTLSConfig("localhost")
	if err != nil {
		t.Fatalf("createTLSConfig with comma-list candidates failed (the bug): %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 loaded certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs populated from the readable CA candidate")
	}
}

// TestCreateTLSConfigAllCandidatesMissing verifies a clean error (not a silent
// no-cert config) when no cert/key candidate is readable.
func TestCreateTLSConfigAllCandidatesMissing(t *testing.T) {
	dir := t.TempDir()
	ssl := &SSLAuthenticator{authenticator: &Authenticator{config: &SecurityConfig{
		CertFile: filepath.Join(dir, "a.crt") + "," + filepath.Join(dir, "b.crt"),
		KeyFile:  filepath.Join(dir, "a.key") + "," + filepath.Join(dir, "b.key"),
	}}}
	if _, err := ssl.createTLSConfig("localhost"); err == nil {
		t.Fatal("expected an error when no cert/key candidate is readable, got nil")
	}
}
