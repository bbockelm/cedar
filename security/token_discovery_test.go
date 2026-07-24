package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDirEntry is a minimal os.DirEntry for exercising the CredentialDirLister path.
type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string { return f.name }
func (f fakeDirEntry) IsDir() bool  { return f.dir }
func (f fakeDirEntry) Type() os.FileMode {
	if f.dir {
		return os.ModeDir
	}
	return 0
}
func (f fakeDirEntry) Info() (os.FileInfo, error) { return nil, os.ErrInvalid }

// fakeCredReader is a CredentialReader + CredentialDirLister that serves in-memory
// entries/files, standing in for a daemon's privileged (root) reader.
type fakeCredReader struct {
	entries    []os.DirEntry
	files      map[string][]byte
	listCalled *bool
	readPaths  *[]string
}

func (f *fakeCredReader) ReadCredential(path string) ([]byte, error) {
	if f.readPaths != nil {
		*f.readPaths = append(*f.readPaths, path)
	}
	if b, ok := f.files[path]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeCredReader) ListCredentialDir(path string) ([]os.DirEntry, error) {
	if f.listCalled != nil {
		*f.listCalled = true
	}
	return f.entries, nil
}

// TestScanTokenDirectoryUsesPrivilegedLister proves scanTokenDirectory lists through the
// wired CredentialDirLister (not os.ReadDir), skips subdirs/hidden files, and sorts.
func TestScanTokenDirectoryUsesPrivilegedLister(t *testing.T) {
	listed := false
	reader := &fakeCredReader{
		entries: []os.DirEntry{
			fakeDirEntry{name: "btoken"},
			fakeDirEntry{name: "atoken"},
			fakeDirEntry{name: ".hidden"},
			fakeDirEntry{name: "subdir", dir: true},
		},
		listCalled: &listed,
	}
	a := NewAuthenticator(&SecurityConfig{Credentials: reader}, nil)

	got := a.scanTokenDirectory("/etc/condor/tokens.d")
	if !listed {
		t.Fatal("expected scanTokenDirectory to use the privileged CredentialDirLister")
	}
	want := []string{
		filepath.Join("/etc/condor/tokens.d", "atoken"),
		filepath.Join("/etc/condor/tokens.d", "btoken"),
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("scanTokenDirectory = %v, want %v (sorted, no hidden/dir)", got, want)
	}
}

// TestScanTokenDirectoryFallbackReadDir proves that with no reader wired, scanTokenDirectory
// falls back to os.ReadDir, and that a missing directory yields empty (no panic).
func TestScanTokenDirectoryFallbackReadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tok1"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAuthenticator(&SecurityConfig{}, nil)

	got := a.scanTokenDirectory(dir)
	if len(got) != 1 || filepath.Base(got[0]) != "tok1" {
		t.Errorf("fallback scan = %v, want just [tok1]", got)
	}
	if missing := a.scanTokenDirectory(filepath.Join(dir, "does-not-exist")); len(missing) != 0 {
		t.Errorf("missing dir should yield empty, got %v", missing)
	}
}

// TestTokenCompatibilityReasons checks the accept/reject decisions and the human-readable
// reasons (mirroring HTCondor's condor_auth_passwd messages) that now drive the debug log.
func TestTokenCompatibilityReasons(t *testing.T) {
	a := NewAuthenticator(&SecurityConfig{}, nil)
	// createTestJWT (auth_test.go) issues an HMAC JWT with kid="POOL".
	tok := createTestJWT("alice@example.com", "example.com", 3600)

	cases := []struct {
		name      string
		cfg       *SecurityConfig
		method    AuthMethod
		wantOK    bool
		reasonHas string
	}{
		{"match issuer+kid", &SecurityConfig{TrustDomain: "example.com", IssuerKeys: []string{"POOL"}}, AuthToken, true, ""},
		{"empty keys accepts any kid", &SecurityConfig{TrustDomain: "example.com"}, AuthToken, true, ""},
		{"empty trust domain accepts", &SecurityConfig{}, AuthToken, true, ""},
		{"wrong trust domain", &SecurityConfig{TrustDomain: "other.org"}, AuthToken, false, "trust domain"},
		{"kid not in keys", &SecurityConfig{TrustDomain: "example.com", IssuerKeys: []string{"OTHER"}}, AuthToken, false, "signed with key POOL"},
		{"hmac token offered for scitokens", &SecurityConfig{}, AuthSciTokens, false, "not usable for SCITOKENS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := a.tokenCompatibility(tok, c.cfg, c.method)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (reason=%q)", ok, c.wantOK, reason)
			}
			if c.reasonHas != "" && !strings.Contains(reason, c.reasonHas) {
				t.Errorf("reason %q missing %q", reason, c.reasonHas)
			}
			if c.wantOK && reason != "" {
				t.Errorf("compatible token should have empty reason, got %q", reason)
			}
		})
	}
}

// TestTokenDiscoveryEndToEndPrivileged proves the whole probe works through a privileged
// reader: list a root-only tokens.d, read the token file, and match it -- the exact path
// that was failing (the file read must use the authenticator's own config, not the
// server's readerless negotiated config).
func TestTokenDiscoveryEndToEndPrivileged(t *testing.T) {
	tokenPath := filepath.Join("/etc/condor/tokens.d", "condor@example.com")
	tok := createTestJWT("condor@example.com", "example.com", 3600)
	reader := &fakeCredReader{
		entries: []os.DirEntry{fakeDirEntry{name: "condor@example.com"}},
		files:   map[string][]byte{tokenPath: []byte(tok + "\n")},
	}
	// Client config owns the reader + points at the system token dir.
	clientCfg := &SecurityConfig{
		Credentials: reader,
		TokenDir:    "/etc/condor/tokens.d",
		AuthMethods: []AuthMethod{AuthToken},
	}
	a := NewAuthenticator(clientCfg, nil)
	// Server config carries only the match criteria and NO reader (as negotiated).
	serverCfg := &SecurityConfig{TrustDomain: "example.com", IssuerKeys: []string{"POOL"}}

	if !a.hasCompatibleToken(clientCfg, serverCfg) {
		t.Fatal("expected a compatible token to be discovered via the privileged reader")
	}
}

// TestTokenSearchSummary checks the operator-facing "where did we look" summary.
func TestTokenSearchSummary(t *testing.T) {
	a := NewAuthenticator(&SecurityConfig{}, nil)
	clientCfg := &SecurityConfig{TokenDir: "/etc/condor/tokens.d"}
	serverCfg := &SecurityConfig{TrustDomain: "pool.example.org", IssuerKeys: []string{"KEY1", "KEY2"}}

	s := a.tokenSearchSummary(clientCfg, serverCfg)
	for _, want := range []string{"/etc/condor/tokens.d", "token_file=(unset)", "pool.example.org", "KEY1,KEY2"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q missing %q", s, want)
		}
	}
}
