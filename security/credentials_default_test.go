package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type recordingReader struct {
	paths []string
	data  []byte
	err   error
}

func (r *recordingReader) ReadCredential(path string) ([]byte, error) {
	r.paths = append(r.paths, path)
	if r.err != nil {
		return nil, r.err
	}
	return r.data, nil
}

// GenerateJWT has no SecurityConfig to consult, so it reads the signing
// key through the process-wide reader. A daemon that has dropped to the
// condor account installs one that re-elevates; without this the read is
// a plain os.ReadFile and fails on a root-owned key.
func TestGenerateJWTUsesTheDefaultCredentialReader(t *testing.T) {
	// 16 bytes so the POOL duplication path has something to work with.
	key := []byte("0123456789abcdef")
	rr := &recordingReader{data: key}
	SetDefaultCredentialReader(rr)
	t.Cleanup(func() { SetDefaultCredentialReader(nil) })

	// A directory that does NOT contain the key: if GenerateJWT fell back
	// to reading the filesystem this would fail, so the test cannot pass
	// by accident.
	dir := t.TempDir()

	tok, err := GenerateJWT(dir, "POOL", "alice@example.org", "example.org", 1, 1<<40, nil)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	want := filepath.Join(dir, "POOL")
	if len(rr.paths) != 1 || rr.paths[0] != want {
		t.Errorf("reader was asked for %v, want exactly [%s]", rr.paths, want)
	}
}

// The reader's failure is the caller's failure: a daemon that cannot read
// its signing key must not mint a token signed with something else.
func TestGenerateJWTPropagatesReaderError(t *testing.T) {
	boom := errors.New("permission denied")
	SetDefaultCredentialReader(&recordingReader{err: boom})
	t.Cleanup(func() { SetDefaultCredentialReader(nil) })

	if _, err := GenerateJWT(t.TempDir(), "POOL", "alice", "example.org", 1, 1<<40, nil); err == nil {
		t.Fatal("a token was minted although the signing key could not be read")
	}
}

// With no reader installed, behaviour is unchanged: a plain read under
// the current identity.
func TestGenerateJWTFallsBackToPlainRead(t *testing.T) {
	SetDefaultCredentialReader(nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "POOL"), []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateJWT(dir, "POOL", "alice", "example.org", 1, 1<<40, nil); err != nil {
		t.Fatalf("GenerateJWT with no reader installed: %v", err)
	}
}
