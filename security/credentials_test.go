package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeReader is a CredentialReader that serves bytes from an in-memory map and
// counts calls, standing in for a privilege-elevating, cache-and-reload reader.
type fakeReader struct {
	calls int
	data  map[string][]byte
}

func (f *fakeReader) ReadCredential(path string) ([]byte, error) {
	f.calls++
	if b, ok := f.data[path]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}

func TestReadCredentialUsesReader(t *testing.T) {
	fr := &fakeReader{data: map[string][]byte{"/etc/condor/key": []byte("secret")}}
	c := &SecurityConfig{Credentials: fr}

	b, err := c.readCredential("/etc/condor/key")
	if err != nil {
		t.Fatalf("readCredential: %v", err)
	}
	if string(b) != "secret" {
		t.Errorf("got %q, want %q", b, "secret")
	}
	if fr.calls != 1 {
		t.Errorf("reader called %d times, want 1 (cedar must route through the reader)", fr.calls)
	}
}

func TestReadCredentialNilFallsBackToOSReadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cred")
	if err := os.WriteFile(p, []byte("on-disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &SecurityConfig{} // no reader configured
	b, err := c.readCredential(p)
	if err != nil {
		t.Fatalf("readCredential: %v", err)
	}
	if string(b) != "on-disk" {
		t.Errorf("got %q, want %q", b, "on-disk")
	}

	// A missing file surfaces the os error.
	if _, err := c.readCredential(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist for missing file, got %v", err)
	}
}

// TestReadCredentialReloads documents the reload contract: cedar holds no
// credential state and re-consults the reader on every read, so a reader that
// returns fresh bytes after a reconfig (cache invalidation on SIGHUP) is
// reflected immediately — e.g. a rotated signing key or renewed certificate.
func TestReadCredentialReloads(t *testing.T) {
	fr := &fakeReader{data: map[string][]byte{"/k": []byte("v1")}}
	c := &SecurityConfig{Credentials: fr}

	if b, _ := c.readCredential("/k"); string(b) != "v1" {
		t.Fatalf("first read got %q, want v1", b)
	}
	// Operator rotates the credential; a caching reader would refresh on reload.
	fr.data["/k"] = []byte("v2")
	if b, _ := c.readCredential("/k"); string(b) != "v2" {
		t.Errorf("after rotation got %q, want v2 (cedar must not cache credentials)", b)
	}
	if fr.calls != 2 {
		t.Errorf("reader called %d times, want 2", fr.calls)
	}
}
