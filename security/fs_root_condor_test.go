package security

import (
	"errors"
	"os"
	"testing"
)

func fsBoolPtr(b bool) *bool { return &b }

func TestFSRootToCondorEnabled(t *testing.T) {
	if !(&SecurityConfig{}).fsRootToCondorEnabled() {
		t.Error("nil FSRootToCondor should be enabled (HTCondor default true)")
	}
	if !(&SecurityConfig{FSRootToCondor: fsBoolPtr(true)}).fsRootToCondorEnabled() {
		t.Error("explicit true should be enabled")
	}
	if (&SecurityConfig{FSRootToCondor: fsBoolPtr(false)}).fsRootToCondorEnabled() {
		t.Error("explicit false should be disabled")
	}
}

// TestFSMapOwner covers the server side: a root-owned marker maps to the condor account
// (so a root tool authenticates as condor), gated on FS_ROOT_TO_CONDOR and a configured
// account.
func TestFSMapOwner(t *testing.T) {
	cases := []struct {
		name, owner string
		cfg         *SecurityConfig
		want        string
	}{
		{"root maps to condor by default", "root", &SecurityConfig{CondorUsername: "condor"}, "condor"},
		{"root maps when explicitly enabled", "root", &SecurityConfig{CondorUsername: "condor", FSRootToCondor: fsBoolPtr(true)}, "condor"},
		{"root unchanged when disabled", "root", &SecurityConfig{CondorUsername: "condor", FSRootToCondor: fsBoolPtr(false)}, "root"},
		{"root unchanged with no condor account", "root", &SecurityConfig{}, "root"},
		{"non-root owner unchanged", "alice", &SecurityConfig{CondorUsername: "condor"}, "alice"},
		{"nil config unchanged", "root", nil, "root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fsMapOwner(c.owner, c.cfg); got != c.want {
				t.Errorf("fsMapOwner(%q) = %q, want %q", c.owner, got, c.want)
			}
		})
	}
}

// recordingRunner is a CondorPrivRunner that records invocation and runs fn.
type recordingRunner struct {
	called bool
	ret    error
}

func (r *recordingRunner) RunAsCondor(fn func() error) error {
	r.called = true
	if r.ret != nil {
		return r.ret
	}
	return fn()
}

// TestMkdirFSMarker covers the client side: with a CondorPrivRunner the mkdir goes through
// it (that's where golang-htcondor switches to the condor account); without one it creates
// the marker directly under the current identity.
func TestMkdirFSMarker(t *testing.T) {
	// With a runner: the mkdir is routed through RunAsCondor and the directory is created.
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	rr := &recordingRunner{}
	a := &Authenticator{config: &SecurityConfig{CondorPrivRunner: rr}}
	if err := a.mkdirFSMarker(root, "FS_marker"); err != nil {
		t.Fatalf("mkdirFSMarker: %v", err)
	}
	if !rr.called {
		t.Error("expected the mkdir to be routed through the CondorPrivRunner")
	}
	if _, err := root.Stat("FS_marker"); err != nil {
		t.Errorf("marker not created: %v", err)
	}

	// A runner error propagates (marker not created).
	root2, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root2.Close() }()
	boom := errors.New("boom")
	a = &Authenticator{config: &SecurityConfig{CondorPrivRunner: &recordingRunner{ret: boom}}}
	if err := a.mkdirFSMarker(root2, "FS_marker"); !errors.Is(err, boom) {
		t.Errorf("mkdirFSMarker error = %v, want boom", err)
	}
	if _, err := root2.Stat("FS_marker"); err == nil {
		t.Error("marker should not exist when the runner fails")
	}

	// No runner (non-root case): created directly under the current identity.
	root3, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root3.Close() }()
	a = &Authenticator{config: &SecurityConfig{}}
	if err := a.mkdirFSMarker(root3, "FS_marker"); err != nil {
		t.Fatalf("mkdirFSMarker (no runner): %v", err)
	}
	if _, err := root3.Stat("FS_marker"); err != nil {
		t.Errorf("marker not created without a runner: %v", err)
	}
}
