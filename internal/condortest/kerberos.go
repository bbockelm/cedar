package condortest

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// KerberosFixture is an ephemeral MIT Kerberos KDC provisioned for interop
// tests: a realm, a service keytab for <service>/<host> (what a C++ condor
// daemon authenticates with), and a client credential cache. Everything lives
// under a temp dir; the KDC is stopped on cleanup.
type KerberosFixture struct {
	Realm       string // e.g. CEDAR.TEST
	Host        string // service host component, e.g. localhost
	Service     string // service component, e.g. host
	ClientPrinc string // e.g. client@CEDAR.TEST
	KeytabFile  string // service keytab (KERBEROS_SERVER_KEYTAB)
	CCacheFile  string // client credential cache (KRB5CCNAME)
	Krb5Conf    string // krb5.conf (KRB5_CONFIG)
	kdcPort     int
}

// SetupKerberos stands up a KDC and returns a fixture. It skips the test if the
// MIT krb5 tools are not installed (so it is a no-op on dev machines / plain CI
// and runs for real in the Docker interop image).
func SetupKerberos(t *testing.T, host string) *KerberosFixture {
	t.Helper()
	for _, bin := range []string{"kdb5_util", "krb5kdc", "kadmin.local", "kinit"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("Kerberos tool %q not found; skipping KERBEROS interop test", bin)
		}
	}

	const (
		realm   = "CEDAR.TEST"
		service = "host"
	)
	dir := t.TempDir()
	f := &KerberosFixture{
		Realm:       realm,
		Host:        host,
		Service:     service,
		ClientPrinc: "client@" + realm,
		KeytabFile:  filepath.Join(dir, "service.keytab"),
		CCacheFile:  filepath.Join(dir, "ccache"),
		Krb5Conf:    filepath.Join(dir, "krb5.conf"),
		kdcPort:     freePort(t),
	}
	dbDir := filepath.Join(dir, "db")
	kdcConf := filepath.Join(dir, "kdc.conf")
	clientKeytab := filepath.Join(dir, "client.keytab")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}

	writeFile(t, f.Krb5Conf, fmt.Sprintf(`[libdefaults]
    default_realm = %[1]s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    udp_preference_limit = 1
[realms]
    %[1]s = {
        kdc = 127.0.0.1:%[2]d
        admin_server = 127.0.0.1:%[2]d
    }
[domain_realm]
    %[3]s = %[1]s
    .%[3]s = %[1]s
`, realm, f.kdcPort, host))

	writeFile(t, kdcConf, fmt.Sprintf(`[kdcdefaults]
    kdc_ports = %[2]d
    kdc_tcp_ports = %[2]d
[realms]
    %[1]s = {
        database_name = %[3]s/principal
        key_stash_file = %[3]s/.k5.%[1]s
        acl_file = %[3]s/kadm5.acl
        max_life = 1h
        max_renewable_life = 1h
    }
`, realm, f.kdcPort, dbDir))

	// The KDC tools read KRB5_CONFIG and KRB5_KDC_PROFILE from the environment.
	env := append(os.Environ(),
		"KRB5_CONFIG="+f.Krb5Conf,
		"KRB5_KDC_PROFILE="+kdcConf,
	)

	// Create the realm database (stash the master key so the KDC starts headless).
	run(t, env, "kdb5_util", "create", "-r", realm, "-s", "-P", "masterpassword")

	// Principals: the service (what condor authenticates as) and the client.
	kadmin(t, env, realm, "addprinc -randkey "+service+"/"+host)
	kadmin(t, env, realm, "ktadd -k "+f.KeytabFile+" "+service+"/"+host)
	kadmin(t, env, realm, "addprinc -randkey "+f.ClientPrinc)
	kadmin(t, env, realm, "ktadd -k "+clientKeytab+" "+f.ClientPrinc)

	// Start the KDC and stop it on cleanup.
	kdc := exec.Command("krb5kdc", "-r", realm, "-n") // -n: run in the foreground
	kdc.Env = env
	kdc.Stdout, kdc.Stderr = testLogWriter{t}, testLogWriter{t}
	if err := kdc.Start(); err != nil {
		t.Fatalf("start krb5kdc: %v", err)
	}
	t.Cleanup(func() {
		_ = kdc.Process.Kill()
		_, _ = kdc.Process.Wait()
	})
	waitForKDC(t, f.kdcPort)

	// Obtain a client ticket into the ccache using the client keytab.
	run(t, append(env, "KRB5CCNAME=FILE:"+f.CCacheFile),
		"kinit", "-k", "-t", clientKeytab, "-c", "FILE:"+f.CCacheFile, f.ClientPrinc)

	return f
}

// CondorConfig returns the HTCondor config lines that make a C++ daemon accept
// KERBEROS with this fixture's keytab.
func (f *KerberosFixture) CondorConfig() string {
	return fmt.Sprintf(`
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = KERBEROS
SEC_CLIENT_AUTHENTICATION_METHODS = KERBEROS
# Require encryption + integrity so the collector runs the wrapped-key exchange
# (server generates the CEDAR key and seals it under the Kerberos ticket key),
# exercising the krb5 wrap/unwrap binding rather than an auth-only session.
SEC_DEFAULT_ENCRYPTION = REQUIRED
SEC_DEFAULT_INTEGRITY = REQUIRED
SEC_DEFAULT_CRYPTO_METHODS = AES
KERBEROS_SERVER_KEYTAB = %s
KERBEROS_SERVER_SERVICE = %s
KERBEROS_MAP_FILE =
`, f.KeytabFile, f.Service)
}

// --- helpers ---

// kadmin runs one kadmin.local command against the fixture's realm.
func kadmin(t *testing.T, env []string, realm, q string) {
	t.Helper()
	run(t, env, "kadmin.local", "-r", realm, "-q", q)
}

func run(t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// freePort returns a currently-free TCP port (also used for UDP — same number).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForKDC(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("KDC did not come up on port %d", port)
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Logf("krb5kdc: %s", p)
	return len(p), nil
}
