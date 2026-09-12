package security

import (
	"os"
	"sync/atomic"
)

// CredentialReader reads the bytes of a credential file referenced by a
// SecurityConfig — the SSL server key/cert, a token signing key, or a token
// file. It exists so a daemon that has dropped privileges to a service account
// (e.g. condor) can still read root-owned 0600 credentials the way HTCondor's
// C++ daemons do: by momentarily re-elevating to root (set_priv(PRIV_ROOT)) for
// the read. Supply such a reader via SecurityConfig.Credentials.
//
// Reload: cedar calls ReadCredential every time it needs a credential (e.g. per
// SSL handshake), so a reader is free to cache for speed and support
// reload-on-reconfig by invalidating its cache on SIGHUP — the next handshake
// then re-reads the fresh bytes. cedar holds no credential state of its own.
//
// When SecurityConfig.Credentials is nil, credentials are read with a plain
// os.ReadFile under the process's current identity.
type CredentialReader interface {
	ReadCredential(path string) ([]byte, error)
}

// CredentialDirLister is an optional companion to CredentialReader for readers that
// can also list a credential *directory* under elevated privilege. A token directory
// such as SEC_TOKEN_SYSTEM_DIRECTORY (/etc/condor/tokens.d) is typically root-owned and
// mode 0700, so a daemon that has dropped to a service account cannot even enumerate it
// without momentarily re-elevating -- the same reason ReadCredential exists, extended to
// the directory scan. cedar type-asserts SecurityConfig.Credentials to this interface
// when scanning a token directory: if the reader implements it the listing is done
// through it (privileged), otherwise cedar falls back to an unprivileged os.ReadDir.
type CredentialDirLister interface {
	ListCredentialDir(path string) ([]os.DirEntry, error)
}

// readCredentialDir is the choke point for listing a credential directory, mirroring
// readCredential: it uses the configured reader's privileged listing when the reader
// implements CredentialDirLister, otherwise an unprivileged os.ReadDir.
func (c *SecurityConfig) readCredentialDir(path string) ([]os.DirEntry, error) {
	if c != nil && c.Credentials != nil {
		if lister, ok := c.Credentials.(CredentialDirLister); ok {
			return lister.ListCredentialDir(path)
		}
	}
	return os.ReadDir(path) //nolint:gosec // path is an operator-configured token directory
}

// readCredential is the single choke point cedar uses for every credential file
// read, so privilege handling and reload policy live in one injectable place. It
// reads through the configured CredentialReader, or with os.ReadFile when none
// is set.
func (c *SecurityConfig) readCredential(path string) ([]byte, error) {
	if c != nil && c.Credentials != nil {
		return c.Credentials.ReadCredential(path)
	}
	return readCredentialDefault(path)
}

// defaultCredentialReader is consulted by the package-level helpers that read a
// credential without a SecurityConfig in hand -- GenerateJWT, which is given a
// key directory and a key id and nothing else.
//
// Those helpers need the same privilege treatment as the rest: a token signing
// key is root-owned (/etc/condor/passwords.d/POOL is root:root 0600) while the
// daemon minting tokens runs as the condor account. Without this they read with
// a plain os.ReadFile and fail with "permission denied" on exactly the
// deployments the CredentialReader interface was introduced for.
//
// A process-wide default rather than a parameter because privilege state is
// itself process-wide, and because it lets a daemon install one reader at
// startup instead of threading it through every call site. Unset, behaviour is
// unchanged: a plain read under the current identity.
var defaultCredentialReader atomic.Pointer[CredentialReader]

// SetDefaultCredentialReader installs the reader used by package-level helpers
// that have no SecurityConfig to consult. Passing nil restores plain reads.
//
// Call it once during daemon startup, after privileges have been dropped, with
// the same reader given to SecurityConfig.Credentials.
func SetDefaultCredentialReader(r CredentialReader) {
	if r == nil {
		defaultCredentialReader.Store(nil)
		return
	}
	defaultCredentialReader.Store(&r)
}

// readCredentialDefault reads through the process-wide reader when one is
// installed, and with a plain os.ReadFile otherwise.
func readCredentialDefault(path string) ([]byte, error) {
	if r := defaultCredentialReader.Load(); r != nil {
		return (*r).ReadCredential(path)
	}
	return os.ReadFile(path) //nolint:gosec // path is an operator-configured credential location
}
