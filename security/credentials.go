package security

import "os"

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

// readCredential is the single choke point cedar uses for every credential file
// read, so privilege handling and reload policy live in one injectable place. It
// reads through the configured CredentialReader, or with os.ReadFile when none
// is set.
func (c *SecurityConfig) readCredential(path string) ([]byte, error) {
	if c != nil && c.Credentials != nil {
		return c.Credentials.ReadCredential(path)
	}
	return os.ReadFile(path) //nolint:gosec // path is an operator-configured credential location
}
