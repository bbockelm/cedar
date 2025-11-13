// Package integration provides end-to-end integration tests for the golang-cedar library.
//
// This package contains integration tests that verify the complete functionality
// of the CEDAR protocol implementation by testing real interactions with
// HTCondor services including:
//   - HTCondor collector connections
//   - Shared port protocol implementation
//   - Security handshake integration
//   - Full query workflows
//
// These tests require a running HTCondor environment and are designed to
// validate that the library works correctly with real HTCondor services.
package integration

// TestSuiteVersion returns version information for the integration test suite.
func TestSuiteVersion() string {
	return "golang-cedar integration tests v1.0.0"
}
