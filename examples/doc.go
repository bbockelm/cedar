// Package examples contains demonstration programs for the golang-cedar library.
//
// These examples show how to use various features of the CEDAR protocol
// implementation including:
//   - HTCondor collector queries
//   - Shared port connections
//   - Security handshakes
//   - Authentication methods
//   - ClassAd serialization
//
// To run any of the examples, use:
//
//	go run -tags ignore <example_file.go>
//
// For example:
//
//	go run -tags ignore query_demo.go cm-1.ospool.osg-htc.org 9618
package examples

// Version returns the version information for the examples package.
func Version() string {
	return "golang-cedar examples v1.0.0"
}
