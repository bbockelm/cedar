// Package addresses provides utilities for parsing HTCondor addresses and handling
// different connection types including shared port connections.
package addresses

import (
	"strings"
)

// SharedPortInfo contains information extracted from a shared port address
type SharedPortInfo struct {
	ServerAddr   string // The address of the shared port server
	SharedPortID string // The shared port ID
	IsSharedPort bool   // True if this is a shared port address
}

// ParseHTCondorAddress parses HTCondor addresses that may contain shared port information
//
// HTCondor addresses with shared port info look like:
// - "<host:port?sock=shared_port_id>"
// - "host:port?sock=shared_port_id"
//
// Returns SharedPortInfo with the parsed information
func ParseHTCondorAddress(address string) SharedPortInfo {
	// Remove angle brackets if present
	address = strings.Trim(address, "<>")

	// Check for shared port parameter in the query string
	queryStartIndex := strings.Index(address, "?")
	if queryStartIndex == -1 {
		return SharedPortInfo{
			ServerAddr:   address,
			SharedPortID: "",
			IsSharedPort: false,
		}
	}

	serverAddr := address[:queryStartIndex]
	queryString := address[queryStartIndex+1:]

	// Look for sock parameter in the query string
	var sharedPortID string
	queryParams := strings.Split(queryString, "&")

	for _, param := range queryParams {
		if strings.HasPrefix(param, "sock=") {
			sharedPortID = param[5:] // Remove "sock=" prefix
			break
		}
	}

	if sharedPortID == "" {
		return SharedPortInfo{
			ServerAddr:   address,
			SharedPortID: "",
			IsSharedPort: false,
		}
	}

	// Remove any additional query parameters from the shared port ID
	if idx := strings.Index(sharedPortID, "&"); idx != -1 {
		sharedPortID = sharedPortID[:idx]
	}
	if idx := strings.Index(sharedPortID, "?"); idx != -1 {
		sharedPortID = sharedPortID[:idx]
	}

	return SharedPortInfo{
		ServerAddr:   serverAddr,
		SharedPortID: sharedPortID,
		IsSharedPort: true,
	}
}

// IsValidSharedPortID validates a shared port ID according to HTCondor rules
// The ID must contain only alphanumeric characters, dots, dashes, and underscores
func IsValidSharedPortID(id string) bool {
	if id == "" {
		return false
	}

	for _, r := range id {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
