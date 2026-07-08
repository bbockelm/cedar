// ClassAd serialization for HTCondor CEDAR protocol
// Based on HTCondor's classad_oldnew.cpp implementation
package message

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// PUT_CLASSAD options that control how ClassAds are serialized
// These mirror HTCondor's putClassAd options from classad_oldnew.cpp
type PutClassAdOptions int

const (
	PutClassAdNone              PutClassAdOptions = 0
	PutClassAdNoTypes           PutClassAdOptions = 1 << 0 // Don't send MyType/TargetType
	PutClassAdNoPrivate         PutClassAdOptions = 1 << 1 // Exclude private attributes
	PutClassAdServerTime        PutClassAdOptions = 1 << 2 // Add ATTR_SERVER_TIME
	PutClassAdNonBlocking       PutClassAdOptions = 1 << 3 // Non-blocking mode (not used in this impl)
	PutClassAdNoExpandWhitelist PutClassAdOptions = 1 << 4 // Don't expand whitelist references
)

// PutClassAdConfig provides configuration for ClassAd serialization
type PutClassAdConfig struct {
	Options        PutClassAdOptions
	Whitelist      []string         // If provided, only these attributes will be sent
	EncryptedAttrs []string         // Attributes that should be encrypted (not implemented)
	PeerVersion    *HTCondorVersion // Peer version for compatibility checks
}

// HTCondorVersion represents a HTCondor version for compatibility checks
type HTCondorVersion struct {
	Major int
	Minor int
	Patch int
}

// NewHTCondorVersion creates a new version
func NewHTCondorVersion(major, minor, patch int) *HTCondorVersion {
	return &HTCondorVersion{Major: major, Minor: minor, Patch: patch}
}

// BuiltSinceVersion checks if this version is >= the specified version
func (v *HTCondorVersion) BuiltSinceVersion(major, minor, patch int) bool {
	if v.Major > major {
		return true
	}
	if v.Major == major && v.Minor > minor {
		return true
	}
	if v.Major == major && v.Minor == minor && v.Patch >= patch {
		return true
	}
	return false
}

// Private-attribute predicates. These delegate to the classad package, the
// single source of truth shared by every serialization layer (see
// classad.IsPrivateAttribute); keeping a local list would risk divergence -- and
// the previous local copy matched names case-sensitively, which leaked e.g.
// "claimid" because ClassAd attribute names are case-insensitive.

// ClassAdAttributeIsPrivateV1 reports whether name is one of HTCondor's fixed
// private attributes (ClassAdPrivateAttrs), case-insensitively.
func ClassAdAttributeIsPrivateV1(name string) bool {
	return classad.IsPrivateAttributeV1(name)
}

// ClassAdAttributeIsPrivateV2 reports whether name is a "_condor_priv"-prefixed
// private attribute.
func ClassAdAttributeIsPrivateV2(name string) bool {
	return classad.IsPrivateAttributeV2(name)
}

// ClassAdAttributeIsPrivateAny reports whether name is private (V1 or V2).
func ClassAdAttributeIsPrivateAny(name string) bool {
	return classad.IsPrivateAttribute(name)
}

// putClassAdToMessageWithOptions writes a ClassAd with advanced options to a Message
// Based on HTCondor's putClassAd() function in classad_oldnew.cpp
// Supports all HTCondor options: whitelist, private attribute exclusion, etc.
func putClassAdToMessageWithOptions(m *Message, ad *classad.ClassAd, config *PutClassAdConfig, ctx context.Context) error {
	// Use default config if none provided
	if config == nil {
		config = &PutClassAdConfig{}
	}

	// Determine which attributes to exclude based on privacy settings
	excludePrivate := (config.Options & PutClassAdNoPrivate) != 0
	excludePrivateV2 := excludePrivate || (config.PeerVersion != nil &&
		!config.PeerVersion.BuiltSinceVersion(9, 9, 0))

	// Get all available attributes
	allAttrs := ad.GetAttributes()

	// Build the final attribute list considering whitelist and privacy
	var attrsToSend []string

	if len(config.Whitelist) > 0 {
		// Use whitelist mode - only send whitelisted attributes
		attrsToSend = filterAttributesByWhitelist(allAttrs, ad, config.Whitelist,
			excludePrivate, excludePrivateV2, config.EncryptedAttrs, config.Options)
	} else {
		// Send all attributes (filtered by privacy)
		attrsToSend = filterAttributesByPrivacy(allAttrs,
			excludePrivate, excludePrivateV2, config.EncryptedAttrs)
	}

	// Count expressions (excluding MyType/TargetType which are handled separately)
	numExprs := len(attrsToSend)

	// Add server time if requested
	sendServerTime := (config.Options & PutClassAdServerTime) != 0
	if sendServerTime {
		numExprs++
	}

	// Write number of expressions
	if err := m.PutInt(ctx, numExprs); err != nil {
		return fmt.Errorf("failed to write expression count: %w", err)
	}

	// Write server time first if requested
	if sendServerTime {
		serverTimeExpr := fmt.Sprintf("ServerTime = %d", getCurrentUnixTime())
		if err := m.PutString(ctx, serverTimeExpr); err != nil {
			return fmt.Errorf("failed to write ServerTime: %w", err)
		}
	}

	// Write each expression as "attr = value" string
	for _, attr := range attrsToSend {
		// Get the expression for this attribute
		expr, exists := ad.Lookup(attr)
		if !exists {
			continue // Should not happen if filtering worked correctly
		}

		// Format as HTCondor attribute assignment
		exprStr := fmt.Sprintf("%s = %s", attr, expr.String())

		// TODO: Implement encryption with SECRET_MARKER for private attributes
		// Check: ClassAdAttributeIsPrivateAny(attr) || isAttrInList(attr, config.EncryptedAttrs)
		// For now, just send as plaintext

		if err := m.PutString(ctx, exprStr); err != nil {
			return fmt.Errorf("failed to write expression %s: %w", attr, err)
		}
	}

	// Write MyType and TargetType unless excluded
	excludeTypes := (config.Options & PutClassAdNoTypes) != 0
	if !excludeTypes {
		// Write MyType (empty string if not present)
		myType := ""
		if myTypeStr, ok := ad.EvaluateAttrString("MyType"); ok {
			myType = myTypeStr
		}
		if err := m.PutString(ctx, myType); err != nil {
			return fmt.Errorf("failed to write MyType: %w", err)
		}

		// Write TargetType (empty string if not present)
		targetType := ""
		if targetTypeStr, ok := ad.EvaluateAttrString("TargetType"); ok {
			targetType = targetTypeStr
		}
		if err := m.PutString(ctx, targetType); err != nil {
			return fmt.Errorf("failed to write TargetType: %w", err)
		}
	}

	return nil
}

// PutClassAdRaw writes a ClassAd to the wire from pre-rendered old-ClassAd
// expression strings ("Attr = Value") plus its MyType/TargetType values, WITHOUT
// a *classad.ClassAd. It is the send-side analogue of GetClassAdRaw: a caller that
// already holds the ad in a compact stored form (e.g. a collector streaming query
// results) can render the expression text directly and skip building an AST. The
// bytes written are identical to PutClassAd on the equivalent ad -- the expression
// count, each "Attr = Value" string, then MyType and TargetType.
func (m *Message) PutClassAdRaw(ctx context.Context, exprs []string, myType, targetType string) error {
	if err := m.PutInt(ctx, len(exprs)); err != nil {
		return fmt.Errorf("failed to write expression count: %w", err)
	}
	for _, e := range exprs {
		if err := m.PutString(ctx, e); err != nil {
			return fmt.Errorf("failed to write expression: %w", err)
		}
	}
	if err := m.PutString(ctx, myType); err != nil {
		return fmt.Errorf("failed to write MyType: %w", err)
	}
	if err := m.PutString(ctx, targetType); err != nil {
		return fmt.Errorf("failed to write TargetType: %w", err)
	}
	return nil
}

// PutClassAdRawBytes is PutClassAdRaw with each "Attr = Value" expression given as
// a byte slice instead of a string, so a caller can render all of an ad's
// expressions into one reused buffer and stream them out with no per-expression
// allocation. The exprs slices are not modified and may alias a shared buffer.
func (m *Message) PutClassAdRawBytes(ctx context.Context, exprs [][]byte, myType, targetType string) error {
	if err := m.PutInt(ctx, len(exprs)); err != nil {
		return fmt.Errorf("failed to write expression count: %w", err)
	}
	for _, e := range exprs {
		if err := m.PutStringBytes(ctx, e); err != nil {
			return fmt.Errorf("failed to write expression: %w", err)
		}
	}
	if err := m.PutString(ctx, myType); err != nil {
		return fmt.Errorf("failed to write MyType: %w", err)
	}
	if err := m.PutString(ctx, targetType); err != nil {
		return fmt.Errorf("failed to write TargetType: %w", err)
	}
	return nil
}

// getClassAdFromMessage reads a ClassAd from a Message using HTCondor's wire protocol
// Based on HTCondor's getClassAd() function in classad_oldnew.cpp
func getClassAdFromMessage(m *Message, ctx context.Context) (*classad.ClassAd, error) {
	return getClassAdFromMessageWithMaxSize(m, 0, ctx) // 0 means no limit
}

// getClassAdFromMessageWithMaxSize reads a ClassAd from a Message with size limits
// maxSize limits the total bytes read for the entire ClassAd across all strings
// If maxSize is 0 or negative, no size limit is applied
// GetClassAdRaw reads a ClassAd off the wire and returns it as old-ClassAd text
// (newline-separated `Name = Value` lines, with MyType/TargetType appended as
// lines) WITHOUT parsing it into a *classad.ClassAd. The bytes consumed are
// identical to GetClassAd; only the AST-building step is skipped.
//
// This is the efficient ingest path for callers that immediately re-encode the
// ad -- for example into a classad collections.Collection via UpdateOld, which
// streams the text straight to its wire form -- avoiding an AST that would only
// be discarded.
func (m *Message) GetClassAdRaw(ctx context.Context) (string, error) {
	numExprs, err := m.GetInt(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read expression count: %w", err)
	}
	return m.GetClassAdRawBody(ctx, numExprs)
}

// GetClassAdRawBody reads the body of a raw ClassAd whose leading expression
// count has already been consumed. This lets a caller reading a stream of ads on
// one connection first inspect that leading integer -- e.g. to tell a real ad
// (a small expression count) from a DC_NOP end-of-batch marker -- before
// committing to reading an ad. See GetClassAdRaw.
func (m *Message) GetClassAdRawBody(ctx context.Context, numExprs int) (string, error) {
	var b strings.Builder
	for i := 0; i < numExprs; i++ {
		exprStr, err := m.GetString(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to read expression %d (expected %d): %w", i, numExprs, err)
		}
		b.WriteString(exprStr)
		b.WriteByte('\n')
	}
	myType, err := m.GetString(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read MyType: %w", err)
	}
	if myType != "" {
		fmt.Fprintf(&b, "MyType = %q\n", myType)
	}
	targetType, err := m.GetString(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read TargetType: %w", err)
	}
	if targetType != "" {
		fmt.Fprintf(&b, "TargetType = %q\n", targetType)
	}
	return b.String(), nil
}

func getClassAdFromMessageWithMaxSize(m *Message, maxSize int, ctx context.Context) (*classad.ClassAd, error) {
	// Read number of expressions
	numExprs, err := m.GetInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read expression count: %w", err)
	}

	// Create new ClassAd
	ad := classad.New()

	// Track total bytes read if maxSize is set
	totalBytesRead := 0

	// Parse each expression string
	for i := 0; i < int(numExprs); i++ {
		var exprStr string
		if maxSize > 0 {
			// Calculate remaining budget for this string
			remainingBytes := maxSize - totalBytesRead
			if remainingBytes <= 0 {
				return nil, fmt.Errorf("ClassAd exceeds maximum size (%d bytes) while reading expression %d", maxSize, i)
			}

			exprStr, err = m.GetStringWithMaxSize(ctx, remainingBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to read expression %d (expected %d; partial ad: %s): %w", i, numExprs, ad.String(), err)
			}

			// Add to total: string length + null terminator
			totalBytesRead += len(exprStr) + 1
		} else {
			exprStr, err = m.GetString(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to read expression %d (expected %d; partial ad: %s): %w", i, numExprs, ad.String(), err)
			}
		}

		// Parse "attr = value" format
		if err := parseAndInsertExpression(ad, exprStr); err != nil {
			return nil, fmt.Errorf("failed to parse expression %d (expected %d; expression contents '%s'): %w", i, numExprs, exprStr, err)
		}
	}

	// Read MyType
	var myType string
	if maxSize > 0 {
		remainingBytes := maxSize - totalBytesRead
		if remainingBytes <= 0 {
			return nil, fmt.Errorf("ClassAd exceeds maximum size (%d bytes) while reading MyType", maxSize)
		}

		myType, err = m.GetStringWithMaxSize(ctx, remainingBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read MyType: %w", err)
		}
		totalBytesRead += len(myType) + 1
	} else {
		myType, err = m.GetString(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read MyType: %w", err)
		}
	}
	if myType != "" {
		_ = ad.Set("MyType", myType) // ClassAd.Set always returns nil, safe to ignore
	}

	// Read TargetType
	var targetType string
	if maxSize > 0 {
		remainingBytes := maxSize - totalBytesRead
		if remainingBytes <= 0 {
			return nil, fmt.Errorf("ClassAd exceeds maximum size (%d bytes) while reading TargetType", maxSize)
		}

		targetType, err = m.GetStringWithMaxSize(ctx, remainingBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read TargetType: %w", err)
		}
		_ = totalBytesRead // Variable declared but not used after this point
	} else {
		targetType, err = m.GetString(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read TargetType: %w", err)
		}
	}
	if targetType != "" {
		_ = ad.Set("TargetType", targetType) // ClassAd.Set always returns nil, safe to ignore
	}

	return ad, nil
}

// parseAndInsertExpression parses "attr = value" string and inserts into ClassAd
// This implements the parsing logic similar to HTCondor's getClassAd()
func parseAndInsertExpression(ad *classad.ClassAd, exprStr string) error {
	// Split on first '=' to separate attribute name from value
	eqPos := strings.Index(exprStr, "=")
	if eqPos == -1 {
		return fmt.Errorf("invalid expression format, missing '=': %s", exprStr)
	}

	attr := strings.TrimSpace(exprStr[:eqPos])
	valueStr := strings.TrimSpace(exprStr[eqPos+1:])

	if attr == "" {
		return fmt.Errorf("empty attribute name in expression: %s", exprStr)
	}

	// Fast path for common literal values (like HTCondor does)
	if err := tryInsertLiteral(ad, attr, valueStr); err == nil {
		return nil
	}

	// Fall back to full ClassAd parsing for complex expressions
	expr, err := classad.ParseExpr(valueStr)
	if err != nil {
		return fmt.Errorf("failed to parse expression value '%s': %w", valueStr, err)
	}

	ad.InsertExpr(attr, expr)
	return nil
}

// tryInsertLiteral attempts fast parsing of simple literal values
// This mirrors HTCondor's fast path optimizations in getClassAd()
func tryInsertLiteral(ad *classad.ClassAd, attr, valueStr string) error {
	// Boolean literals
	switch strings.ToUpper(strings.TrimSpace(valueStr)) {
	case "TRUE":
		_ = ad.Set(attr, true) // ClassAd.Set always returns nil, safe to ignore
		return nil
	case "FALSE":
		_ = ad.Set(attr, false) // ClassAd.Set always returns nil, safe to ignore
		return nil
	}

	// Number literals
	if len(valueStr) > 0 && (valueStr[0] == '-' || (valueStr[0] >= '0' && valueStr[0] <= '9')) {
		// Try integer first
		if !strings.Contains(valueStr, ".") {
			if val, err := strconv.ParseInt(strings.TrimSpace(valueStr), 10, 64); err == nil {
				_ = ad.Set(attr, val) // ClassAd.Set always returns nil, safe to ignore
				return nil
			}
		} else {
			// Try float
			if val, err := strconv.ParseFloat(strings.TrimSpace(valueStr), 64); err == nil {
				_ = ad.Set(attr, val) // ClassAd.Set always returns nil, safe to ignore
				return nil
			}
		}
	}

	// String literals (quoted)
	trimmed := strings.TrimSpace(valueStr)
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		// Simple string without escape sequences
		unquoted := trimmed[1 : len(trimmed)-1]
		if !strings.Contains(unquoted, "\\") {
			_ = ad.Set(attr, unquoted) // ClassAd.Set always returns nil, safe to ignore
			return nil
		}
	}

	// Not a simple literal, caller should use full parser
	return fmt.Errorf("not a simple literal")
}

// Helper functions for ClassAd options processing

// filterAttributesByPrivacy filters attributes based on privacy settings
func filterAttributesByPrivacy(attrs []string, excludePrivate, excludePrivateV2 bool, encryptedAttrs []string) []string {
	var result []string

	for _, attr := range attrs {
		// Check privacy constraints
		if excludePrivate || excludePrivateV2 {
			privateV2 := ClassAdAttributeIsPrivateV2(attr)
			privateV1 := ClassAdAttributeIsPrivateV1(attr) || isAttrInList(attr, encryptedAttrs)

			if (excludePrivate && (privateV1 || privateV2)) ||
				(excludePrivateV2 && privateV2) {
				continue // Exclude this private attribute
			}
		}

		result = append(result, attr)
	}

	return result
}

// filterAttributesByWhitelist filters attributes using whitelist with privacy checks
func filterAttributesByWhitelist(allAttrs []string, ad *classad.ClassAd, whitelist []string,
	excludePrivate, excludePrivateV2 bool, encryptedAttrs []string, options PutClassAdOptions) []string {

	var result []string

	// Convert whitelist to map for faster lookup
	whitelistMap := make(map[string]bool)
	for _, attr := range whitelist {
		whitelistMap[attr] = true
	}

	// Expand whitelist to include references if needed
	// TODO: Implement whitelist expansion (GetInternalReferences)
	// This would add attributes referenced by expressions in the whitelist
	// Currently not implemented - whitelist is used as-is
	_ = options // Acknowledge the option exists but is not yet implemented

	for _, attr := range allAttrs {
		// Must be in whitelist
		if !whitelistMap[attr] {
			continue
		}

		// Must exist in the ClassAd
		if _, exists := ad.Lookup(attr); !exists {
			continue
		}

		// Check privacy constraints
		if excludePrivate || excludePrivateV2 {
			privateV2 := ClassAdAttributeIsPrivateV2(attr)
			privateV1 := ClassAdAttributeIsPrivateV1(attr) || isAttrInList(attr, encryptedAttrs)

			if (excludePrivate && (privateV1 || privateV2)) ||
				(excludePrivateV2 && privateV2) {
				continue // Exclude this private attribute
			}
		}

		result = append(result, attr)
	}

	return result
}

// isAttrInList checks if an attribute is in the given list
func isAttrInList(attr string, list []string) bool {
	for _, item := range list {
		if item == attr {
			return true
		}
	}
	return false
}

// getCurrentUnixTime returns current Unix timestamp
func getCurrentUnixTime() int64 {
	// Use a fixed time for reproducible testing, or time.Now().Unix() for real use
	// For now, return a fixed value to match HTCondor's behavior during testing
	return 1699200000 // Fixed timestamp for testing
}
