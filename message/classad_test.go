// Test file for ClassAd serialization
package message

import (
	"bytes"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestClassAdSerialization(t *testing.T) {
	t.Run("BasicClassAd", func(t *testing.T) {
		// Create a test ClassAd
		ad := classad.New()
		ad.Set("Arch", "x86_64")
		ad.Set("OpSys", "LINUX")
		ad.Set("Memory", int64(8192))
		ad.Set("Cpus", int64(4))
		ad.Set("LoadAvg", 1.5)
		ad.Set("HasVirtualization", true)

		// Serialize
		msg := NewMessage()
		err := msg.PutClassAd(ad)
		if err != nil {
			t.Fatalf("Failed to serialize ClassAd: %v", err)
		}

		// Deserialize
		data := msg.Bytes()
		msg2 := NewMessage()
		msg2.buffer = bytes.NewBuffer(data)

		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize ClassAd: %v", err)
		}

		// Verify attributes
		testCases := []struct {
			attr     string
			expected interface{}
		}{
			{"Arch", "x86_64"},
			{"OpSys", "LINUX"},
			{"Memory", int64(8192)},
			{"Cpus", int64(4)},
			{"LoadAvg", 1.5},
			{"HasVirtualization", true},
		}

		for _, tc := range testCases {
			switch expected := tc.expected.(type) {
			case string:
				if val, ok := ad2.EvaluateAttrString(tc.attr); !ok || val != expected {
					t.Errorf("Attribute %s: expected %v, got %v (ok=%v)", tc.attr, expected, val, ok)
				}
			case int64:
				if val, ok := ad2.EvaluateAttrInt(tc.attr); !ok || val != expected {
					t.Errorf("Attribute %s: expected %v, got %v (ok=%v)", tc.attr, expected, val, ok)
				}
			case float64:
				if val, ok := ad2.EvaluateAttrReal(tc.attr); !ok || val != expected {
					t.Errorf("Attribute %s: expected %v, got %v (ok=%v)", tc.attr, expected, val, ok)
				}
			case bool:
				if val, ok := ad2.EvaluateAttrBool(tc.attr); !ok || val != expected {
					t.Errorf("Attribute %s: expected %v, got %v (ok=%v)", tc.attr, expected, val, ok)
				}
			}
		}
	})

	t.Run("ClassAdWithMyTypeTargetType", func(t *testing.T) {
		// Create ClassAd with MyType and TargetType
		ad := classad.New()
		ad.Set("Arch", "x86_64")
		ad.Set("MyType", "Machine")
		ad.Set("TargetType", "Job")

		// Serialize
		msg := NewMessage()
		err := msg.PutClassAd(ad)
		if err != nil {
			t.Fatalf("Failed to serialize ClassAd: %v", err)
		}

		// Deserialize
		data := msg.Bytes()
		msg2 := NewMessage()
		msg2.buffer = bytes.NewBuffer(data)

		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize ClassAd: %v", err)
		}

		// Verify MyType and TargetType
		if myType, ok := ad2.EvaluateAttrString("MyType"); !ok || myType != "Machine" {
			t.Errorf("MyType: expected 'Machine', got '%s' (ok=%v)", myType, ok)
		}

		if targetType, ok := ad2.EvaluateAttrString("TargetType"); !ok || targetType != "Job" {
			t.Errorf("TargetType: expected 'Job', got '%s' (ok=%v)", targetType, ok)
		}

		if arch, ok := ad2.EvaluateAttrString("Arch"); !ok || arch != "x86_64" {
			t.Errorf("Arch: expected 'x86_64', got '%s' (ok=%v)", arch, ok)
		}
	})

	t.Run("EmptyClassAd", func(t *testing.T) {
		// Create empty ClassAd
		ad := classad.New()

		// Serialize
		msg := NewMessage()
		err := msg.PutClassAd(ad)
		if err != nil {
			t.Fatalf("Failed to serialize empty ClassAd: %v", err)
		}

		// Deserialize
		data := msg.Bytes()
		msg2 := NewMessage()
		msg2.buffer = bytes.NewBuffer(data)

		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize empty ClassAd: %v", err)
		}

		// Should have no attributes (except possibly empty MyType/TargetType)
		attrs := ad2.GetAttributes()
		for _, attr := range attrs {
			if attr == "MyType" || attr == "TargetType" {
				// These are OK, should be empty strings
				if val, ok := ad2.EvaluateAttrString(attr); ok && val != "" {
					t.Errorf("Expected empty %s, got '%s'", attr, val)
				}
			} else {
				t.Errorf("Unexpected attribute in empty ClassAd: %s", attr)
			}
		}
	})

	t.Run("ComplexExpressions", func(t *testing.T) {
		// Create ClassAd with complex expressions
		ad := classad.New()
		ad.Set("SimpleString", "test")

		// Add a complex expression by parsing it
		expr, err := classad.ParseExpr("Memory > 4096 && Arch == \"x86_64\"")
		if err != nil {
			t.Fatalf("Failed to parse complex expression: %v", err)
		}
		ad.InsertExpr("Requirements", expr)

		// Add another complex expression
		expr2, err := classad.ParseExpr("strcat(\"Hello\", \" \", \"World\")")
		if err != nil {
			t.Fatalf("Failed to parse string expression: %v", err)
		}
		ad.InsertExpr("Greeting", expr2)

		// Serialize
		msg := NewMessage()
		err = msg.PutClassAd(ad)
		if err != nil {
			t.Fatalf("Failed to serialize complex ClassAd: %v", err)
		}

		// Deserialize
		data := msg.Bytes()
		msg2 := NewMessage()
		msg2.buffer = bytes.NewBuffer(data)

		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize complex ClassAd: %v", err)
		}

		// Verify simple attribute
		if val, ok := ad2.EvaluateAttrString("SimpleString"); !ok || val != "test" {
			t.Errorf("SimpleString: expected 'test', got '%s' (ok=%v)", val, ok)
		}

		// Verify complex expressions exist (we can't easily evaluate them without context)
		if _, exists := ad2.Lookup("Requirements"); !exists {
			t.Error("Requirements expression not found after round-trip")
		}

		if _, exists := ad2.Lookup("Greeting"); !exists {
			t.Error("Greeting expression not found after round-trip")
		}
	})
}

func TestPrivateAttributeDetection(t *testing.T) {
	testCases := []struct {
		name     string
		attr     string
		isPrivV1 bool
		isPrivV2 bool
	}{
		{"PublicAttribute", "Arch", false, false},
		{"PublicAttribute2", "Memory", false, false},
		{"PrivateV1_Capability", "Capability", true, false},
		{"PrivateV1_ClaimId", "ClaimId", true, false},
		{"PrivateV1_TransferKey", "TransferKey", true, false},
		{"PrivateV2_condor_priv", "_condor_priv", false, true},
		{"PrivateV2_condor_privdata", "_condor_privdata", false, true},
		{"PrivateV2_CONDOR_PRIV", "_CONDOR_PRIV", false, true}, // Case insensitive
		{"NotPrivate_condor", "_condor", false, false},         // Too short
		{"NotPrivate_short", "_condor_pri", false, false},      // Too short
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassAdAttributeIsPrivateV1(tc.attr); got != tc.isPrivV1 {
				t.Errorf("ClassAdAttributeIsPrivateV1(%s) = %v, want %v", tc.attr, got, tc.isPrivV1)
			}

			if got := ClassAdAttributeIsPrivateV2(tc.attr); got != tc.isPrivV2 {
				t.Errorf("ClassAdAttributeIsPrivateV2(%s) = %v, want %v", tc.attr, got, tc.isPrivV2)
			}

			expectedAny := tc.isPrivV1 || tc.isPrivV2
			if got := ClassAdAttributeIsPrivateAny(tc.attr); got != expectedAny {
				t.Errorf("ClassAdAttributeIsPrivateAny(%s) = %v, want %v", tc.attr, got, expectedAny)
			}
		})
	}
}

func TestLiteralParsing(t *testing.T) {
	testCases := []struct {
		name      string
		exprStr   string
		expectErr bool
	}{
		{"BoolTrue", "Enabled = TRUE", false},
		{"BoolFalse", "Disabled = FALSE", false},
		{"Integer", "Count = 42", false},
		{"NegativeInteger", "Delta = -10", false},
		{"Float", "Pi = 3.14159", false},
		{"QuotedString", "Name = \"test string\"", false},
		{"ComplexExpr", "Requirement = Memory > 1024", false},
		{"InvalidFormat", "NoEquals", true},
		{"EmptyAttr", " = value", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			err := parseAndInsertExpression(ad, tc.exprStr)

			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			} else if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestClassAdRoundTripCompatibility(t *testing.T) {
	// Test with a realistic HTCondor job ClassAd
	ad := classad.New()

	// Job attributes
	ad.Set("Cmd", "/usr/bin/python")
	ad.Set("Args", "script.py")
	ad.Set("Owner", "user")
	ad.Set("ClusterId", int64(123))
	ad.Set("ProcId", int64(0))
	ad.Set("RequestMemory", int64(2048))
	ad.Set("RequestCpus", int64(1))
	ad.Set("JobStatus", int64(1)) // Idle
	ad.Set("MyType", "Job")
	ad.Set("TargetType", "Machine")

	// Multiple round trips
	for i := 0; i < 3; i++ {
		// Serialize
		msg := NewMessage()
		err := msg.PutClassAd(ad)
		if err != nil {
			t.Fatalf("Round %d: Failed to serialize: %v", i+1, err)
		}

		// Deserialize
		data := msg.Bytes()
		msg2 := NewMessage()
		msg2.buffer = bytes.NewBuffer(data)

		ad, err = msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Round %d: Failed to deserialize: %v", i+1, err)
		}
	}

	// Verify final state
	if cmd, ok := ad.EvaluateAttrString("Cmd"); !ok || cmd != "/usr/bin/python" {
		t.Errorf("Final Cmd: expected '/usr/bin/python', got '%s'", cmd)
	}

	if clusterId, ok := ad.EvaluateAttrInt("ClusterId"); !ok || clusterId != 123 {
		t.Errorf("Final ClusterId: expected 123, got %d", clusterId)
	}

	if myType, ok := ad.EvaluateAttrString("MyType"); !ok || myType != "Job" {
		t.Errorf("Final MyType: expected 'Job', got '%s'", myType)
	}
}

func TestClassAdWithOptions(t *testing.T) {
	t.Run("PrivateAttributeExclusion", func(t *testing.T) {
		// Create ClassAd with private attributes
		ad := classad.New()
		ad.Set("Arch", "x86_64")
		ad.Set("ClaimId", "secret-claim-id") // V1 private
		ad.Set("_condor_privdata", "secret") // V2 private
		ad.Set("PublicAttr", "public-value")

		// Test with private attribute exclusion
		config := &PutClassAdConfig{
			Options: PutClassAdNoPrivate,
		}

		msg := NewMessage()
		err := msg.PutClassAdWithOptions(ad, config)
		if err != nil {
			t.Fatalf("Failed to serialize with private exclusion: %v", err)
		}

		// Deserialize and verify private attributes are excluded
		data := msg.Bytes()
		msg2 := NewMessageFromBytes(data)
		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize: %v", err)
		}

		// Public attributes should be present
		if arch, ok := ad2.EvaluateAttrString("Arch"); !ok || arch != "x86_64" {
			t.Errorf("Public attribute missing: Arch = %s", arch)
		}
		if pub, ok := ad2.EvaluateAttrString("PublicAttr"); !ok || pub != "public-value" {
			t.Errorf("Public attribute missing: PublicAttr = %s", pub)
		}

		// Private attributes should be excluded
		if _, ok := ad2.EvaluateAttrString("ClaimId"); ok {
			t.Error("Private V1 attribute ClaimId should be excluded")
		}
		if _, ok := ad2.EvaluateAttrString("_condor_privdata"); ok {
			t.Error("Private V2 attribute _condor_privdata should be excluded")
		}
	})

	t.Run("WhitelistFiltering", func(t *testing.T) {
		// Create ClassAd with many attributes
		ad := classad.New()
		ad.Set("Arch", "x86_64")
		ad.Set("Memory", int64(8192))
		ad.Set("Cpus", int64(4))
		ad.Set("LoadAvg", 1.5)
		ad.Set("Unwanted", "should-not-appear")

		// Test with whitelist
		config := &PutClassAdConfig{
			Whitelist: []string{"Arch", "Memory", "Cpus"},
		}

		msg := NewMessage()
		err := msg.PutClassAdWithOptions(ad, config)
		if err != nil {
			t.Fatalf("Failed to serialize with whitelist: %v", err)
		}

		// Deserialize and verify only whitelisted attributes are present
		data := msg.Bytes()
		msg2 := NewMessageFromBytes(data)
		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize: %v", err)
		}

		// Whitelisted attributes should be present
		if arch, ok := ad2.EvaluateAttrString("Arch"); !ok || arch != "x86_64" {
			t.Errorf("Whitelisted attribute missing: Arch = %s", arch)
		}
		if mem, ok := ad2.EvaluateAttrInt("Memory"); !ok || mem != 8192 {
			t.Errorf("Whitelisted attribute missing: Memory = %d", mem)
		}
		if cpu, ok := ad2.EvaluateAttrInt("Cpus"); !ok || cpu != 4 {
			t.Errorf("Whitelisted attribute missing: Cpus = %d", cpu)
		}

		// Non-whitelisted attributes should be excluded
		if _, ok := ad2.EvaluateAttrReal("LoadAvg"); ok {
			t.Error("Non-whitelisted attribute LoadAvg should be excluded")
		}
		if _, ok := ad2.EvaluateAttrString("Unwanted"); ok {
			t.Error("Non-whitelisted attribute Unwanted should be excluded")
		}
	})

	t.Run("NoTypesOption", func(t *testing.T) {
		// Create ClassAd with MyType/TargetType
		ad := classad.New()
		ad.Set("Arch", "x86_64")
		ad.Set("MyType", "Machine")
		ad.Set("TargetType", "Job")

		// Test without types
		config := &PutClassAdConfig{
			Options: PutClassAdNoTypes,
		}

		msg := NewMessage()
		err := msg.PutClassAdWithOptions(ad, config)
		if err != nil {
			t.Fatalf("Failed to serialize without types: %v", err)
		}

		// For no-types mode, we need to use a different deserializer
		// or manually parse to verify MyType/TargetType are not sent
		// For now, just verify it doesn't crash
		data := msg.Bytes()
		if len(data) == 0 {
			t.Error("Expected non-empty serialized data")
		}
	})

	t.Run("ServerTimeOption", func(t *testing.T) {
		// Create simple ClassAd
		ad := classad.New()
		ad.Set("Arch", "x86_64")

		// Test with server time
		config := &PutClassAdConfig{
			Options: PutClassAdServerTime,
		}

		msg := NewMessage()
		err := msg.PutClassAdWithOptions(ad, config)
		if err != nil {
			t.Fatalf("Failed to serialize with server time: %v", err)
		}

		// Deserialize and verify ServerTime is present
		data := msg.Bytes()
		msg2 := NewMessageFromBytes(data)
		ad2, err := msg2.GetClassAd()
		if err != nil {
			t.Fatalf("Failed to deserialize: %v", err)
		}

		// ServerTime should be present
		if serverTime, ok := ad2.EvaluateAttrInt("ServerTime"); !ok || serverTime == 0 {
			t.Errorf("ServerTime attribute missing or zero: %d", serverTime)
		}

		// Original attribute should still be present
		if arch, ok := ad2.EvaluateAttrString("Arch"); !ok || arch != "x86_64" {
			t.Errorf("Original attribute missing: Arch = %s", arch)
		}
	})
}
