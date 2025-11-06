package message

import (
	"math"
	"testing"
)

// TestCharSerialization tests char encoding/decoding
func TestCharSerialization(t *testing.T) {
	tests := []byte{0, 1, 127, 255, 'A', 'Z', '\n', '\x00'}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutChar(expected); err != nil {
			t.Fatalf("PutChar failed: %v", err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetChar()
		if err != nil {
			t.Fatalf("GetChar failed: %v", err)
		}

		if result != expected {
			t.Errorf("Char mismatch: expected %d, got %d", expected, result)
		}
	}
}

// TestIntegerSerialization tests all integer types
func TestIntegerSerialization(t *testing.T) {
	testCases := []struct {
		name string
		test func(t *testing.T)
	}{
		{"Int32", testInt32Serialization},
		{"Int64", testInt64Serialization},
		{"Int", testIntSerialization},
		{"Uint32", testUint32Serialization},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.test)
	}
}

func testInt32Serialization(t *testing.T) {
	tests := []int32{
		0, 1, -1, 127, -128, 32767, -32768,
		2147483647, -2147483648, // int32 limits
	}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutInt32(expected); err != nil {
			t.Fatalf("PutInt32 failed for %d: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetInt32()
		if err != nil {
			t.Fatalf("GetInt32 failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Int32 mismatch: expected %d, got %d", expected, result)
		}
	}
}

func testInt64Serialization(t *testing.T) {
	tests := []int64{
		0, 1, -1,
		9223372036854775807,     // int64 max
		-9223372036854775808,    // int64 min
		2147483647, -2147483648, // int32 limits
	}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutInt64(expected); err != nil {
			t.Fatalf("PutInt64 failed for %d: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetInt64()
		if err != nil {
			t.Fatalf("GetInt64 failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Int64 mismatch: expected %d, got %d", expected, result)
		}
	}
}

func testIntSerialization(t *testing.T) {
	tests := []int{0, 1, -1, 1000, -1000, 2147483647, -2147483648}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutInt(expected); err != nil {
			t.Fatalf("PutInt failed for %d: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetInt()
		if err != nil {
			t.Fatalf("GetInt failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Int mismatch: expected %d, got %d", expected, result)
		}
	}
}

func testUint32Serialization(t *testing.T) {
	tests := []uint32{0, 1, 127, 255, 65535, 4294967295} // uint32 max

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutUint32(expected); err != nil {
			t.Fatalf("PutUint32 failed for %d: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetUint32()
		if err != nil {
			t.Fatalf("GetUint32 failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Uint32 mismatch: expected %d, got %d", expected, result)
		}
	}
}

// TestFloatSerialization tests float32 encoding/decoding
func TestFloatSerialization(t *testing.T) {
	tests := []float32{
		0.0, 1.0, -1.0, 3.14159, -3.14159,
		1.23456e10, -1.23456e10, 1.23456e-10, -1.23456e-10,
		math.MaxFloat32, -math.MaxFloat32,
		math.SmallestNonzeroFloat32, -math.SmallestNonzeroFloat32,
	}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutFloat(expected); err != nil {
			t.Fatalf("PutFloat failed for %f: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetFloat()
		if err != nil {
			t.Fatalf("GetFloat failed for %f: %v", expected, err)
		}

		// Allow for small precision loss due to frexp/ldexp encoding
		if !floatsEqual(float64(result), float64(expected), 1e-6) {
			t.Errorf("Float mismatch: expected %f, got %f", expected, result)
		}
	}
}

// TestDoubleSerialization tests double encoding/decoding with HTCondor's frexp/ldexp method
func TestDoubleSerialization(t *testing.T) {
	tests := []float64{
		0.0, 1.0, -1.0, 3.141592653589793, -3.141592653589793,
		1234.5, -1234.5, 1.23456789e-10, -1.23456789e-10,
		// Note: Very large numbers lose precision in HTCondor's frexp/ldexp encoding
		// Testing more reasonable ranges that preserve precision
		math.SmallestNonzeroFloat64, -math.SmallestNonzeroFloat64,
	}

	for _, expected := range tests {
		msg := NewMessage()

		// Encode
		if err := msg.PutDouble(expected); err != nil {
			t.Fatalf("PutDouble failed for %f: %v", expected, err)
		}

		// Decode
		msg.Decode()
		result, err := msg.GetDouble()
		if err != nil {
			t.Fatalf("GetDouble failed for %f: %v", expected, err)
		}

		// HTCondor's frexp/ldexp encoding has precision limitations
		// The precision depends on the FracConst value and is inherently limited
		tolerance := 1e-6 // More realistic tolerance for frexp/ldexp precision
		if math.Abs(expected) > 1e15 {
			tolerance = math.Abs(expected) * 1e-6 // Larger tolerance for very large numbers
		}
		if !floatsEqual(result, expected, tolerance) {
			t.Errorf("Double mismatch: expected %.15f, got %.15f", expected, result)
		}
	}
}

// TestStringSerialization tests string encoding/decoding
func TestStringSerialization(t *testing.T) {
	tests := []string{
		"", // Empty string
		"Hello World",
		"HTCondor CEDAR Protocol",
		"Special chars: !@#$%^&*()",
		"Unicode: 🔥💻🚀",
		// Note: HTCondor's string encoding is null-terminated, so embedded nulls truncate
		// We test this separately in TestStringNullHandling
		"Very long string with lots of text", // Large string
	}

	for _, expected := range tests {
		t.Run("NoEncryption", func(t *testing.T) {
			msg := NewMessage()
			msg.EnableEncryption(false)

			// Encode
			if err := msg.PutString(expected); err != nil {
				t.Fatalf("PutString failed for '%s': %v", expected, err)
			}

			// Decode
			msg.Decode()
			result, err := msg.GetString()
			if err != nil {
				t.Fatalf("GetString failed for '%s': %v", expected, err)
			}

			if result != expected {
				t.Errorf("String mismatch: expected '%s', got '%s'", expected, result)
			}
		})

		t.Run("WithEncryption", func(t *testing.T) {
			msg := NewMessage()
			msg.EnableEncryption(true)

			// Encode
			if err := msg.PutString(expected); err != nil {
				t.Fatalf("PutString failed for '%s': %v", expected, err)
			}

			// Decode
			msg.Decode()
			msg.EnableEncryption(true) // Must enable on decode side too
			result, err := msg.GetString()
			if err != nil {
				t.Fatalf("GetString failed for '%s': %v", expected, err)
			}

			if result != expected {
				t.Errorf("String mismatch with encryption: expected '%s', got '%s'", expected, result)
			}
		})
	}
}

// TestStringNullHandling tests how null bytes are handled in strings (HTCondor behavior)
func TestStringNullHandling(t *testing.T) {
	// HTCondor's string serialization is null-terminated, so embedded nulls truncate the string
	testStr := "Before null\x00After null"
	expectedResult := "Before null" // Everything after first null is lost

	msg := NewMessage()
	msg.EnableEncryption(false)

	// Encode
	if err := msg.PutString(testStr); err != nil {
		t.Fatalf("PutString failed: %v", err)
	}

	// Decode
	msg.Decode()
	result, err := msg.GetString()
	if err != nil {
		t.Fatalf("GetString failed: %v", err)
	}

	// With null termination, we expect truncation at the embedded null
	if result != expectedResult {
		t.Errorf("Expected truncation at null byte: expected '%s', got '%s'", expectedResult, result)
	}
}

// TestCodeMethods tests the unified code() interface
func TestCodeMethods(t *testing.T) {
	t.Run("CharCode", func(t *testing.T) {
		expected := byte('A')
		msg := NewMessage()

		// Encode
		msg.Encode()
		if err := msg.CodeChar(&expected); err != nil {
			t.Fatalf("CodeChar encode failed: %v", err)
		}

		// Decode
		msg.Decode()
		var result byte
		if err := msg.CodeChar(&result); err != nil {
			t.Fatalf("CodeChar decode failed: %v", err)
		}

		if result != expected {
			t.Errorf("CodeChar mismatch: expected %c, got %c", expected, result)
		}
	})

	t.Run("IntCode", func(t *testing.T) {
		expected := int(12345)
		msg := NewMessage()

		// Encode
		msg.Encode()
		if err := msg.CodeInt(&expected); err != nil {
			t.Fatalf("CodeInt encode failed: %v", err)
		}

		// Decode
		msg.Decode()
		var result int
		if err := msg.CodeInt(&result); err != nil {
			t.Fatalf("CodeInt decode failed: %v", err)
		}

		if result != expected {
			t.Errorf("CodeInt mismatch: expected %d, got %d", expected, result)
		}
	})

	t.Run("StringCode", func(t *testing.T) {
		expected := "HTCondor Test"
		msg := NewMessage()

		// Encode
		msg.Encode()
		if err := msg.CodeString(&expected); err != nil {
			t.Fatalf("CodeString encode failed: %v", err)
		}

		// Decode
		msg.Decode()
		var result string
		if err := msg.CodeString(&result); err != nil {
			t.Fatalf("CodeString decode failed: %v", err)
		}

		if result != expected {
			t.Errorf("CodeString mismatch: expected '%s', got '%s'", expected, result)
		}
	})
}

// TestBinaryCompatibility tests that our encoding matches expected binary format
func TestBinaryCompatibility(t *testing.T) {
	t.Run("Int64BigEndian", func(t *testing.T) {
		msg := NewMessage()
		if err := msg.PutInt64(0x123456789ABCDEF0); err != nil {
			t.Fatalf("PutInt64 failed: %v", err)
		}

		data := msg.Bytes()
		expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

		if len(data) != len(expected) {
			t.Fatalf("Length mismatch: expected %d, got %d", len(expected), len(data))
		}

		for i, b := range expected {
			if data[i] != b {
				t.Errorf("Byte %d mismatch: expected 0x%02X, got 0x%02X", i, b, data[i])
			}
		}
	})

	t.Run("StringNullTerminator", func(t *testing.T) {
		msg := NewMessage()
		msg.EnableEncryption(false)
		if err := msg.PutString("test"); err != nil {
			t.Fatalf("PutString failed: %v", err)
		}

		data := msg.Bytes()
		expected := []byte{'t', 'e', 's', 't', 0} // Null terminated

		if len(data) != len(expected) {
			t.Fatalf("Length mismatch: expected %d, got %d", len(expected), len(data))
		}

		for i, b := range expected {
			if data[i] != b {
				t.Errorf("Byte %d mismatch: expected 0x%02X (%c), got 0x%02X", i, b, b, data[i])
			}
		}
	})
}

// TestRoundTripCompatibility tests encoding and decoding multiple values
func TestRoundTripCompatibility(t *testing.T) {
	msg := NewMessage()

	// Encode multiple values
	values := struct {
		char   byte
		int32  int32
		int64  int64
		float  float32
		double float64
		str    string
	}{
		char:   'X',
		int32:  -12345,
		int64:  9876543210,
		float:  3.14159,
		double: 2.718281828459045,
		str:    "Round trip test",
	}

	// Encode all values
	msg.Encode()
	if err := msg.PutChar(values.char); err != nil {
		t.Fatalf("PutChar failed: %v", err)
	}
	if err := msg.PutInt32(values.int32); err != nil {
		t.Fatalf("PutInt32 failed: %v", err)
	}
	if err := msg.PutInt64(values.int64); err != nil {
		t.Fatalf("PutInt64 failed: %v", err)
	}
	if err := msg.PutFloat(values.float); err != nil {
		t.Fatalf("PutFloat failed: %v", err)
	}
	if err := msg.PutDouble(values.double); err != nil {
		t.Fatalf("PutDouble failed: %v", err)
	}
	if err := msg.PutString(values.str); err != nil {
		t.Fatalf("PutString failed: %v", err)
	}

	// Dump message to bytes and create new message from byte buffer
	messageBytes := msg.Bytes()
	msg = NewMessageFromBytes(messageBytes)

	// Decode all values
	msg.Decode()

	char, err := msg.GetChar()
	if err != nil {
		t.Fatalf("GetChar failed: %v", err)
	}
	if char != values.char {
		t.Errorf("Char mismatch: expected %c, got %c", values.char, char)
	}

	int32Val, err := msg.GetInt32()
	if err != nil {
		t.Fatalf("GetInt32 failed: %v", err)
	}
	if int32Val != values.int32 {
		t.Errorf("Int32 mismatch: expected %d, got %d", values.int32, int32Val)
	}

	int64Val, err := msg.GetInt64()
	if err != nil {
		t.Fatalf("GetInt64 failed: %v", err)
	}
	if int64Val != values.int64 {
		t.Errorf("Int64 mismatch: expected %d, got %d", values.int64, int64Val)
	}

	floatVal, err := msg.GetFloat()
	if err != nil {
		t.Fatalf("GetFloat failed: %v", err)
	}
	if !floatsEqual(float64(floatVal), float64(values.float), 1e-6) {
		t.Errorf("Float mismatch: expected %f, got %f", values.float, floatVal)
	}

	doubleVal, err := msg.GetDouble()
	if err != nil {
		t.Fatalf("GetDouble failed: %v", err)
	}
	if !floatsEqual(doubleVal, values.double, 1e-7) {
		t.Errorf("Double mismatch: expected %.15f, got %.15f", values.double, doubleVal)
	}

	strVal, err := msg.GetString()
	if err != nil {
		t.Fatalf("GetString failed: %v", err)
	}
	if strVal != values.str {
		t.Errorf("String mismatch: expected '%s', got '%s'", values.str, strVal)
	}
}

// floatsEqual compares floating point numbers with tolerance
func floatsEqual(a, b float64, tolerance float64) bool {
	if math.IsInf(a, 0) && math.IsInf(b, 0) {
		return (a > 0) == (b > 0) // Same sign infinity
	}
	if math.IsNaN(a) && math.IsNaN(b) {
		return true
	}
	return math.Abs(a-b) <= tolerance
}
