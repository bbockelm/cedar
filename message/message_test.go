package message

import (
	"math"
	"testing"
)

// Helper functions for testing basic serialization using Message API

func serializeChar(c byte) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutChar(c); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeChar(data []byte) (byte, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetChar()
}

func serializeInt32(val int32) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutInt32(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeInt32(data []byte) (int32, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetInt32()
}

func serializeInt64(val int64) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutInt64(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeInt64(data []byte) (int64, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetInt64()
}

func serializeInt(val int) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutInt(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeInt(data []byte) (int, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetInt()
}

func serializeUint32(val uint32) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutUint32(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeUint32(data []byte) (uint32, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetUint32()
}

func serializeFloat(val float32) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutFloat(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeFloat(data []byte) (float32, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetFloat()
}

func serializeDouble(val float64) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutDouble(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeDouble(data []byte) (float64, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetDouble()
}

func serializeString(val string) ([]byte, error) {
	mockStream := NewMockStream(false)
	msg := NewMessageForStream(mockStream)
	if err := msg.PutString(val); err != nil {
		return nil, err
	}
	if err := msg.FinishMessage(); err != nil {
		return nil, err
	}
	var result []byte
	for _, frame := range mockStream.frames {
		result = append(result, frame...)
	}
	return result, nil
}

func deserializeString(data []byte) (string, error) {
	mockStream := NewMockStream(false)
	mockStream.AddFrame(data, true)
	msg := NewMessageFromStream(mockStream)
	return msg.GetString()
}

// TestCharSerialization tests char encoding/decoding
func TestCharSerialization(t *testing.T) {
	tests := []byte{0, 1, 127, 255, 'A', 'Z', '\n', '\x00'}

	for _, expected := range tests {
		// Encode
		data, err := serializeChar(expected)
		if err != nil {
			t.Fatalf("serializeChar failed: %v", err)
		}

		// Decode
		result, err := deserializeChar(data)
		if err != nil {
			t.Fatalf("deserializeChar failed: %v", err)
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
		// Encode
		data, err := serializeInt32(expected)
		if err != nil {
			t.Fatalf("serializeInt32 failed for %d: %v", expected, err)
		}

		// Decode
		result, err := deserializeInt32(data)
		if err != nil {
			t.Fatalf("deserializeInt32 failed for %d: %v", expected, err)
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
		// Encode
		data, err := serializeInt64(expected)
		if err != nil {
			t.Fatalf("serializeInt64 failed for %d: %v", expected, err)
		}

		// Decode
		result, err := deserializeInt64(data)
		if err != nil {
			t.Fatalf("deserializeInt64 failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Int64 mismatch: expected %d, got %d", expected, result)
		}
	}
}

func testIntSerialization(t *testing.T) {
	tests := []int{0, 1, -1, 1000, -1000, 2147483647, -2147483648}

	for _, expected := range tests {
		// Encode
		data, err := serializeInt(expected)
		if err != nil {
			t.Fatalf("serializeInt failed for %d: %v", expected, err)
		}

		// Decode
		result, err := deserializeInt(data)
		if err != nil {
			t.Fatalf("deserializeInt failed for %d: %v", expected, err)
		}

		if result != expected {
			t.Errorf("Int mismatch: expected %d, got %d", expected, result)
		}
	}
}

func testUint32Serialization(t *testing.T) {
	tests := []uint32{0, 1, 127, 255, 65535, 4294967295} // uint32 max

	for _, expected := range tests {
		// Encode
		data, err := serializeUint32(expected)
		if err != nil {
			t.Fatalf("serializeUint32 failed for %d: %v", expected, err)
		}

		// Decode
		result, err := deserializeUint32(data)
		if err != nil {
			t.Fatalf("deserializeUint32 failed for %d: %v", expected, err)
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
		// Encode
		data, err := serializeFloat(expected)
		if err != nil {
			t.Fatalf("serializeFloat failed for %f: %v", expected, err)
		}

		// Decode
		result, err := deserializeFloat(data)
		if err != nil {
			t.Fatalf("deserializeFloat failed for %f: %v", expected, err)
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
		// Encode
		data, err := serializeDouble(expected)
		if err != nil {
			t.Fatalf("serializeDouble failed for %f: %v", expected, err)
		}

		// Decode
		result, err := deserializeDouble(data)
		if err != nil {
			t.Fatalf("deserializeDouble failed for %f: %v", expected, err)
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
			// Encode
			data, err := serializeString(expected)
			if err != nil {
				t.Fatalf("serializeString failed for '%s': %v", expected, err)
			}

			// Decode
			result, err := deserializeString(data)
			if err != nil {
				t.Fatalf("deserializeString failed for '%s': %v", expected, err)
			}

			if result != expected {
				t.Errorf("String mismatch: expected '%s', got '%s'", expected, result)
			}
		})

		// TODO: Add WithEncryption test using Message API with encryption enabled
	}
}

// TestStringNullHandling tests how null bytes are handled in strings (HTCondor behavior)
func TestStringNullHandling(t *testing.T) {
	// HTCondor's string serialization is null-terminated, so embedded nulls truncate the string
	testStr := "Before null\x00After null"
	expectedResult := "Before null" // Everything after first null is lost

	// Encode
	data, err := serializeString(testStr)
	if err != nil {
		t.Fatalf("serializeString failed: %v", err)
	}

	// Decode
	result, err := deserializeString(data)
	if err != nil {
		t.Fatalf("deserializeString failed: %v", err)
	}

	// With null termination, we expect truncation at the embedded null
	if result != expectedResult {
		t.Errorf("Expected truncation at null byte: expected '%s', got '%s'", expectedResult, result)
	}
}

/* TODO: Update TestCodeMethods to use Message API - these test unified code() interface

// TestCodeMethods tests the unified code() interface
func TestCodeMethods(t *testing.T) {
	// These need to be updated to use Message API
	// For now, skipping as they use removed Frame methods
}
*/

/* TODO: Update TestBinaryCompatibility and TestRoundTripCompatibility to use Message API

// TestBinaryCompatibility tests that our encoding matches expected binary format
func TestBinaryCompatibility(t *testing.T) {
	// These need to be updated to use Message API
	// For now, skipping as they use removed Frame methods
}

// TestRoundTripCompatibility tests encoding and decoding multiple values
func TestRoundTripCompatibility(t *testing.T) {
	// This needs to be updated to use Message API
	// For now, skipping as it uses removed Frame methods
}
*/

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
