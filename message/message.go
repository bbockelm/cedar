// Package message provides serialization and deserialization
// of CEDAR protocol messages.
//
// This package implements the type serialization system used by
// HTCondor's CEDAR protocol, based on stream.cpp implementation.
//
// The type serialization follows HTCondor's exact binary format:
// - Integers: 64-bit values in network (big-endian) byte order
// - Doubles: Split into fractional and exponential parts for portability
// - Strings: Null-terminated with optional encryption length prefix
// - All types support bidirectional encoding/decoding
package message

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// Constants from HTCondor stream.cpp
const (
	// FRAC_CONST used for double encoding - must match HTCondor's value
	FracConst = 2147483647 // 2^31 - 1
	// BinNullChar used to represent NULL strings
	BinNullChar = '\255'
	// IntSize is the number of bytes for integers on the wire
	IntSize = 8 // HTCondor sends 64-bit integers
)

// CodingDirection represents the stream direction (encode vs decode)
type CodingDirection int

const (
	CodingEncode CodingDirection = iota
	CodingDecode
	CodingUnknown
)

// Message represents a CEDAR protocol message with HTCondor-compatible serialization
type Message struct {
	buffer    *bytes.Buffer
	direction CodingDirection
	// For string decryption buffer (matches HTCondor's decrypt_buf)
	encryptionEnabled bool
}

// NewMessage creates a new empty message for writing (encode mode)
func NewMessage() *Message {
	return &Message{
		buffer:            &bytes.Buffer{},
		direction:         CodingEncode,
		encryptionEnabled: false,
	}
}

// NewMessageFromBytes creates a message from existing bytes for reading (decode mode)
func NewMessageFromBytes(data []byte) *Message {
	return &Message{
		buffer:            bytes.NewBuffer(data),
		direction:         CodingDecode,
		encryptionEnabled: false,
	}
}

// SetCoding sets the direction for code() operations
func (m *Message) SetCoding(direction CodingDirection) {
	m.direction = direction
}

// IsEncode returns true if in encode mode
func (m *Message) IsEncode() bool {
	return m.direction == CodingEncode
}

// IsDecode returns true if in decode mode
func (m *Message) IsDecode() bool {
	return m.direction == CodingDecode
}

// Encode sets the message to encode mode
func (m *Message) Encode() {
	m.direction = CodingEncode
}

// Decode sets the message to decode mode
func (m *Message) Decode() {
	m.direction = CodingDecode
}

// EnableEncryption enables encryption mode for strings
func (m *Message) EnableEncryption(enabled bool) {
	m.encryptionEnabled = enabled
}

// PutBytes writes raw bytes to the message
func (m *Message) PutBytes(data []byte) (int, error) {
	return m.buffer.Write(data)
}

// GetBytes reads raw bytes from the message
func (m *Message) GetBytes(data []byte) (int, error) {
	return m.buffer.Read(data)
}

//
// CHAR OPERATIONS
//

// PutChar writes a single byte
func (m *Message) PutChar(c byte) error {
	return m.buffer.WriteByte(c)
}

// GetChar reads a single byte
func (m *Message) GetChar() (byte, error) {
	return m.buffer.ReadByte()
}

// CodeChar handles char encoding/decoding based on direction
func (m *Message) CodeChar(c *byte) error {
	switch m.direction {
	case CodingEncode:
		return m.PutChar(*c)
	case CodingDecode:
		var err error
		*c, err = m.GetChar()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

//
// INTEGER OPERATIONS (HTCondor uses 64-bit on wire)
//

// putLongLong writes a 64-bit integer in network byte order (matches HTCondor)
func (m *Message) putLongLong(value int64) error {
	// Convert to network byte order (big-endian)
	networkValue := uint64(value)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, networkValue)
	_, err := m.buffer.Write(buf)
	return err
}

// getLongLong reads a 64-bit integer from network byte order
func (m *Message) getLongLong() (int64, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(m.buffer, buf); err != nil {
		return 0, err
	}
	networkValue := binary.BigEndian.Uint64(buf)
	return int64(networkValue), nil
}

// PutInt writes an int as 64-bit value (HTCondor convention)
func (m *Message) PutInt(value int) error {
	return m.putLongLong(int64(value))
}

// GetInt reads an int from 64-bit value
func (m *Message) GetInt() (int, error) {
	val, err := m.getLongLong()
	return int(val), err
}

// PutInt32 writes an int32 as 64-bit value
func (m *Message) PutInt32(value int32) error {
	return m.putLongLong(int64(value))
}

// GetInt32 reads an int32 from 64-bit value
func (m *Message) GetInt32() (int32, error) {
	val, err := m.getLongLong()
	return int32(val), err
}

// PutInt64 writes an int64 directly
func (m *Message) PutInt64(value int64) error {
	return m.putLongLong(value)
}

// GetInt64 reads an int64 directly
func (m *Message) GetInt64() (int64, error) {
	return m.getLongLong()
}

// PutUint32 writes a uint32 as unsigned 64-bit value
func (m *Message) PutUint32(value uint32) error {
	return m.putLongLong(int64(value))
}

// GetUint32 reads a uint32 from unsigned 64-bit value
func (m *Message) GetUint32() (uint32, error) {
	val, err := m.getLongLong()
	return uint32(val), err
}

// Code methods for integers (HTCondor style)
func (m *Message) CodeInt(value *int) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt(*value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeInt32(value *int32) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt32(*value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt32()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeInt64(value *int64) error {
	switch m.direction {
	case CodingEncode:
		return m.PutInt64(*value)
	case CodingDecode:
		var err error
		*value, err = m.GetInt64()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

//
// FLOATING POINT OPERATIONS (HTCondor's frexp/ldexp encoding)
//

// PutFloat writes a float as double (HTCondor convention)
func (m *Message) PutFloat(value float32) error {
	return m.PutDouble(float64(value))
}

// GetFloat reads a float from double encoding
func (m *Message) GetFloat() (float32, error) {
	val, err := m.GetDouble()
	return float32(val), err
}

// PutDouble writes a double using HTCondor's frexp/ldexp encoding
// This matches stream.cpp's put(double) method exactly
func (m *Message) PutDouble(value float64) error {
	// HTCondor uses frexp to split double into fraction and exponent
	frac, exp := math.Frexp(value)

	// Convert fraction to integer (multiply by FracConst)
	fracInt := int32(frac * float64(FracConst))

	// Write fractional part as int32, then exponent as int32
	if err := m.PutInt32(fracInt); err != nil {
		return err
	}
	return m.PutInt32(int32(exp))
}

// GetDouble reads a double using HTCondor's frexp/ldexp decoding
// This matches stream.cpp's get(double) method exactly
func (m *Message) GetDouble() (float64, error) {
	// Read fractional part and exponent
	fracInt, err := m.GetInt32()
	if err != nil {
		return 0, err
	}

	exp, err := m.GetInt32()
	if err != nil {
		return 0, err
	}

	// Convert back using ldexp (matches HTCondor exactly)
	frac := float64(fracInt) / float64(FracConst)
	return math.Ldexp(frac, int(exp)), nil
}

// Code methods for floating point
func (m *Message) CodeFloat(value *float32) error {
	switch m.direction {
	case CodingEncode:
		return m.PutFloat(*value)
	case CodingDecode:
		var err error
		*value, err = m.GetFloat()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

func (m *Message) CodeDouble(value *float64) error {
	switch m.direction {
	case CodingEncode:
		return m.PutDouble(*value)
	case CodingDecode:
		var err error
		*value, err = m.GetDouble()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

//
// STRING OPERATIONS (HTCondor's null-terminated with encryption support)
//

// PutString writes a string with null terminator (matches HTCondor's put(const char*))
func (m *Message) PutString(s string) error {
	// HTCondor treats empty string same as null - add null terminator
	data := []byte(s + "\x00")
	length := len(data)

	// If encryption enabled, write length first
	if m.encryptionEnabled {
		if err := m.PutInt32(int32(length)); err != nil {
			return err
		}
	}

	// Write string data with null terminator
	_, err := m.buffer.Write(data)
	return err
}

// GetString reads a null-terminated string (matches HTCondor's get(char*&))
func (m *Message) GetString() (string, error) {
	var length int32
	var err error

	// If encryption enabled, read length first
	if m.encryptionEnabled {
		length, err = m.GetInt32()
		if err != nil {
			return "", err
		}

		// Read the specified number of bytes
		data := make([]byte, length)
		if _, err := io.ReadFull(m.buffer, data); err != nil {
			return "", err
		}

		// Check for HTCondor's null string marker
		if len(data) > 0 && data[0] == BinNullChar {
			return "", nil // NULL string in HTCondor
		}

		// Remove null terminator if present
		if len(data) > 0 && data[len(data)-1] == 0 {
			data = data[:len(data)-1]
		}

		return string(data), nil
	} else {
		// Read until null terminator
		var result []byte
		for {
			b, err := m.buffer.ReadByte()
			if err != nil {
				return "", err
			}
			if b == 0 {
				break // Found null terminator
			}
			result = append(result, b)
		}
		return string(result), nil
	}
}

// CodeString handles string encoding/decoding
func (m *Message) CodeString(s *string) error {
	switch m.direction {
	case CodingEncode:
		return m.PutString(*s)
	case CodingDecode:
		var err error
		*s, err = m.GetString()
		return err
	default:
		return fmt.Errorf("unknown coding direction")
	}
}

//
// UTILITY METHODS
//

// Bytes returns the message content as bytes
func (m *Message) Bytes() []byte {
	return m.buffer.Bytes()
}

// Len returns the current message length
func (m *Message) Len() int {
	return m.buffer.Len()
}

// Reset clears the message buffer
func (m *Message) Reset() {
	m.buffer.Reset()
}

// WriteTo writes the message content to a writer
func (m *Message) WriteTo(w io.Writer) (int64, error) {
	return m.buffer.WriteTo(w)
}
