// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package stream provides low-level TCP socket stream management
// and message framing for the CEDAR protocol.
//
// This package implements the binary framing protocol that wraps
// messages before sending them over TCP sockets, based on HTCondor's
// reli_sock.cpp implementation.
package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
)

// Stream represents a CEDAR protocol stream over a TCP connection
type Stream struct {
	conn   net.Conn
	reader io.Reader
	writer io.Writer

	// Security settings
	encrypted     bool
	authenticated bool

	// AES-GCM encryption
	gcm        cipher.AEAD
	encryptKey []byte

	// Nonce/IV state tracking (matches HTCondor's approach)
	encryptIV      [16]byte // Base IV for encryption (16 bytes for GCM)
	decryptIV      [16]byte // Base IV for decryption (16 bytes for GCM)
	encryptCounter uint32   // Message counter for encryption
	decryptCounter uint32   // Message counter for decryption

	// AAD (Additional Authenticated Data) support for HTCondor compatibility
	sendDigest      hash.Hash // SHA-256 digest of all sent data
	recvDigest      hash.Hash // SHA-256 digest of all received data
	finishedSendAAD bool      // True after first encrypted frame is sent
	finishedRecvAAD bool      // True after first encrypted frame is received
	finalSendDigest []byte    // Final digest of all sent data (32 bytes)
	finalRecvDigest []byte    // Final digest of all received data (32 bytes)

	// EOM (End of Message) handling
	sendBuffer    []byte // Buffer for building messages across multiple writes
	sendEOM       bool   // True if EOM has been indicated for current message
	receiveBuffer []byte // Buffer for accumulating partial frames
	bytesRead     int    // Bytes consumed from current message during decoding
	totalMsgBytes int    // Total bytes in current message being decoded
	inMessage     bool   // True if currently decoding a multi-frame message
}

// CEDAR protocol constants based on HTCondor's reli_sock.cpp
const (
	// Header sizes from HTCondor reli_sock.cpp
	NormalHeaderSize = 5
	MaxHeaderSize    = NormalHeaderSize // TODO: Add MAC_SIZE when implementing MD

	// Maximum message size from HTCondor (1MB)
	MaxMessageSize = 1024 * 1024

	// Frame size threshold - send frame when message reaches this size
	DefaultFrameThreshold = 4096 // 4KB default threshold

	// End flag values
	EndFlagPartial  = 0 // More frames follow
	EndFlagComplete = 1 // Last frame in message
)

// NewStream creates a new CEDAR stream from a TCP connection
func NewStream(conn net.Conn) *Stream {
	return &Stream{
		conn:       conn,
		reader:     conn,
		writer:     conn,
		sendDigest: sha256.New(),
		recvDigest: sha256.New(),
	}
}

// SendMessage sends a framed message over the stream
// Uses HTCondor CEDAR protocol format:
// [1 byte: end flag] [4 bytes: message length in network order] [message data]
func (s *Stream) SendMessage(data []byte) error {
	return s.sendMessageWithEnd(data, EndFlagComplete) // Complete message in single frame
}

// sendMessageWithEnd sends a message with specified end flag
func (s *Stream) sendMessageWithEnd(data []byte, end byte) error {
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}

	// For encrypted data, we need to calculate the final size first
	messageData := data
	var finalHeader []byte

	if s.gcm != nil {
		// Calculate the size overhead from encryption
		encryptedSize := s.calculateEncryptedSize(len(data))

		// Construct header with encrypted data length
		finalHeader = make([]byte, NormalHeaderSize)
		finalHeader[0] = end // End flag
		binary.BigEndian.PutUint32(finalHeader[1:5], uint32(encryptedSize))

		// Now encrypt with the correct header for AAD
		encryptedData, err := s.encryptDataWithAAD(data, finalHeader)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}
		messageData = encryptedData
	} else {
		// No encryption - construct header with plain data length
		finalHeader = make([]byte, NormalHeaderSize)
		finalHeader[0] = end // End flag
		binary.BigEndian.PutUint32(finalHeader[1:5], uint32(len(data)))
	}

	// Track cleartext data for AAD digest calculation BEFORE sending
	if s.sendDigest != nil && s.finalSendDigest == nil {
		// Track header (always cleartext for digest purposes)
		s.sendDigest.Write(finalHeader)
		// Track original data (cleartext, not encrypted messageData)
		if len(data) > 0 {
			s.sendDigest.Write(data)
		}
	}

	// Send header
	if _, err := s.writer.Write(finalHeader); err != nil {
		return fmt.Errorf("failed to write frame header: %w", err)
	}

	// Send message data (may be encrypted)
	if len(messageData) > 0 {
		if _, err := s.writer.Write(messageData); err != nil {
			return fmt.Errorf("failed to write message data: %w", err)
		}
	}

	return nil
}

// SendPartialMessage sends a message frame (end flag = 0)
func (s *Stream) SendPartialMessage(data []byte) error {
	return s.sendMessageWithEnd(data, EndFlagPartial) // More frames follow
}

// ReceiveFrame receives and deframes a message from the stream
// Uses HTCondor CEDAR protocol format:
// [1 byte: end flag] [4 bytes: message length in network order] [message data]
func (s *Stream) ReceiveFrame() ([]byte, error) {
	// Read HTCondor-style header (5 bytes)
	header := make([]byte, NormalHeaderSize)
	if _, err := io.ReadFull(s.reader, header); err != nil {
		return nil, fmt.Errorf("failed to read frame header: %w", err)
	}

	// Extract end flag and message length
	endFlag := header[0]
	messageLength := binary.BigEndian.Uint32(header[1:5])

	// Validate message size
	if messageLength > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", messageLength, MaxMessageSize)
	}

	// Validate end flag (HTCondor uses values 0-10)
	if endFlag > 10 {
		return nil, fmt.Errorf("invalid end flag: %d", endFlag)
	}

	// Handle zero-length messages
	if messageLength == 0 {
		return []byte{}, nil
	}

	// Read message data
	messageData := make([]byte, messageLength)
	if _, err := io.ReadFull(s.reader, messageData); err != nil {
		return nil, fmt.Errorf("failed to read message data: %w", err)
	}

	// Decrypt data if encryption is enabled using AAD
	var clearData []byte
	if s.gcm != nil {
		decryptedData, err := s.decryptDataWithAAD(messageData, header)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}
		clearData = decryptedData
	} else {
		clearData = messageData
	}

	// Track cleartext data for AAD digest calculation AFTER decryption
	if s.recvDigest != nil && s.finalRecvDigest == nil {
		s.recvDigest.Write(header)
		s.recvDigest.Write(clearData)
	}

	return clearData, nil
}

// ReceiveFrameWithEnd receives a message and returns both data and end flag
func (s *Stream) ReceiveFrameWithEnd() ([]byte, byte, error) {
	// Read HTCondor-style header (5 bytes)
	header := make([]byte, NormalHeaderSize)
	if _, err := io.ReadFull(s.reader, header); err != nil {
		return nil, 0, fmt.Errorf("failed to read frame header: %w", err)
	}

	// Extract end flag and message length
	endFlag := header[0]
	messageLength := binary.BigEndian.Uint32(header[1:5])

	// Validate message size
	if messageLength > MaxMessageSize {
		return nil, 0, fmt.Errorf("message too large: %d bytes (max %d)", messageLength, MaxMessageSize)
	}

	// Validate end flag (HTCondor uses values 0-10)
	if endFlag > 10 {
		return nil, 0, fmt.Errorf("invalid end flag: %d", endFlag)
	}

	// Handle zero-length messages
	if messageLength == 0 {
		// Track header for AAD digest calculation
		if s.recvDigest != nil && s.finalRecvDigest == nil {
			s.recvDigest.Write(header)
		}
		return []byte{}, endFlag, nil
	}

	// Read message data
	messageData := make([]byte, messageLength)
	if _, err := io.ReadFull(s.reader, messageData); err != nil {
		return nil, 0, fmt.Errorf("failed to read message data: %w", err)
	}

	// Decrypt data if encryption is enabled using AAD
	var clearData []byte
	if s.gcm != nil && len(messageData) > 0 {
		decryptedData, err := s.decryptDataWithAAD(messageData, header)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decrypt message: %w", err)
		}
		clearData = decryptedData
	} else {
		clearData = messageData
	}

	// Track cleartext data for AAD digest calculation AFTER decryption
	if s.recvDigest != nil && s.finalRecvDigest == nil {
		s.recvDigest.Write(header)
		s.recvDigest.Write(clearData)
	}

	return clearData, endFlag, nil
}

// IsConnected returns true if the underlying connection is still open
func (s *Stream) IsConnected() bool {
	return s.conn != nil
}

// Close closes the underlying connection
func (s *Stream) Close() error {
	return s.conn.Close()
}

// GetConnection returns the underlying connection for TLS upgrade
func (s *Stream) GetConnection() net.Conn {
	return s.conn
}

// SetConnection replaces the underlying connection (e.g., with TLS connection)
func (s *Stream) SetConnection(conn net.Conn) {
	s.conn = conn
	s.reader = conn
	s.writer = conn
}

// WriteMessage writes data to the message buffer
// Data is accumulated until EndMessage() is called or frame threshold is reached
func (s *Stream) WriteMessage(data []byte) error {
	if s.sendEOM {
		return fmt.Errorf("cannot write to message after EndMessage() has been called")
	}

	// Append to send buffer
	s.sendBuffer = append(s.sendBuffer, data...)

	// If buffer exceeds threshold, send a partial frame
	if len(s.sendBuffer) >= DefaultFrameThreshold {
		return s.flushPartialFrame()
	}

	return nil
}

// StartMessage resets EOM state to allow writing a new message
func (s *Stream) StartMessage() {
	s.sendEOM = false
	s.sendBuffer = nil
}

// EndMessage indicates end of message and sends any remaining buffered data
func (s *Stream) EndMessage() error {
	if s.sendEOM {
		return fmt.Errorf("EndMessage() already called for this message")
	}

	s.sendEOM = true

	// Send remaining buffer as final frame
	err := s.sendMessageWithEnd(s.sendBuffer, EndFlagComplete)
	if err != nil {
		return err
	}

	// Reset buffer but keep sendEOM flag true until next message starts
	s.sendBuffer = nil

	return nil
}

// flushPartialFrame sends a partial frame and clears the buffer
func (s *Stream) flushPartialFrame() error {
	if len(s.sendBuffer) == 0 {
		return nil
	}

	err := s.sendMessageWithEnd(s.sendBuffer, EndFlagPartial)
	if err != nil {
		return err
	}

	// Clear buffer for next chunk
	s.sendBuffer = nil
	return nil
}

// ReadMessageBytes reads up to n bytes from the current message
// Returns error if trying to read more bytes than available in current message
func (s *Stream) ReadMessageBytes(data []byte) (int, error) {
	if !s.inMessage {
		return 0, fmt.Errorf("no message currently being read")
	}

	available := len(s.receiveBuffer) - s.bytesRead
	if available == 0 {
		// Need to read more frames
		err := s.readNextFrame()
		if err != nil {
			return 0, err
		}
		available = len(s.receiveBuffer) - s.bytesRead
	}

	// Read up to requested amount or available amount
	toRead := len(data)
	if toRead > available {
		toRead = available
	}

	copy(data[:toRead], s.receiveBuffer[s.bytesRead:s.bytesRead+toRead])
	s.bytesRead += toRead

	return toRead, nil
}

// EndMessageRead indicates that message reading is complete
// Returns error if not all bytes have been consumed
func (s *Stream) EndMessageRead() error {
	if !s.inMessage {
		return fmt.Errorf("no message currently being read")
	}

	if s.bytesRead < s.totalMsgBytes {
		return fmt.Errorf("message not fully consumed: read %d of %d bytes", s.bytesRead, s.totalMsgBytes)
	}

	// Reset for next message
	s.inMessage = false
	s.receiveBuffer = nil
	s.bytesRead = 0
	s.totalMsgBytes = 0

	return nil
}

// StartMessageRead begins reading a complete message (potentially across multiple frames)
func (s *Stream) StartMessageRead() error {
	if s.inMessage {
		return fmt.Errorf("already reading a message")
	}

	// Read first frame
	err := s.readNextFrame()
	if err != nil {
		return err
	}

	s.inMessage = true
	s.bytesRead = 0
	return nil
}

// readNextFrame reads the next frame and appends to receive buffer
func (s *Stream) readNextFrame() error {
	frameData, endFlag, err := s.ReceiveFrameWithEnd()
	if err != nil {
		return err
	}

	// Append frame data to receive buffer
	s.receiveBuffer = append(s.receiveBuffer, frameData...)
	s.totalMsgBytes = len(s.receiveBuffer)

	// If this is not the final frame, read more frames
	if endFlag == EndFlagPartial {
		return s.readNextFrame() // Recursively read until complete message
	}

	return nil
}

// ReceiveCompleteMessage receives a complete message, reading multiple frames if necessary
// This is the main method for reading complete messages that may span multiple frames
func (s *Stream) ReceiveCompleteMessage() ([]byte, error) {
	var completeMessage []byte

	for {
		frameData, endFlag, err := s.ReceiveFrameWithEnd()
		if err != nil {
			return nil, err
		}

		// Append this frame's data to the complete message
		completeMessage = append(completeMessage, frameData...)

		// Check if message is complete
		if endFlag == EndFlagComplete {
			break // This was the final frame
		} else if endFlag == EndFlagPartial {
			// More frames to come, continue reading
			continue
		} else {
			return nil, fmt.Errorf("unexpected end flag: %d", endFlag)
		}
	}

	return completeMessage, nil
}

// SetSymmetricKey configures AES-GCM encryption with the provided key
func (s *Stream) SetSymmetricKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("AES-256-GCM requires a 32-byte key, got %d bytes", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return fmt.Errorf("failed to create GCM mode: %w", err)
	}

	s.gcm = gcm
	s.encryptKey = make([]byte, len(key))
	copy(s.encryptKey, key)

	// Initialize IV state following HTCondor's approach
	// Generate random base IV for encryption
	if _, err := rand.Read(s.encryptIV[:]); err != nil {
		return fmt.Errorf("failed to generate encryption IV: %w", err)
	}

	// Reset counters
	s.encryptCounter = 0
	s.decryptCounter = 0

	// Finalize AAD digest state for HTCondor compatibility
	// The digests should contain all data sent/received before encryption was enabled
	s.finishedSendAAD = false
	s.finishedRecvAAD = false

	// Finalize the digests if not already done
	if s.finalSendDigest == nil && s.sendDigest != nil {
		s.finalSendDigest = s.sendDigest.Sum(nil)
	}
	if s.finalRecvDigest == nil && s.recvDigest != nil {
		s.finalRecvDigest = s.recvDigest.Sum(nil)
	}

	// Decrypt IV will be initialized from first received message

	s.encrypted = true
	return nil
}

// calculateEncryptedSize returns the size of data after AES-GCM encryption
func (s *Stream) calculateEncryptedSize(plainSize int) int {
	if !s.encrypted || s.gcm == nil {
		return plainSize
	}

	// AES-GCM adds 16 bytes for authentication tag
	result := plainSize + 16

	// First packet also includes 16-byte IV
	if s.encryptCounter == 0 {
		result += 16
	}

	return result
}

// encryptDataWithAAD encrypts data using AES-GCM with HTCondor-compatible AAD
func (s *Stream) encryptDataWithAAD(data []byte, frameHeader []byte) ([]byte, error) {
	if !s.encrypted || s.gcm == nil {
		return data, nil // No encryption
	}

	// Check if we've hit the maximum counter (HTCondor safety check)
	if s.encryptCounter == 0xffffffff {
		return nil, fmt.Errorf("hit maximum number of packets per connection")
	}

	// Determine if we need to send the IV (only on first message)
	sendingIV := (s.encryptCounter == 0)

	// Construct IV following HTCondor's approach:
	// Take base IV, replace first 4 bytes with (base_counter + message_counter)
	var iv [16]byte
	copy(iv[:], s.encryptIV[:])

	// Extract base counter from first 4 bytes of base IV (network byte order)
	baseCounter := binary.BigEndian.Uint32(s.encryptIV[:4])

	// Add message counter to base counter
	finalCounter := baseCounter + s.encryptCounter

	// Put final counter back into first 4 bytes of IV (network byte order)
	binary.BigEndian.PutUint32(iv[:4], finalCounter)

	// Construct AAD according to HTCondor specification
	var aad []byte
	if !s.finishedSendAAD {
		// First frame: AAD = SHA256(sent_data) + SHA256(recv_data) + frame_header
		s.finishedSendAAD = true

		// Finalize digests if not already done
		if s.finalSendDigest == nil {
			s.finalSendDigest = s.sendDigest.Sum(nil)
		}
		if s.finalRecvDigest == nil {
			s.finalRecvDigest = s.recvDigest.Sum(nil)
		}

		// Construct AAD: sent_digest(32) + recv_digest(32) + frame_header(5) = 69 bytes
		aad = make([]byte, 32+32+len(frameHeader))
		copy(aad[0:32], s.finalSendDigest)
		copy(aad[32:64], s.finalRecvDigest)
		copy(aad[64:], frameHeader)
	} else {
		// Subsequent frames: AAD = frame_header only (5 bytes)
		aad = make([]byte, len(frameHeader))
		copy(aad, frameHeader)
	}

	// Encrypt data with the constructed IV and AAD (use full 16 bytes for GCM)
	ciphertext := s.gcm.Seal(nil, iv[:], data, aad)

	// Calculate output size: ciphertext + optional IV
	outputSize := len(ciphertext)
	if sendingIV {
		outputSize += 16 // Add IV size for first packet
	}

	// Build result: [IV (first packet only)] + [encrypted data + auth tag]
	result := make([]byte, outputSize)
	offset := 0

	if sendingIV {
		// Include base IV in first packet (HTCondor sends the base IV)
		copy(result[offset:], s.encryptIV[:])
		offset += 16
	}

	// Add encrypted data + authentication tag
	copy(result[offset:], ciphertext)

	// Increment counter only after successful encryption
	s.encryptCounter++

	return result, nil
}

// decryptDataWithAAD decrypts data using AES-GCM with HTCondor-compatible AAD
func (s *Stream) decryptDataWithAAD(data []byte, frameHeader []byte) ([]byte, error) {
	if !s.encrypted || s.gcm == nil {
		return data, nil // No decryption
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty encrypted data")
	}

	var iv [16]byte
	var encryptedData []byte
	offset := 0

	// Check if IV is included (first packet)
	expectIV := (s.decryptCounter == 0)

	if expectIV {
		if len(data) < 16 {
			return nil, fmt.Errorf("encrypted data too short to contain IV")
		}
		// Extract IV from data
		copy(s.decryptIV[:], data[:16])
		offset = 16
	}

	// Prepare IV for decryption: base IV with counter
	copy(iv[:], s.decryptIV[:])

	// Extract base counter and add message counter
	baseCounter := binary.BigEndian.Uint32(s.decryptIV[:4])
	finalCounter := baseCounter + s.decryptCounter
	binary.BigEndian.PutUint32(iv[:4], finalCounter)

	// Extract encrypted data (remaining bytes after optional IV)
	encryptedData = data[offset:]

	if len(encryptedData) < 16 { // Need at least auth tag
		return nil, fmt.Errorf("encrypted data too short for auth tag")
	}

	// Construct AAD according to HTCondor specification
	var aad []byte
	if !s.finishedRecvAAD {
		// First frame: AAD = SHA256(sent_data) + SHA256(recv_data) + frame_header
		s.finishedRecvAAD = true

		// Finalize digests if not already done
		if s.finalSendDigest == nil {
			s.finalSendDigest = s.sendDigest.Sum(nil)
		}
		if s.finalRecvDigest == nil {
			s.finalRecvDigest = s.recvDigest.Sum(nil)
		}

		// Construct AAD: sent_digest(32) + recv_digest(32) + frame_header(5) = 69 bytes
		// NOTE: Order is different for decryption - recv first, then send
		aad = make([]byte, 32+32+len(frameHeader))
		copy(aad[0:32], s.finalRecvDigest)
		copy(aad[32:64], s.finalSendDigest)
		copy(aad[64:], frameHeader)
	} else {
		// Subsequent frames: AAD = frame_header only (5 bytes)
		aad = make([]byte, len(frameHeader))
		copy(aad, frameHeader)
	}

	// Decrypt data with the constructed IV and AAD (use full 16 bytes for GCM)
	plaintext, err := s.gcm.Open(nil, iv[:], encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}

	// Increment counter only after successful decryption
	s.decryptCounter++

	return plaintext, nil
}

// IsAuthenticated returns true if the stream has completed authentication
func (s *Stream) IsAuthenticated() bool {
	return s.authenticated
}

// IsEncrypted returns true if the stream is using encryption
func (s *Stream) IsEncrypted() bool {
	return s.encrypted
}

// SetAuthenticated sets the authentication status of the stream
func (s *Stream) SetAuthenticated(authenticated bool) {
	s.authenticated = authenticated
}

// SetEncrypted sets the encryption status of the stream
func (s *Stream) SetEncrypted(encrypted bool) {
	s.encrypted = encrypted
}

//
// STREAMINTERFACE IMPLEMENTATION
//

// ReadFrame reads a single frame from the stream and returns the data and EOM flag
func (s *Stream) ReadFrame() ([]byte, bool, error) {
	data, endByte, err := s.ReceiveFrameWithEnd()
	if err != nil {
		return nil, false, err
	}
	// EOM is indicated by endByte != 0 in CEDAR protocol
	isEOM := endByte != 0
	return data, isEOM, nil
}

// WriteFrame writes a single frame to the stream with the EOM flag
func (s *Stream) WriteFrame(data []byte, isEOM bool) error {
	if isEOM {
		return s.SendMessage(data)
	} else {
		return s.SendPartialMessage(data)
	}
}
