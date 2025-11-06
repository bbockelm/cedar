# HTCondor CEDAR Protocol Specification

This document describes the HTCondor CEDAR binary protocol implementation.

## Overview

CEDAR (ClassAd Evaluation Daemon And Repository) is HTCondor's binary protocol for communication between HTCondor daemons and clients. The protocol operates over TCP sockets and includes:

1. **Message Framing**: Binary framing to delimit messages on the socket
2. **Type Serialization**: Serialization of C++ types to binary format  
3. **ClassAd Serialization**: Special handling for HTCondor's ClassAd data structures
4. **Security**: Authentication and encryption support

## Reference Implementation

The canonical implementation is in HTCondor's C++ codebase:
- Stream serialization: `~/projects/htcondor/src/condor_io/stream.cpp`
- Socket framing: `~/projects/htcondor/src/condor_io/reli_sock.cpp`
- ClassAd handling: `~/projects/htcondor/src/condor_utils/classad_oldnew.cpp`

## Message Structure

### CEDAR Packet Format
Based on HTCondor's reli_sock.cpp implementation:

```
+------------------+------------------+------------------+
| End Flag         | Message Length   | Message Data     |
| (1 byte)         | (4 bytes)        | (variable)       |
|                  | Network Order    |                  |
+------------------+------------------+------------------+
```

### Header Fields
- **End Flag** (1 byte): 
  - `0` = More packets follow (partial message)
  - `1` = Last packet (complete message) 
  - Values 0-10 are valid per HTCondor specification
- **Message Length** (4 bytes): Size of message data in network (big-endian) byte order
- **Message Data** (variable): The actual payload data

### Message Digest Support
When Message Digest (MD) mode is enabled:
- Header size expands to `NORMAL_HEADER_SIZE + MAC_SIZE`
- Additional MAC/checksum bytes follow the length field

### Type Serialization

HTCondor's type serialization system is based on `stream.cpp` and uses a unified encoding/decoding interface. All integer types are serialized as 64-bit values in network (big-endian) byte order.

#### Basic Types

**Integers (All variants encoded as 64-bit)**
- **Format**: 8 bytes, network byte order (big-endian)
- **Types**: `char`, `int`, `int32`, `int64`, `uint32`, `long`, `short`
- **Wire Protocol**: All integer types are converted to `long long` (64-bit) before encoding
- **Example**: `int32(12345)` → `0x00 0x00 0x00 0x00 0x00 0x00 0x30 0x39`

**Floating Point**
- **float**: Converted to double before encoding
- **double**: Uses HTCondor's frexp/ldexp encoding for cross-platform compatibility

**Double Encoding (HTCondor's frexp/ldexp method)**
```
+------------------+------------------+
| Fractional Part  | Exponent Part    |
| (int32)          | (int32)          |
+------------------+------------------+
```
- Fractional part: `frexp(value) * 2147483647` as int32
- Exponent part: `frexp(value)` exponent as int32
- Decoding: `ldexp(frac/2147483647, exp)`
- **Note**: This encoding has precision limitations for very large numbers

**Character**
- **Format**: 1 byte, direct encoding
- **Types**: `char`, `unsigned char`, `byte`

#### Strings

HTCondor uses null-terminated string encoding with optional encryption support:

**Without Encryption (Standard Mode)**
```
+------------------+------------------+
| String Data      | Null Terminator  |
| (UTF-8 bytes)    | (0x00)           |
+------------------+------------------+
```

**With Encryption Mode**
```
+------------------+------------------+------------------+
| Length Prefix    | String Data      | Null Terminator  |
| (int32)          | (UTF-8 bytes)    | (0x00)           |
+------------------+------------------+------------------+
```

**Special String Handling**:
- Empty strings become single null byte `\x00`
- NULL strings (C++ `nullptr`) use special marker `\xFF` 
- Embedded null bytes truncate the string (null-terminated behavior)
- Length includes the null terminator when encryption is enabled

#### Unified Code Interface

HTCondor uses a bidirectional `code()` interface for all types:

```go
// Set stream direction
msg.Encode() // or msg.Decode()

// Use unified code methods
var value int32
msg.CodeInt32(&value)  // Encodes or decodes based on direction

var str string  
msg.CodeString(&str)   // Encodes or decodes based on direction
```

This allows the same code to work for both serialization and deserialization by changing the stream direction.

#### Binary Compatibility

Our implementation maintains exact binary compatibility with HTCondor:
- Network byte order for all multi-byte integers
- HTCondor's frexp/ldexp double encoding
- Null-terminated string format
- 64-bit integer wire protocol
- FracConst = 2147483647 for double precision

#### ClassAds
ClassAds use a custom binary format defined in `classad_oldnew.cpp` (not yet implemented).

## Security Methods

### SSL
Uses standard TLS encryption with X.509 certificates.

### SCITOKENS  
Uses JWT tokens for authentication (SciTokens specification).

### IDTOKENS
Uses HTCondor's internal identity token format.

## Implementation Status

### Core Protocol
- [x] HTCondor-compatible packet framing (end flag + network-order length + data)
- [x] Support for complete and partial messages
- [x] Proper header validation and size limits (1MB max)
- [ ] Message Digest/MAC support

### Type Serialization
- [x] Complete HTCondor-compatible type serialization system
- [x] All integer types (char, int, int32, int64, uint32, etc.) as 64-bit network byte order
- [x] HTCondor's frexp/ldexp double encoding for cross-platform compatibility  
- [x] Float support (converted to double)
- [x] String serialization with null termination and encryption support
- [x] Unified `code()` interface for bidirectional encoding/decoding
- [x] Binary compatibility with HTCondor stream.cpp
- [x] Comprehensive test suite with round-trip validation

### Advanced Features  
- [ ] ClassAd binary format serialization
- [ ] SSL authentication and encryption
- [ ] SCITOKENS support
- [ ] IDTOKENS support
- [ ] Complete HTCondor client implementations (condor_status, etc.)

## Protocol Evolution

This specification will be updated as the implementation progresses to document the exact binary format discovered through reverse engineering the HTCondor C++ implementation.