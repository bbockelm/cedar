# golang-cedar

A Go implementation of HTCondor's CEDAR binary protocol.

## Overview

This library provides a low-level interface for creating and receiving messages using HTCondor's CEDAR protocol over TCP sockets. CEDAR (ClassAd Evaluation Daemon And Repository) is the binary protocol used for communication between HTCondor daemons and clients.

## Features

- **Stream Management**: Low-level TCP socket handling with message framing
- **Message Serialization**: Binary serialization of C++ types compatible with HTCondor  
- **ClassAd Support**: Serialization/deserialization of HTCondor ClassAd structures
- **Security**: Authentication and encryption (SSL, SCITOKENS, IDTOKENS)
- **HTCondor Clients**: High-level clients for HTCondor API operations

## Project Structure

```
├── commands/        # HTCondor command constants and utilities
├── stream/          # TCP socket stream management and message framing
├── message/         # Message serialization and deserialization
├── security/        # Authentication and encryption protocols
├── client/          # HTCondor API client implementations
├── protocol/        # Binary protocol documentation
└── main.go          # Example usage
```

## Key Components
- `commands/`: HTCondor command constants and utilities
- `stream/`: TCP socket stream management and message framing
- `message/`: Message serialization and deserialization 
- `security/`: Authentication and encryption protocols
- `client/`: HTCondor API client implementations
- `protocol/`: Binary protocol documentation and specifications

**External Dependencies:**
- [PelicanPlatform/classad](https://github.com/PelicanPlatform/classad): ClassAd parsing and evaluation

## Development Roadmap

### Phase 1: Core Protocol ✅ COMPLETED
- [x] HTCondor-compatible CEDAR packet framing
- [x] Message encoding/decoding with proper header format  
- [x] Support for complete and partial messages
- [x] Validation and size limits matching HTCondor
- [x] End-of-Message (EOM) handling with multi-frame support
- [x] Complete type serialization/deserialization system
- [x] HTCondor's frexp/ldexp double encoding
- [x] ClassAd binary serialization (HTCondor wire format)
- [x] Advanced ClassAd serialization options (private attribute filtering, whitelists, etc.)

### Phase 2: Security ✅ COMPLETED
- [x] Security handshake protocol (DC_AUTHENTICATE)
- [x] Authentication method negotiation (SSL, TOKEN, FS, etc.)
- [x] Encryption method negotiation (AES, BLOWFISH, 3DES)
- [x] Security policy negotiation (REQUIRED/OPTIONAL/NEVER)
- [x] ECDH key exchange support
- [x] HTCondor-compatible ClassAd security exchange
- [x] AES-256-GCM encryption with HTCondor-compatible AAD mechanism
- [x] HKDF key derivation from ECDH shared secrets
- [x] Complete authenticated encryption implementation
- [ ] SSL certificate validation
- [ ] Token validation and generation

### Phase 2.5: Command System ✅ COMPLETED
- [x] HTCondor command constant enumeration (condor_commands.h)
- [x] Command metadata and categorization system
- [x] Session command specification in security handshake
- [x] Type-safe command handling utilities
- [x] Integration with authentication protocol

### Phase 3: Clients
- [ ] Collector query client (condor_status equivalent)
- [ ] Additional HTCondor API clients

## Usage

### ClassAd Serialization

```go
package main

import (
    "fmt"
    "github.com/PelicanPlatform/classad/classad"
    "github.com/bbockelm/golang-cedar/message"
)

func main() {
    // Create a ClassAd
    ad := classad.New()
    ad.Set("Arch", "x86_64")
    ad.Set("Memory", 8192)
    ad.Set("MyType", "Machine")
    ad.Set("Capability", "0xdeadbeef")  // Private attribute
    
    // Basic serialization
    msg := message.NewMessage()
    if err := msg.PutClassAd(ad); err != nil {
        panic(err)
    }
    
    // Advanced serialization with options
    config := &message.PutClassAdConfig{
        Options:     message.NoPrivate | message.ServerTime,
        PeerVersion: "8.9.6",  // HTCondor version compatibility
    }
    msg2 := message.NewMessage()
    if err := msg2.PutClassAdWithOptions(ad, config); err != nil {
        panic(err)
    }
    
    // Private attributes are excluded from msg2
    fmt.Printf("Basic: %d bytes, NoPrivate: %d bytes\n", len(msg.Bytes()), len(msg2.Bytes()))
}
```

### Private Attribute Handling

```go
// Check if an attribute is considered private
isPrivate := message.ClassAdAttributeIsPrivateAny("Capability", "8.9.6")
fmt.Printf("'Capability' is private: %v\n", isPrivate)  // true

// Whitelist filtering
config := &message.PutClassAdConfig{
    Options:      message.NoExpandWhitelist,
    AttributeWhiteList: []string{"Arch", "Memory"},  // Only these attributes
}
```

### Security Handshake

```go
package main

import (
    "log"
    "net"
    "github.com/bbockelm/golang-cedar/security"
    "github.com/bbockelm/golang-cedar/stream"
)

func main() {
    // Establish TCP connection
    conn, err := net.Dial("tcp", "condor.example.com:9618")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    // Create stream and configure security
    s := stream.NewStream(conn)
    config := &security.SecurityConfig{
        AuthMethods:   []security.AuthMethod{security.AuthToken, security.AuthSSL},
        CryptoMethods: []security.CryptoMethod{security.CryptoAES},
        Authentication: security.SecurityRequired,
        Encryption:    security.SecurityRequired,
        TrustDomain:   "htcondor.example.com",
        ECDHPublicKey: "base64-encoded-public-key",
    }
    
    // Perform security handshake
    auth := security.NewAuthenticator(config, s)
    negotiation, err := auth.ClientHandshake()
    if err != nil {
        log.Fatal(err)
    }
    
    if negotiation.Enact {
        log.Printf("Secure session established using %s auth and %s encryption",
            negotiation.NegotiatedAuth, negotiation.NegotiatedCrypto)
    }
}
```

### Stream Operations with EOM
```
```

### Stream Operations with EOM

```go
// Create a stream from TCP connection
stream := stream.NewStream(conn)

// Send multi-part message with EOM
stream.StartMessage()
stream.WriteMessage([]byte("Part 1: "))
stream.WriteMessage([]byte("Part 2"))
stream.EndMessage() // Automatically sends with complete flag

// Receive complete message
received, err := stream.ReceiveCompleteMessage()
if err != nil {
    log.Fatal(err)
}
```

## Reference Implementation

This implementation is based on HTCondor's C++ codebase:
- Stream serialization: `~/projects/htcondor/src/condor_io/stream.cpp`
- Socket framing: `~/projects/htcondor/src/condor_io/reli_sock.cpp`
- ClassAd handling: `~/projects/htcondor/src/condor_utils/classad_oldnew.cpp`

## Getting Started

```bash
# Clone the repository
git clone https://github.com/bbockelm/golang-cedar
cd golang-cedar

# Install dependencies
go mod tidy

# Run the example (currently shows basic structure)
go run main.go
```

## Documentation

See [protocol/CEDAR_PROTOCOL.md](protocol/CEDAR_PROTOCOL.md) for detailed protocol specification.

## License

This project is licensed under the Apache License 2.0.