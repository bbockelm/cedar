# Golang CEDAR Protocol Implementation

This project implements HTCondor's CEDAR binary protocol in Go.

## Project Overview
- **CEDAR Protocol**: Binary protocol implementation for HTCondor communication
- **Stream Management**: Low-level TCP socket message handling with framing
- **Serialization**: Support for C++ type serialization including ClassAds
- **Security**: Authentication and encryption (SSL, SCITOKENS, IDTOKENS)
- **HTCondor Clients**: Tools for HTCondor API interaction (e.g., condor_status equivalent)

## Key Components
- `stream/`: TCP socket stream management and message framing
- `message/`: Message serialization and deserialization 
- `security/`: Authentication and encryption protocols
- `client/`: HTCondor API client implementations
- `protocol/`: Binary protocol documentation and specifications

**External Dependencies:**
- [PelicanPlatform/classad](https://github.com/PelicanPlatform/classad): ClassAd parsing and evaluation

## Development Guidelines
- Follow Go conventions and best practices
- Maintain protocol documentation alongside implementation
- Reference HTCondor C++ implementation in ~/projects/htcondor/src/condor_io/
- Focus on low-level binary protocol accuracy
- Support incremental development from basic streams to full clients

## Reference Implementation
- Stream serialization: ~/projects/htcondor/src/condor_io/stream.cpp
- Socket framing: ~/projects/htcondor/src/condor_io/reli_sock.cpp  
- ClassAd handling: ~/projects/htcondor/src/condor_utils/classad_oldnew.cpp

## Project Status
✅ Project structure created  
✅ Core packages scaffolded  
✅ Go module initialized  
✅ Build tasks configured  
✅ CEDAR protocol framing implemented
✅ Complete type serialization system 
✅ End-of-Message (EOM) handling with multi-frame support
✅ ClassAd binary serialization (HTCondor wire format)
✅ Advanced ClassAd serialization options (private attribute filtering, whitelists, security)
✅ Security handshake protocol (DC_AUTHENTICATE command, method negotiation, ClassAd exchange)
✅ Comprehensive test suite
⏳ Full security implementation (certificate validation, encryption, token handling)