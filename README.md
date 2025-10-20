# PQC-Algo

Post-quantum cryptography library for securing entropy distribution in IoT systems. 

## Overview

This Rust library implements NIST-approved post-quantum cryptographic algorithms for the QEaaS project. It provides Kyber-1024 for key encapsulation, Dilithium-3 for digital signatures, and AES-256-GCM for hybrid encryption. Basically, it makes sure your random numbers stay random even when quantum computers show up to the party.

## Features

- Post-quantum secure key exchange using Kyber-1024
- Post-quantum digital signatures using Dilithium-3
- Hybrid encryption combining PQC with AES-256-GCM
- Complete device authentication flow
- Comprehensive error handling
- Full test coverage

## Installation

Add this to your Cargo.toml:
```toml
[dependencies]
pqc-algo = { git = "https://github.com/Rickygole/PQC-Algo" }
```

## Quick Start

### Generate Device Credentials
```rust
use pqc_algo::*;

let device = DeviceCredentials::generate()?;
```

This generates both Kyber encryption keys and Dilithium signing keys for a device.

### Encrypt Entropy (Server-Side)
```rust
let entropy = b"super_secret_random_data";
let encrypted = encrypt_entropy_for_device(
    entropy,
    &device.kyber_public_key
)?;
```

### Decrypt Entropy (Client-Side)
```rust
let decrypted = decrypt_entropy(
    &encrypted,
    &device.kyber_secret_key
)?;
```

### Device Authentication

Client creates a signed authentication request:
```rust
let auth_request = create_auth_request(
    "device_12345",
    b"random_nonce",
    &device.dilithium_secret_key
)?;
```

Server verifies the signature:
```rust
let is_valid = verify_auth_request(
    &auth_request,
    &device.dilithium_public_key
)?;
```

## Architecture

The library provides a layered architecture. High-level functions handle common use cases like encrypting entropy or authenticating devices. Low-level functions give direct access to Kyber and Dilithium primitives if you need more control. The hybrid encryption uses Kyber KEM to establish shared secrets, then switches to AES-256-GCM for actual data encryption because performance still matters.

## API Reference

### High-Level API

**DeviceCredentials**

Complete key set for a device including both encryption and signing keys.
```rust
pub struct DeviceCredentials {
    pub kyber_public_key: Vec<u8>,
    pub kyber_secret_key: Vec<u8>,
    pub dilithium_public_key: Vec<u8>,
    pub dilithium_secret_key: Vec<u8>,
}
```

**encrypt_entropy_for_device**

Server-side function to encrypt entropy for a specific device using Kyber KEM and AES-256-GCM.
```rust
pub fn encrypt_entropy_for_device(
    entropy: &[u8],
    device_kyber_public_key: &[u8],
) -> Result<EncryptedEntropy>
```

**decrypt_entropy**

Client-side function to decrypt received entropy.
```rust
pub fn decrypt_entropy(
    encrypted: &EncryptedEntropy,
    device_kyber_secret_key: &[u8],
) -> Result<Vec<u8>>
```

**create_auth_request**

Creates a signed authentication request from a device.
```rust
pub fn create_auth_request(
    device_id: &str,
    nonce: &[u8],
    device_dilithium_secret_key: &[u8],
) -> Result<AuthRequest>
```

**verify_auth_request**

Verifies the authenticity of a device authentication request.
```rust
pub fn verify_auth_request(
    request: &AuthRequest,
    device_dilithium_public_key: &[u8],
) -> Result<bool>
```

### Low-Level API

**Kyber KEM Functions**
```rust
pub fn kem::generate_keypair() -> Result<KyberKeyPair>
pub fn kem::encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>
pub fn kem::decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>
```

**Dilithium Signature Functions**
```rust
pub fn sign::generate_keypair() -> Result<DilithiumKeyPair>
pub fn sign::sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>
pub fn sign::verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>
```

## Testing

Run the test suite:
```bash
cargo test
```

The test suite covers:
- Kyber encryption and decryption roundtrip
- Dilithium signature creation and verification
- Detection of tampered signatures
- Complete entropy encryption flow
- Full device authentication flow

## Security Considerations

This library is designed with security best practices in mind:

- Never log or expose secret keys in any form
- Use cryptographically secure random number generators for nonces
- Implement periodic key rotation policies in production systems
- The underlying liboqs library provides constant-time implementations to protect against timing attacks

## Use Cases

This library is designed for the QEaaS project but can be used in any scenario requiring:

- Post-quantum secure communication between IoT devices and servers
- Authenticated delivery of sensitive data to resource-constrained devices
- Hybrid encryption schemes combining PQC with traditional symmetric cryptography
- Future-proof cryptographic implementations resistant to quantum computing attacks

## Dependencies

- oqs - Open Quantum Safe library providing NIST PQC implementations
- aes-gcm - Authenticated encryption with AES-GCM
- rand - Cryptographically secure random number generation
- zeroize - Secure memory handling for cryptographic secrets
- serde - Serialization support for data structures
- thiserror - Ergonomic error handling

## Standards Compliance

This library implements NIST-approved post-quantum cryptographic standards:

- NIST FIPS 203 (ML-KEM, formerly Kyber)
- NIST FIPS 204 (ML-DSA, formerly Dilithium)

## Project Structure
```
pqc-algo/
├── src/
│   ├── lib.rs         # Public API exports
│   ├── error.rs       # Error types
│   ├── kem.rs         # Kyber implementation
│   ├── sign.rs        # Dilithium implementation
│   └── api.rs         # High-level convenience functions
├── Cargo.toml
└── README.md

bye bye hahah
```