# PQC-Algo: Post-Quantum Cryptography for Entropy-as-a-Service

A Rust implementation of post-quantum cryptographic algorithms for securing entropy distribution to IoT devices using quantum-resistant encryption.

## 🔐 Overview

This library provides the cryptographic foundation for a Quantum Random Number Generator (QRNG) entropy-as-a-service system. It implements post-quantum cryptography (PQC) algorithms to ensure that entropy distribution remains secure even against future quantum computer attacks.

## 🚀 Features

- **Kyber1024 KEM**: NIST-standardized Key Encapsulation Mechanism for post-quantum encryption
- **liboqs Integration**: Built on the industry-standard Open Quantum Safe library
- **IoT-Ready**: Designed for secure entropy distribution to resource-constrained devices
- **Future-Proof**: Quantum-resistant cryptography that remains secure against quantum attacks

## 📋 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   IoT Devices   │───▶│  QRNG Server     │───▶│  PQC-Algo       │
│   (Clients)     │    │  (Entropy        │    │  (This Library) │
│                 │    │   Provider)      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
        ▼                        ▼                        ▼
  Request Entropy    ──▶   Generate Random   ──▶    Encrypt with
  with PQC Auth             Numbers from            Kyber1024 KEM
                           Hardware QRNG
```

## 🛠 Installation

### Prerequisites

- Rust 1.70+ 
- OpenSSL development libraries

#### macOS (using Homebrew)
```bash
brew install openssl
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
export OPENSSL_LIB_DIR=$(brew --prefix openssl)/lib
export OPENSSL_INCLUDE_DIR=$(brew --prefix openssl)/include
```

#### Ubuntu/Debian
```bash
sudo apt-get install libssl-dev pkg-config
```

### Build
```bash
git clone https://github.com/Rickygole/PQC-Algo.git
cd PQC-Algo
cargo build --release
```

## 📖 Usage

### Basic KEM Operations

```rust
use pqc_algo::kem::{generate_keypair, encapsulate, decapsulate};

// Generate quantum-resistant key pair
let keypair = generate_keypair().unwrap();

// Encrypt data using post-quantum cryptography
let (ciphertext, shared_secret) = encapsulate(&keypair.public_key).unwrap();

// Decrypt data (secure against quantum attacks)
let decrypted_secret = decapsulate(&keypair.secret_key, &ciphertext).unwrap();

assert_eq!(shared_secret, decrypted_secret);
```

### Error Handling

```rust
use pqc_algo::error::{PqcError, Result};

match generate_keypair() {
    Ok(keypair) => println!("Keys generated successfully"),
    Err(PqcError::KeyGeneration(msg)) => eprintln!("Key generation failed: {}", msg),
    Err(e) => eprintln!("Other error: {:?}", e),
}
```

## 🧪 Testing

Run the test suite:
```bash
cargo test
```

Run tests with output:
```bash
cargo test -- --nocapture
```

## 📁 Project Structure

```
src/
├── lib.rs          # Library entry point and module exports
├── kem.rs          # Kyber KEM implementation (Key Encapsulation)
├── sign.rs         # Digital signatures (Dilithium - Future)
└── error.rs        # Custom error types and handling

Cargo.toml          # Dependencies and project configuration
```

## 🔬 Algorithms

### Currently Implemented

- **Kyber1024**: NIST-standardized KEM for post-quantum key exchange
  - Key Size: 1568 bytes (public), 3168 bytes (secret)  
  - Security Level: NIST Level 5 (equivalent to AES-256)
  - Quantum Safe: Yes ✅

### Planned

- **Dilithium**: Digital signatures for device authentication
- **Additional KEMs**: Support for other NIST-approved algorithms

## 🌐 Use Cases

### Entropy-as-a-Service
- **QRNG Server**: Distributes hardware-generated entropy to IoT devices
- **Secure Transmission**: Uses Kyber1024 to encrypt entropy data
- **Device Authentication**: Future Dilithium integration for device verification

### IoT Security
- **Edge Devices**: Secure random number generation for constrained devices
- **Sensor Networks**: Quantum-safe key distribution
- **Critical Infrastructure**: Future-proof cryptographic protection

## 🔧 Dependencies

- **oqs**: Rust bindings for liboqs (Open Quantum Safe)
- **liboqs**: Industry-standard post-quantum cryptography library
- **Standard Rust libraries**: For error handling and memory management

## 🚧 Roadmap

- [ ] **Dilithium Signatures**: Complete authentication system
- [ ] **REST API**: HTTP interface for entropy requests  
- [ ] **Performance Optimization**: Benchmark and optimize for IoT constraints
- [ ] **Multiple Algorithm Support**: Additional NIST-approved PQC algorithms
- [ ] **Client Libraries**: SDKs for various IoT platforms

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

This implementation uses NIST-approved post-quantum cryptographic algorithms. However:

- **Review Required**: This is experimental code - conduct security audits before production use
- **Key Management**: Implement proper key storage and rotation in production
- **Side-Channel Protection**: Consider additional protections for embedded deployments

## 📞 Contact

- **Author**: Ricky Gole
- **Project**: [PQC-Algo](https://github.com/Rickygole/PQC-Algo)
- **Purpose**: Academic/Research implementation of PQC for entropy services

---

*Built with 🦀 Rust for quantum-safe IoT security*