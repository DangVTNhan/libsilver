# LibSilver - Cross-Platform Cryptography Library

[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

LibSilver is a comprehensive, cross-platform cryptography library built with RustCrypto that provides secure cryptographic primitives for multiple platforms including Node.js, Swift (iOS/macOS), and Kotlin/Java (Android/JVM).

## 🚀 Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048+ bit keys)
- **Digital Signatures**: ECDSA P-256, Ed25519
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2, HKDF, PBKDF2
- **Secure Random Generation**: OS-backed cryptographically secure random number generation
- **Memory Safety**: Automatic zeroization of sensitive data using the `zeroize` crate
- **Cross-Platform**: Designed for FFI bindings to Node.js, Swift, and Kotlin/Java

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libsilver = "0.1.0"
```

## 🔧 Quick Start

```rust
use libsilver::prelude::*;

fn main() -> Result<(), CryptoError> {
    // Symmetric encryption
    let key = AesGcm::generate_key()?;
    let plaintext = b"Hello, World!";
    let ciphertext = AesGcm::encrypt(plaintext, &key)?;
    let decrypted = AesGcm::decrypt(&ciphertext, &key)?;
    assert_eq!(plaintext, &decrypted[..]);

    // Digital signatures
    let keypair = Ed25519Crypto::generate_keypair()?;
    let message = b"Sign this message";
    let signature = Ed25519Crypto::sign(message, keypair.signing_key())?;
    let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key())?;
    assert!(is_valid);

    // Hashing
    let data = b"Hash this data";
    let hash = Sha256Hash::hash(data)?;
    let hex_hash = Sha256Hash::hash_hex(data)?;

    Ok(())
}
```

## 📚 API Documentation

### Symmetric Encryption

#### AES-256-GCM
```rust
use libsilver::prelude::*;

let key = AesGcm::generate_key()?;
let plaintext = b"Secret message";
let ciphertext = AesGcm::encrypt(plaintext, &key)?;
let decrypted = AesGcm::decrypt(&ciphertext, &key)?;
```

#### ChaCha20-Poly1305
```rust
use libsilver::prelude::*;

let key = ChaCha20Poly1305Cipher::generate_key()?;
let ciphertext = ChaCha20Poly1305Cipher::encrypt(plaintext, &key)?;
let decrypted = ChaCha20Poly1305Cipher::decrypt(&ciphertext, &key)?;
```

### Asymmetric Encryption

#### RSA-OAEP
```rust
use libsilver::prelude::*;

let keypair = RsaCrypto::generate_keypair()?; // 2048-bit by default
let ciphertext = RsaCrypto::encrypt(plaintext, keypair.public_key())?;
let decrypted = RsaCrypto::decrypt(&ciphertext, keypair.private_key())?;
```

### Digital Signatures

#### Ed25519
```rust
use libsilver::prelude::*;

let keypair = Ed25519Crypto::generate_keypair()?;
let signature = Ed25519Crypto::sign(message, keypair.signing_key())?;
let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key())?;
```

#### ECDSA P-256
```rust
use libsilver::prelude::*;

let keypair = EcdsaCrypto::generate_keypair()?;
let signature = EcdsaCrypto::sign(message, keypair.signing_key())?;
let is_valid = EcdsaCrypto::verify(message, &signature, keypair.verifying_key())?;
```

### Cryptographic Hashing

```rust
use libsilver::prelude::*;

// SHA-256
let hash = Sha256Hash::hash(data)?;
let hex_hash = Sha256Hash::hash_hex(data)?;

// BLAKE3
let hash = Blake3Hash::hash(data)?;
let custom_length_hash = Blake3Hash::hash_with_length(data, 64)?;

// HMAC
let mac = Hmac::sha256(key, message)?;
let is_valid = Hmac::verify_sha256(key, message, &mac)?;
```

### Key Derivation Functions

```rust
use libsilver::prelude::*;

// Argon2 (recommended for password hashing)
let salt = SecureRandom::generate_salt()?;
let key = Argon2Kdf::derive_key(password, &salt, 32)?;

// PBKDF2
let key = Pbkdf2Kdf::derive_sha256(password, &salt, 100_000, 32)?;

// HKDF (for key expansion)
let key = HkdfKdf::derive_sha256(input_key, Some(&salt), info, 32)?;
```

### Secure Random Generation

```rust
use libsilver::prelude::*;

let random_bytes = SecureRandom::generate_bytes(32)?;
let secure_key = SecureRandom::generate_key(32)?; // Auto-zeroizing
let nonce = SecureRandom::generate_nonce(12)?;
let salt = SecureRandom::generate_salt()?;
```

## 🛡️ Security Features

- **Memory Safety**: All sensitive data is automatically zeroized when dropped
- **Secure Defaults**: Uses secure parameters and algorithms by default
- **Constant-Time Operations**: Leverages RustCrypto's constant-time implementations
- **No Unsafe Code**: Pure safe Rust implementation
- **Audited Dependencies**: Built on well-audited RustCrypto crates

## 📁 Project Structure

```
libsilver/
├── src/                    # Core Rust library
│   ├── core/              # Core cryptographic implementations
│   ├── ffi/               # FFI layer for C compatibility
│   └── bindings/          # Language-specific bindings (Rust side)
├── bindings/              # Platform-specific bindings
│   ├── node/             # Node.js/JavaScript bindings ✅
│   ├── swift/            # Swift/iOS/macOS bindings (coming soon)
│   └── kotlin/           # Kotlin/Android/JVM bindings (coming soon)
└── docs/                 # Documentation
```

## 🔗 Cross-Platform Support

LibSilver provides native bindings for multiple platforms:

- **Node.js**: ✅ Ready - Via NAPI-RS bindings in `bindings/node/`
- **Swift/iOS/macOS**: 🚧 Coming Soon - Via FFI bindings in `bindings/swift/`
- **Kotlin/Android/JVM**: 🚧 Coming Soon - Via FFI + JNI bindings in `bindings/kotlin/`

### Getting Started with Bindings

#### Node.js
```bash
cd bindings/node
npm install
npm run build
npm test
```

#### Swift (Coming Soon)
```bash
cd bindings/swift
swift build
```

#### Kotlin (Coming Soon)
```bash
cd bindings/kotlin
./gradlew build
```

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Run the example:

```bash
cargo run --example basic_usage
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🔒 Security

If you discover a security vulnerability, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

## 📖 Documentation

For detailed API documentation, run:

```bash
cargo doc --open
```
