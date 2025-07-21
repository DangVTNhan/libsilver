# LibSilver Swift Bindings

LibSilver Swift bindings provide a comprehensive cryptography library for iOS, macOS, watchOS, and tvOS applications. Built on top of the high-performance LibSilver Rust library using UniFFI, it offers both classical and post-quantum cryptographic operations with a Swift-native API.

## ✅ Status

**Ready for Use** - Swift bindings are now available with full UniFFI integration!

## 🎯 Planned Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048+ bit keys)
- **Digital Signatures**: ECDSA P-256, Ed25519
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2, HKDF, PBKDF2
- **Secure Random Generation**: OS-backed cryptographically secure random number generation
- **Memory Safety**: Automatic zeroization of sensitive data
- **Swift Package Manager**: Easy integration with SPM
- **iOS/macOS/watchOS/tvOS**: Full Apple platform support

## 📦 Installation (Planned)

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/DangVTNhan/libsilver.git", from: "0.1.0")
]
```

## 🔧 Usage (Planned)

```swift
import LibSilver

// Symmetric encryption
let key = SymmetricCrypto.generateAESKey()
let plaintext = "Hello, World!".data(using: .utf8)!
let ciphertext = try SymmetricCrypto.encryptAES(plaintext, key: key)
let decrypted = try SymmetricCrypto.decryptAES(ciphertext, key: key)

// Digital signatures
let keypair = try AsymmetricCrypto.generateEd25519Keypair()
let message = "Sign this message".data(using: .utf8)!
let signature = try AsymmetricCrypto.signEd25519(message, signingKey: keypair.signingKey)
let isValid = try AsymmetricCrypto.verifyEd25519(message, signature: signature, verifyingKey: keypair.verifyingKey)
```

## 🏗️ Development

This binding will be implemented using:
- Rust FFI with C-compatible interface
- Swift Package Manager for distribution
- Automatic memory management
- Swift-native error handling
- Comprehensive unit tests

## 📄 License

MIT License - see [LICENSE](../../LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔗 Related Projects

- [LibSilver Core](../../) - The main Rust library
- [LibSilver Node.js](../node/) - Node.js bindings
- [LibSilver Kotlin](../kotlin/) - Kotlin/Android bindings
