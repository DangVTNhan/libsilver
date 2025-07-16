# LibSilver Kotlin Bindings

Kotlin Multiplatform bindings for the LibSilver cryptography library.

## 🚧 Status

**Coming Soon** - Kotlin bindings are currently in development.

## 🎯 Planned Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048+ bit keys)
- **Digital Signatures**: ECDSA P-256, Ed25519
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2, HKDF, PBKDF2
- **Secure Random Generation**: OS-backed cryptographically secure random number generation
- **Memory Safety**: Automatic zeroization of sensitive data
- **Kotlin Multiplatform**: Support for JVM, Android, iOS, and Native targets
- **Coroutines Support**: Async/await patterns for cryptographic operations

## 📦 Installation (Planned)

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("com.libsilver:libsilver-kotlin:0.1.0")
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'com.libsilver:libsilver-kotlin:0.1.0'
}
```

### Maven

```xml
<dependency>
    <groupId>com.libsilver</groupId>
    <artifactId>libsilver-kotlin</artifactId>
    <version>0.1.0</version>
</dependency>
```

## 🔧 Usage (Planned)

```kotlin
import com.libsilver.*

// Symmetric encryption
val key = SymmetricCrypto.generateAESKey()
val plaintext = "Hello, World!".toByteArray()
val ciphertext = SymmetricCrypto.encryptAES(plaintext, key)
val decrypted = SymmetricCrypto.decryptAES(ciphertext, key)

// Digital signatures
val keypair = AsymmetricCrypto.generateEd25519Keypair()
val message = "Sign this message".toByteArray()
val signature = AsymmetricCrypto.signEd25519(message, keypair.signingKey)
val isValid = AsymmetricCrypto.verifyEd25519(message, signature, keypair.verifyingKey)

// Async operations (with coroutines)
suspend fun encryptAsync() {
    val key = SymmetricCrypto.generateAESKeyAsync()
    val ciphertext = SymmetricCrypto.encryptAESAsync(plaintext, key)
}
```

## 🏗️ Development

This binding will be implemented using:
- Kotlin Multiplatform for cross-platform support
- JNI for Android/JVM integration
- Rust FFI with C-compatible interface
- Kotlin Coroutines for async operations
- Comprehensive unit tests for all platforms

## 🎯 Supported Platforms

- **JVM**: Java 8+ compatible
- **Android**: API level 24+ (Android 7.0+)
- **iOS**: iOS 13+ (via Kotlin/Native)
- **macOS**: macOS 10.15+ (via Kotlin/Native)
- **Linux**: x86_64 (via Kotlin/Native)
- **Windows**: x86_64 (via Kotlin/Native)

## 📄 License

MIT License - see [LICENSE](../../LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔗 Related Projects

- [LibSilver Core](../../) - The main Rust library
- [LibSilver Node.js](../node/) - Node.js bindings
- [LibSilver Swift](../swift/) - Swift bindings
