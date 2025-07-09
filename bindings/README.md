# LibSilver Platform Bindings

This directory contains platform-specific bindings for the LibSilver cryptography library.

## 📁 Directory Structure

```
bindings/
├── node/              # Node.js/JavaScript bindings ✅
├── swift/             # Swift/iOS/macOS bindings (coming soon)
└── kotlin/            # Kotlin/Android/JVM bindings (coming soon)
```

## 🚀 Available Bindings

### ✅ Node.js Bindings (`node/`)

**Status**: Ready for use

High-performance Node.js bindings built with NAPI-RS, providing native cryptographic operations for JavaScript/TypeScript applications.

**Features**:
- Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Asymmetric encryption (RSA-OAEP)
- Digital signatures (Ed25519, ECDSA P-256)
- Cryptographic hashing (SHA-256, SHA-512, BLAKE3, HMAC)
- Key derivation functions (Argon2, PBKDF2, HKDF)
- Secure random generation
- TypeScript definitions included
- Cross-platform support (Windows, macOS, Linux)

**Quick Start**:
```bash
cd node/
npm install
npm run build
npm test
```

**Installation**:
```bash
npm install @libsilver/nodejs
```

**Usage**:
```javascript
const { SymmetricCrypto, HashFunctions } = require('@libsilver/nodejs');

// Generate key and encrypt data
const key = SymmetricCrypto.generateAesKey();
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);

// Hash data
const hash = HashFunctions.sha256(Buffer.from('data to hash'));
```

### 🚧 Swift Bindings (`swift/`)

**Status**: Coming Soon

Native Swift bindings for iOS, macOS, watchOS, and tvOS applications.

**Planned Features**:
- Swift Package Manager integration
- iOS 13+ and macOS 10.15+ support
- Swift-native error handling
- Automatic memory management
- Comprehensive unit tests

**Planned Usage**:
```swift
import LibSilver

let key = try SymmetricCrypto.generateAESKey()
let plaintext = "Hello, World!".data(using: .utf8)!
let ciphertext = try SymmetricCrypto.encryptAES(plaintext, key: key)
```

### 🚧 Kotlin Bindings (`kotlin/`)

**Status**: Coming Soon

Kotlin Multiplatform bindings for Android, JVM, and native applications.

**Planned Features**:
- Kotlin Multiplatform support
- Android API 24+ support
- JVM 8+ compatibility
- Coroutines support for async operations
- Gradle/Maven integration

**Planned Usage**:
```kotlin
import com.libsilver.*

val key = SymmetricCrypto.generateAESKey()
val plaintext = "Hello, World!".toByteArray()
val ciphertext = SymmetricCrypto.encryptAES(plaintext, key)
```

## 🏗️ Development

### Building All Bindings

```bash
# Node.js
cd node/ && npm run build

# Swift (when available)
cd swift/ && swift build

# Kotlin (when available)
cd kotlin/ && ./gradlew build
```

### Testing

```bash
# Node.js
cd node/ && npm test

# Swift (when available)
cd swift/ && swift test

# Kotlin (when available)
cd kotlin/ && ./gradlew test
```

## 🔗 Integration Examples

### Electron App (Node.js)
```javascript
const { SymmetricCrypto } = require('@libsilver/nodejs');

// Encrypt user data before storing
const userData = JSON.stringify({ username: 'alice', preferences: {...} });
const key = SymmetricCrypto.generateAesKey();
const encrypted = SymmetricCrypto.encryptAes(Buffer.from(userData), key);
```

### iOS App (Swift - Coming Soon)
```swift
import LibSilver

// Secure password storage
let password = "user_password".data(using: .utf8)!
let salt = try RandomGenerator.generateSalt()
let derivedKey = try KeyDerivation.argon2(password: password, salt: salt, length: 32)
```

### Android App (Kotlin - Coming Soon)
```kotlin
import com.libsilver.*

// Secure API communication
val message = "API request data".toByteArray()
val keypair = AsymmetricCrypto.generateEd25519Keypair()
val signature = AsymmetricCrypto.signEd25519(message, keypair.signingKey)
```

## 📄 License

MIT License - see [LICENSE](../LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔒 Security

All bindings maintain the same security guarantees as the core Rust library:
- Memory safety with automatic zeroization
- Constant-time operations where applicable
- Secure defaults and well-audited dependencies
- No unsafe code in the binding layers
