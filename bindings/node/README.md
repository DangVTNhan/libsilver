# LibSilver Node.js Bindings

High-performance cryptography library for Node.js, built with Rust and RustCrypto.

## 🚀 Features

- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048+ bit keys)
- **Digital Signatures**: ECDSA P-256, Ed25519
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2, HKDF, PBKDF2
- **Secure Random Generation**: OS-backed cryptographically secure random number generation
- **Memory Safety**: Automatic zeroization of sensitive data
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **TypeScript Support**: Full TypeScript definitions included

## 📦 Installation

```bash
npm install @libsilver/nodejs
```

## 🔧 Quick Start

```javascript
const { SymmetricCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator } = require('@libsilver/nodejs');

// Symmetric encryption
const key = SymmetricCrypto.generateAesKey();
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);

console.log('Decrypted:', decrypted.toString('utf8')); // "Hello, World!"
```

## 📚 API Documentation

### Symmetric Encryption

#### AES-256-GCM
```javascript
const key = SymmetricCrypto.generateAesKey();
const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);
```

#### ChaCha20-Poly1305
```javascript
const key = SymmetricCrypto.generateChacha20Key();
const ciphertext = SymmetricCrypto.encryptChacha20(plaintext, key);
const decrypted = SymmetricCrypto.decryptChacha20(ciphertext, key);
```

### Asymmetric Encryption

#### RSA-OAEP
```javascript
const keypair = AsymmetricCrypto.generateRsaKeypair();
const ciphertext = AsymmetricCrypto.encryptRsa(plaintext, keypair.publicKeyPem);
const decrypted = AsymmetricCrypto.decryptRsa(ciphertext, keypair.privateKeyPem);
```

### Digital Signatures

#### Ed25519
```javascript
const keypair = AsymmetricCrypto.generateEd25519Keypair();
const signature = AsymmetricCrypto.signEd25519(message, keypair.signingKeyBytes);
const isValid = AsymmetricCrypto.verifyEd25519(message, signature, keypair.verifyingKeyBytes);
```

#### ECDSA P-256
```javascript
const keypair = AsymmetricCrypto.generateEcdsaKeypair();
const signature = AsymmetricCrypto.signEcdsa(message, keypair.signingKeyBytes);
const isValid = AsymmetricCrypto.verifyEcdsa(message, signature, keypair.verifyingKeyBytes);
```

### Cryptographic Hashing

```javascript
// SHA-256
const hash = HashFunctions.sha256(data);
const hexHash = HashFunctions.sha256Hex(data);

// BLAKE3
const blake3Hash = HashFunctions.blake3(data);
const customLengthHash = HashFunctions.blake3WithLength(data, 64);

// HMAC
const mac = HashFunctions.hmacSha256(key, message);
const isValid = HashFunctions.verifyHmacSha256(key, message, mac);
```

### Key Derivation Functions

```javascript
// Argon2 (recommended for password hashing)
const salt = RandomGenerator.generateSalt();
const key = KeyDerivation.argon2(password, salt, 32);

// PBKDF2
const pbkdf2Key = KeyDerivation.pbkdf2Sha256(password, salt, 100000, 32);

// HKDF (for key expansion)
const hkdfKey = KeyDerivation.hkdfSha256(inputKey, salt, info, 32);
```

### Secure Random Generation

```javascript
const randomBytes = RandomGenerator.generateBytes(32);
const secureKey = RandomGenerator.generateKey(32);
const nonce = RandomGenerator.generateNonce(12);
const salt = RandomGenerator.generateSalt();
```

## 🛡️ Security Features

- **Memory Safety**: All sensitive data is automatically zeroized when no longer needed
- **Secure Defaults**: Uses secure parameters and algorithms by default
- **Constant-Time Operations**: Leverages RustCrypto's constant-time implementations
- **No Unsafe Code**: Pure safe Rust implementation with secure FFI bindings
- **Audited Dependencies**: Built on well-audited RustCrypto crates

## 🏗️ Building from Source

```bash
# Clone the repository
git clone https://github.com/DangVTNhan/libsilver.git
cd libsilver

# Install dependencies
npm install

# Build the native module
npm run build

# Run tests
npm test

# Run examples
node examples/nodejs-example.js
```

## 🧪 Testing

```bash
npm test
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔗 Related Projects

- [LibSilver Core](https://github.com/DangVTNhan/libsilver) - The main Rust library
- [LibSilver Swift](https://github.com/DangVTNhan/libsilver-swift) - Swift bindings
- [LibSilver Kotlin](https://github.com/DangVTNhan/libsilver-kotlin) - Kotlin/Android bindings
