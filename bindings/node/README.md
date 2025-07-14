# LibSilver Node.js Bindings

High-performance cryptography library for Node.js, built with Rust and RustCrypto.

## 🚀 Features

- **Post-Quantum Cryptography**: ML-KEM (Key Encapsulation) and ML-DSA (Digital Signatures) - NIST standardized algorithms
- **Symmetric Encryption**: AES-256-GCM (RustCrypto + AWS-LC-RS), ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-OAEP (2048+ bit keys)
- **Digital Signatures**: ECDSA P-256, Ed25519, ML-DSA (Post-Quantum)
- **Key Encapsulation**: ML-KEM (Post-Quantum Key Exchange)
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2, HKDF, PBKDF2
- **Secure Random Generation**: OS-backed cryptographically secure random number generation
- **Memory Safety**: Automatic zeroization of sensitive data
- **Cross-Platform**: Works on Windows (x64/ARM64), macOS (Intel/ARM64), and Linux (via CI/CD)
- **TypeScript Support**: Full TypeScript definitions included

## 📦 Installation

```bash
npm install libsilver-nodejs
```

## 🔧 Quick Start

```javascript
const {
  SymmetricCrypto, AwsLcAesCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator,
  MlKem768Crypto, MlDsa65Crypto  // Post-Quantum Cryptography
} = require('libsilver-nodejs');

// Symmetric encryption
const key = SymmetricCrypto.generateAesKey();
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);

console.log('Decrypted:', decrypted.toString('utf8')); // "Hello, World!"

// Post-Quantum Key Encapsulation (ML-KEM-768)
const kemKeypair = MlKem768Crypto.generateKeypair();
const encapsulation = MlKem768Crypto.encapsulate(kemKeypair.publicKeyBytes);
const sharedSecret = MlKem768Crypto.decapsulate(encapsulation.ciphertext, kemKeypair.privateKeyBytes);

console.log('Post-quantum shared secret established!');
```

## 📚 API Documentation

### Post-Quantum Cryptography

LibSilver provides NIST-standardized post-quantum cryptographic algorithms to protect against quantum computer attacks.

#### NIST Security Levels

| Security Level | Classical Security | Quantum Security | Key Sizes | Performance | Recommended Use |
|----------------|-------------------|------------------|-----------|-------------|-----------------|
| **Level 1** | AES-128 | Grover's algorithm | Smallest | Fastest | IoT, embedded systems |
| **Level 3** | AES-192 | Grover's algorithm | Medium | Balanced | **General purpose (recommended)** |
| **Level 5** | AES-256 | Grover's algorithm | Largest | Slowest | High-security applications |

#### ML-KEM (Key Encapsulation Mechanism)

ML-KEM provides quantum-resistant key exchange. Three security levels are available:

##### ML-KEM-512 (NIST Level 1)
```javascript
const { MlKem512Crypto } = require('libsilver-nodejs');

// Generate key pair
const keypair = MlKem512Crypto.generateKeypair();

// Encapsulate shared secret
const encapsulation = MlKem512Crypto.encapsulate(keypair.publicKeyBytes);

// Decapsulate shared secret
const sharedSecret = MlKem512Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);

// Get size constants
const sizes = MlKem512Crypto.getSizes();
console.log('Public key size:', sizes.publicKeySize);
console.log('Private key size:', sizes.privateKeySize);
console.log('Ciphertext size:', sizes.ciphertextSize);
console.log('Shared secret size:', sizes.sharedSecretSize);
```

##### ML-KEM-768 (NIST Level 3) - Recommended
```javascript
const { MlKem768Crypto } = require('libsilver-nodejs');

// Same API as ML-KEM-512, but with higher security level
const keypair = MlKem768Crypto.generateKeypair();
const encapsulation = MlKem768Crypto.encapsulate(keypair.publicKeyBytes);
const sharedSecret = MlKem768Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

##### ML-KEM-1024 (NIST Level 5)
```javascript
const { MlKem1024Crypto } = require('libsilver-nodejs');

// Same API as ML-KEM-512, but with highest security level
const keypair = MlKem1024Crypto.generateKeypair();
const encapsulation = MlKem1024Crypto.encapsulate(keypair.publicKeyBytes);
const sharedSecret = MlKem1024Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

#### ML-DSA (Digital Signature Algorithm)

ML-DSA provides quantum-resistant digital signatures. Three security levels are available:

##### ML-DSA-44 (NIST Level 2)
```javascript
const { MlDsa44Crypto } = require('libsilver-nodejs');

// Generate key pair
const keypair = MlDsa44Crypto.generateKeypair();

// Sign message
const message = Buffer.from('Hello, post-quantum world!', 'utf8');
const signature = MlDsa44Crypto.sign(message, keypair.privateKeyBytes);

// Verify signature
const isValid = MlDsa44Crypto.verify(message, signature, keypair.publicKeyBytes);

// Get size constants
const sizes = MlDsa44Crypto.getSizes();
console.log('Public key size:', sizes.publicKeySize);
console.log('Private key size:', sizes.privateKeySize);
console.log('Max signature size:', sizes.maxSignatureSize);
```

##### ML-DSA-65 (NIST Level 3) - Recommended
```javascript
const { MlDsa65Crypto } = require('libsilver-nodejs');

// Same API as ML-DSA-44, but with higher security level
const keypair = MlDsa65Crypto.generateKeypair();
const signature = MlDsa65Crypto.sign(message, keypair.privateKeyBytes);
const isValid = MlDsa65Crypto.verify(message, signature, keypair.publicKeyBytes);
```

##### ML-DSA-87 (NIST Level 5)
```javascript
const { MlDsa87Crypto } = require('libsilver-nodejs');

// Same API as ML-DSA-44, but with highest security level
const keypair = MlDsa87Crypto.generateKeypair();
const signature = MlDsa87Crypto.sign(message, keypair.privateKeyBytes);
const isValid = MlDsa87Crypto.verify(message, signature, keypair.publicKeyBytes);
```

#### Hybrid Encryption Example

Combine ML-KEM with symmetric encryption for secure communication:

```javascript
const { MlKem768Crypto, SymmetricCrypto } = require('libsilver-nodejs');

// Alice generates key pair
const aliceKeypair = MlKem768Crypto.generateKeypair();

// Bob wants to send encrypted message to Alice
const message = Buffer.from('Confidential message', 'utf8');

// Bob encapsulates shared secret using Alice's public key
const encapsulation = MlKem768Crypto.encapsulate(aliceKeypair.publicKeyBytes);

// Bob encrypts message with shared secret
const encryptedMessage = SymmetricCrypto.encryptAes(message, encapsulation.sharedSecret);

// Alice decapsulates shared secret
const aliceSharedSecret = MlKem768Crypto.decapsulate(
  encapsulation.ciphertext,
  aliceKeypair.privateKeyBytes
);

// Alice decrypts message
const decryptedMessage = SymmetricCrypto.decryptAes(encryptedMessage, aliceSharedSecret);
```

### Symmetric Encryption

#### AES-256-GCM (Default - AWS-LC-RS)
```javascript
const { SymmetricCrypto } = require('libsilver-nodejs');

// Basic encryption/decryption (uses AWS-LC-RS by default)
const key = SymmetricCrypto.generateAesKey();
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);

// With Additional Authenticated Data (AAD)
const aad = Buffer.from('user_id:12345,session:abc123', 'utf8');
const ciphertextWithAad = SymmetricCrypto.encryptAesWithAad(plaintext, key, aad);
const decryptedWithAad = SymmetricCrypto.decryptAesWithAad(ciphertextWithAad, key, aad);

// With fixed nonce (for testing only)
const nonce = Buffer.alloc(12, 0x42);
const deterministicCiphertext = SymmetricCrypto.encryptAesWithNonce(plaintext, key, nonce);
```

**Default Benefits (AWS-LC-RS):**
- 🚀 **5-20x faster** than RustCrypto AES-GCM
- 🔒 **FIPS 140-2 Level 1** validated cryptography
- ⚡ **Hardware acceleration** (AES-NI support)
- 🏷️ **AAD support** for additional authentication

#### AES-256-GCM (AWS-LC-RS Explicit)
```javascript
const { AwsLcAesCrypto } = require('libsilver-nodejs');

// Same as SymmetricCrypto but explicitly using AWS-LC-RS
const key = AwsLcAesCrypto.generateKey();
const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
const decrypted = AwsLcAesCrypto.decrypt(ciphertext, key);
```

#### AES-256-GCM (RustCrypto Alternative)
```javascript
const { RustCryptoAesCrypto } = require('libsilver-nodejs');

// For users who specifically want RustCrypto implementation
const key = RustCryptoAesCrypto.generateKey();
const ciphertext = RustCryptoAesCrypto.encrypt(plaintext, key);
const decrypted = RustCryptoAesCrypto.decrypt(ciphertext, key);

// RustCrypto also supports AAD
const ciphertextWithAad = RustCryptoAesCrypto.encryptWithAad(plaintext, key, aad);
const decryptedWithAad = RustCryptoAesCrypto.decryptWithAad(ciphertextWithAad, key, aad);
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

- **Post-Quantum Security**: NIST-standardized ML-KEM and ML-DSA algorithms protect against quantum computer attacks
- **Memory Safety**: All sensitive data is automatically zeroized when no longer needed
- **Secure Defaults**: Uses secure parameters and algorithms by default
- **Constant-Time Operations**: Leverages RustCrypto's constant-time implementations
- **No Unsafe Code**: Pure safe Rust implementation with secure FFI bindings
- **Audited Dependencies**: Built on well-audited RustCrypto crates and NIST reference implementations

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
npm run example                    # Basic cryptography examples
npm run example:post-quantum       # Post-quantum cryptography examples
node examples/aws-lc-aes-example.js  # AWS-LC-RS AES performance demo
```

## 🧪 Testing

```bash
# Run basic tests
npm test

# Run post-quantum cryptography tests
npm run test:post-quantum

# Run all comprehensive tests
npm run test:all

# Run specific test suites
npm run test:basic          # Basic cryptography tests
npm run test:integration    # Integration tests
npm run test:performance    # Performance benchmarks
```

## 🖥️ Platform Support

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| macOS | ARM64 (M1/M2) | ✅ | Native compilation |
| macOS | Intel x64 | ✅ | Cross-compilation |
| Windows | x64 | ✅ | Cross-compilation |
| Windows | ARM64 | ✅ | Cross-compilation |
| Linux | x64 | ⚠️ | CI/CD builds |
| Linux | ARM64 | ⚠️ | CI/CD builds |

Pre-built binaries are available for all supported platforms via npm.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔗 Related Projects

- [LibSilver Core](https://github.com/DangVTNhan/libsilver) - The main Rust library
- [LibSilver Swift](https://github.com/DangVTNhan/libsilver-swift) - Swift bindings
- [LibSilver Kotlin](https://github.com/DangVTNhan/libsilver-kotlin) - Kotlin/Android bindings
