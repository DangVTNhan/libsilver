# LibSilver Node.js Bindings

High-performance cryptography library for Node.js, built with Rust and featuring post-quantum cryptography.

## 🚀 Features

- **Post-Quantum Cryptography**: ML-KEM (Key Encapsulation) and ML-DSA (Digital Signatures) - NIST standardized algorithms
- **Symmetric Encryption**: AES-256-GCM (AWS-LC-RS), ChaCha20-Poly1305
- **Stream Cipher**: Stateful AES-256-GCM with automatic nonce management for streaming data
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
- **Key Derivation Functions**: Argon2 password hashing
- **Memory Safety**: Automatic zeroization of sensitive data
- **Cross-Platform**: Works on Windows (x64/ARM64), macOS (Intel/ARM64), and Linux (via CI/CD)
- **TypeScript Support**: Full TypeScript definitions included
- **Simple API**: Unified Crypto class with algorithm selection

## 📦 Installation

```bash
yarn add git+ssh://git@gitlab.silvertiger.tech/stealth-vault/stealthvault-libsilver.git#v1.0.2
```

## 🔧 Quick Start

```javascript
const { Crypto, StreamEncryption } = require('stealthvault-libsilver');

// Symmetric encryption with AES-256-GCM (default)
const key = Crypto.generateEncryptionKey();
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = Crypto.encrypt(plaintext, key);
const decrypted = Crypto.decrypt(ciphertext, key);

console.log('Decrypted:', decrypted.toString('utf8')); // "Hello, World!"

// Stream cipher for stateful encryption
const streamKey = StreamEncryption.generateKey();
const cipher = new StreamEncryption(streamKey);
const chunk1 = cipher.encryptChunk(Buffer.from('Chunk 1', 'utf8'));
const chunk2 = cipher.encryptChunk(Buffer.from('Chunk 2', 'utf8'));
console.log('Stream encrypted chunks created!');

// Post-Quantum Key Encapsulation (ML-KEM-1024 default)
const kemKeypair = Crypto.generateEncapsulationKey();
const encapsulation = Crypto.encapsulate(kemKeypair.publicKeyBytes);
const sharedSecret = Crypto.decapsulate(encapsulation.ciphertext, kemKeypair.privateKeyBytes);

console.log('Post-quantum shared secret established!');
```

## 📚 API Documentation

The `Crypto` class provides a unified interface for all cryptographic operations with sensible defaults and algorithm selection.

### Symmetric Encryption

#### AES-256-GCM (Default)

```javascript
const { Crypto } = require('stealthvault-libsilver');

// Generate encryption key
const key = Crypto.generateEncryptionKey(); // defaults to AES-256-GCM
const key2 = Crypto.generateEncryptionKey("aes-256-gcm"); // explicit

// Basic encryption/decryption
const plaintext = Buffer.from('Hello, World!', 'utf8');
const ciphertext = Crypto.encrypt(plaintext, key);
// If you want to log the nonce (the first 12 bytes of the ciphertext)
const nonce = Crypto.getNonceFromCiphertext(ciphertext);
console.log('Nonce:', nonce.toString('hex'));
const decrypted = Crypto.decrypt(ciphertext, key);

// With Additional Authenticated Data (AAD)
const aad = Buffer.from('user_id:12345', 'utf8');
const ciphertextWithAad = Crypto.encrypt(plaintext, key, aad);

// If you want to log the nonce (the first 12 bytes of the ciphertext)
const nonce = Crypto.getNonceFromCiphertext(ciphertextWithAad);
console.log('Nonce:', nonce.toString('hex'));

const decryptedWithAad = Crypto.decrypt(ciphertextWithAad, key, aad);
```

#### ChaCha20-Poly1305

```javascript
// Generate ChaCha20 key
const chachaKey = Crypto.generateEncryptionKey("chacha20-poly1305");

// Encrypt/decrypt with ChaCha20-Poly1305
const ciphertext = Crypto.encrypt(plaintext, chachaKey, null, "chacha20-poly1305");
const decrypted = Crypto.decrypt(ciphertext, chachaKey, null, "chacha20-poly1305");
```

### Stream Cipher (Stateful AES-256-GCM)

The `StreamEncryption` class provides stateful encryption for streaming data with automatic nonce management. This is ideal for encrypting large amounts of data in chunks or for real-time streaming applications.

**Features:**
- **Stateful Design**: Maintains internal state for nonce management
- **Thread-Safe**: Can be used safely across multiple threads
- **AWS-LC-RS Backend**: High-performance implementation
- **Automatic Nonce Management**: Prevents nonce reuse within the same key context
- **Zero-Copy Operations**: Optimized for large data processing

```javascript
const { StreamEncryption } = require('stealthvault-libsilver');

// Generate a key for stream cipher
const key = StreamEncryption.generateKey();

// Create a stream cipher instance
const cipher = new StreamEncryption(key);

// Encrypt data chunks
const chunk1 = Buffer.from('First chunk of data', 'utf8');
const chunk2 = Buffer.from('Second chunk of data', 'utf8');
const chunk3 = Buffer.from('Third chunk of data', 'utf8');

const encrypted1 = cipher.encryptChunk(chunk1);
const encrypted2 = cipher.encryptChunk(chunk2);
const encrypted3 = cipher.encryptChunk(chunk3);

// Decrypt data chunks (order matters for stream ciphers)
const decrypted1 = cipher.decryptChunk(encrypted1);
const decrypted2 = cipher.decryptChunk(encrypted2);
const decrypted3 = cipher.decryptChunk(encrypted3);

console.log('Decrypted chunks:');
console.log(decrypted1.toString('utf8')); // "First chunk of data"
console.log(decrypted2.toString('utf8')); // "Second chunk of data"
console.log(decrypted3.toString('utf8')); // "Third chunk of data"

// Monitor nonce usage
console.log('Nonce counter:', cipher.getNonceCounter()); // 3

// Reset cipher state for new session
cipher.reset();
console.log('Nonce counter after reset:', cipher.getNonceCounter()); // 0
```

**Important Notes:**
- Each `StreamEncryption` instance maintains its own state
- Nonces are automatically incremented for each `encryptChunk()` call
- The same cipher instance should be used for both encryption and decryption
- Consider calling `reset()` when the nonce counter approaches overflow
- Each encrypted chunk includes its own nonce and authentication tag

### Post-Quantum Key Encapsulation (ML-KEM)

ML-KEM provides quantum-resistant key exchange with three security levels:

#### ML-KEM-1024 (NIST Level 5) - Default

```javascript
// Generate key pair (defaults to ML-KEM-1024)
const keypair = Crypto.generateEncapsulationKey();
const keypair2 = Crypto.generateEncapsulationKey("ml-kem-1024"); // explicit

// Encapsulate shared secret
const encapsulation = Crypto.encapsulate(keypair.publicKeyBytes);

// Decapsulate shared secret
const sharedSecret = Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

#### ML-KEM-768 (NIST Level 3) - Recommended for most use cases

```javascript
// Generate ML-KEM-768 key pair
const keypair = Crypto.generateEncapsulationKey("ml-kem-768");

// Encapsulate and decapsulate
const encapsulation = Crypto.encapsulate(keypair.publicKeyBytes, "ml-kem-768");
const sharedSecret = Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes,
  "ml-kem-768"
);
```

#### ML-KEM-512 (NIST Level 1) - For resource-constrained environments

```javascript
// Generate ML-KEM-512 key pair
const keypair = Crypto.generateEncapsulationKey("ml-kem-512");

// Encapsulate and decapsulate
const encapsulation = Crypto.encapsulate(keypair.publicKeyBytes, "ml-kem-512");
const sharedSecret = Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes,
  "ml-kem-512"
);
```

### Post-Quantum Digital Signatures (ML-DSA)

ML-DSA provides quantum-resistant digital signatures with three security levels:

#### ML-DSA-87 (NIST Level 5) - Default

```javascript
// Generate signature key pair (defaults to ML-DSA-87)
const keypair = Crypto.generateSignatureKey();
const keypair2 = Crypto.generateSignatureKey("ml-dsa-87"); // explicit

// Sign message
const message = Buffer.from('Hello, post-quantum world!', 'utf8');
const signature = Crypto.sign(message, keypair.privateKeyBytes);

// Verify signature
const isValid = Crypto.verify(message, signature, keypair.publicKeyBytes);
console.log('Signature valid:', isValid);
```

#### ML-DSA-65 (NIST Level 3) - Recommended for most use cases

```javascript
// Generate ML-DSA-65 key pair
const keypair = Crypto.generateSignatureKey("ml-dsa-65");

// Sign and verify
const signature = Crypto.sign(message, keypair.privateKeyBytes, "ml-dsa-65");
const isValid = Crypto.verify(message, signature, keypair.publicKeyBytes, "ml-dsa-65");
```

#### ML-DSA-44 (NIST Level 2) - For smaller signatures

```javascript
// Generate ML-DSA-44 key pair
const keypair = Crypto.generateSignatureKey("ml-dsa-44");

// Sign and verify
const signature = Crypto.sign(message, keypair.privateKeyBytes, "ml-dsa-44");
const isValid = Crypto.verify(message, signature, keypair.publicKeyBytes, "ml-dsa-44");
```

### Cryptographic Hashing

```javascript
// SHA-256 (default)
const hash = Crypto.hash(data);
const hashHex = Crypto.hashHex(data); // returns hex string

// SHA-512
const sha512Hash = Crypto.hash(data, "sha-512");
const sha512Hex = Crypto.hashHex(data, "sha-512");

// BLAKE3 (hex only)
const blake3Hex = Crypto.hashHex(data, "blake3");

// HMAC
const key = Buffer.from('secret-key', 'utf8');
const message = Buffer.from('message to authenticate', 'utf8');
const mac = Crypto.hmac(key, message); // defaults to SHA-256
const mac512 = Crypto.hmac(key, message, "sha-512");

// Verify HMAC
const isValid = Crypto.verifyHmac(key, message, mac);
const isValid512 = Crypto.verifyHmac(key, message, mac512, "sha-512");
```

### Password Derivation

```javascript
// Argon2 password hashing (recommended for passwords)
const password = Buffer.from('user-password', 'utf8');
const salt = Buffer.from('random-salt-16-bytes'); // 16 bytes minimum
const derivedKey = Crypto.derivePassword(password, salt); // 32 bytes default
const derivedKey64 = Crypto.derivePassword(password, salt, 64); // 64 bytes

// String passwords are automatically converted to UTF-8 buffers
const derivedFromString = Crypto.derivePassword('user-password', salt);
```

### Hybrid Encryption Example

Combine ML-KEM with symmetric encryption for secure communication:

```javascript
const { Crypto } = require('stealthvault-libsilver');

// Alice generates key pair
const aliceKeypair = Crypto.generateEncapsulationKey("ml-kem-768");

// Bob wants to send encrypted message to Alice
const message = Buffer.from('Confidential message', 'utf8');

// Bob encapsulates shared secret using Alice's public key
const encapsulation = Crypto.encapsulate(aliceKeypair.publicKeyBytes, "ml-kem-768");

// Bob encrypts message with shared secret (use first 32 bytes as AES key)
const aesKey = encapsulation.sharedSecret.slice(0, 32);
const encryptedMessage = Crypto.encrypt(message, aesKey);

// Alice decapsulates shared secret
const aliceSharedSecret = Crypto.decapsulate(
  encapsulation.ciphertext,
  aliceKeypair.privateKeyBytes,
  "ml-kem-768"
);

// Alice decrypts message
const aliceAesKey = aliceSharedSecret.slice(0, 32);
const decryptedMessage = Crypto.decrypt(encryptedMessage, aliceAesKey);

console.log('Decrypted:', decryptedMessage.toString('utf8'));
```

### Algorithm Support

#### Supported Algorithms

**Symmetric Encryption:**
- `"aes-256-gcm"` (default) - AES-256-GCM using AWS-LC-RS
- `"chacha20-poly1305"` - ChaCha20-Poly1305

**Post-Quantum Key Encapsulation (ML-KEM):**
- `"ml-kem-512"` - NIST Level 1 (smallest keys, fastest)
- `"ml-kem-768"` - NIST Level 3 (recommended balance)
- `"ml-kem-1024"` - NIST Level 5 (highest security, default)

**Post-Quantum Digital Signatures (ML-DSA):**
- `"ml-dsa-44"` - NIST Level 2 (smallest signatures)
- `"ml-dsa-65"` - NIST Level 3 (recommended balance)
- `"ml-dsa-87"` - NIST Level 5 (highest security, default)

**Cryptographic Hashing:**
- `"sha-256"` (default) - SHA-256
- `"sha-512"` - SHA-512
- `"blake3"` - BLAKE3 (hex output only)

**Password Derivation:**
- `"argon2"` (default) - Argon2id with secure defaults

## 🛡️ Security Features

- **Post-Quantum Security**: NIST-standardized ML-KEM and ML-DSA algorithms protect against quantum computer attacks
- **Memory Safety**: All sensitive data is automatically zeroized when no longer needed
- **Secure Defaults**: Uses secure parameters and algorithms by default (AES-256-GCM, ML-KEM-1024, ML-DSA-87)
- **High Performance**: AWS-LC-RS provides hardware-accelerated AES-GCM with FIPS 140-2 Level 1 validation
- **Constant-Time Operations**: Leverages RustCrypto's constant-time implementations
- **No Unsafe Code**: Pure safe Rust implementation with secure FFI bindings
- **Audited Dependencies**: Built on well-audited RustCrypto crates and NIST reference implementations

## 🏗️ Building from Source

```bash
# Clone the repository
git clone git@gitlab.silvertiger.tech:stealth-vault/stealthvault-libsilver.git
cd stealthvault-libsilver

# Install dependencies
yarn install

# Build the native module
yarn build

# Run tests
yarn test

# Run examples
yarn example                    # Basic cryptography examples
yarn example:post-quantum       # Post-quantum cryptography examples
node examples/aws-lc-aes-example.js  # AWS-LC-RS AES performance demo
```

## 🧪 Testing

```bash
# Run basic tests
yarn test

# Run post-quantum cryptography tests
yarn test:post-quantum

# Run all comprehensive tests
yarn test:all

# Run specific test suites
yarn test:basic          # Basic cryptography tests
yarn test:integration    # Integration tests
yarn test:performance    # Performance benchmarks
yarn test:stream         # Stream cipher tests (both native and wrapper)
yarn test:stream-cipher  # Native stream cipher tests only
yarn test:stream-wrapper # Stream encryption wrapper tests only
```

## 📊 Benchmarking

Run comprehensive performance benchmarks to compare LibSilver with Node.js native crypto:

```bash
# Run comprehensive stream cipher benchmarks
yarn benchmark:stream

# This benchmark includes:
# - Basic LibSilver StreamCipher performance
# - LibSilver vs Node.js crypto comparison
# - Streaming vs chunk-based processing
# - Memory usage analysis
# - Large file processing benchmarks
```

The benchmark generates detailed performance reports and saves results to JSON files for analysis.

## 🖥️ Platform Support

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| macOS | ARM64 (M1/M2) | ✅ | Native compilation |
| macOS | Intel x64 | ✅ | Cross-compilation |
| Windows | x64 | ✅ | Cross-compilation |
| Windows | ARM64 | ✅ | Cross-compilation |
| Linux | x64 | ⚠️ | CI/CD builds |
| Linux | ARM64 | ⚠️ | CI/CD builds |

Pre-built binaries are available for all supported platforms via GitLab package registry.

## � 🔧 Advanced Usage: Native Modules

For advanced users who need direct access to the underlying native implementations, the following modules are also exported:

- **`SymmetricCrypto`** - Direct access to symmetric encryption functions
- **`AwsLcAesCrypto`** - AWS-LC-RS AES-GCM implementation
- **`RustCryptoAesCrypto`** - RustCrypto AES-GCM implementation
- **`AsymmetricCrypto`** - RSA, ECDSA, and Ed25519 operations
- **`HashFunctions`** - SHA-256, SHA-512, BLAKE3, and HMAC functions
- **`KeyDerivation`** - Argon2, PBKDF2, and HKDF functions
- **`RandomGenerator`** - Cryptographically secure random number generation
- **`MlKem512Crypto`**, **`MlKem768Crypto`**, **`MlKem1024Crypto`** - ML-KEM implementations
- **`MlDsa44Crypto`**, **`MlDsa65Crypto`**, **`MlDsa87Crypto`** - ML-DSA implementations

These modules provide the same functionality as the `Crypto` class but with direct access to specific implementations. Refer to the TypeScript definitions for detailed API documentation.

## �📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## 🔗 Related Projects

- [StealthVault LibSilver Core](https://gitlab.silvertiger.tech/stealth-vault/stealthvault-libsilver) - The main Rust library
- [LibSilver Swift](https://github.com/DangVTNhan/libsilver-swift) - Swift bindings
- [LibSilver Kotlin](https://github.com/DangVTNhan/libsilver-kotlin) - Kotlin/Android bindings
