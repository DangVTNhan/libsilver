# LibSilver Node.js Bindings - Standalone Post-Quantum Variants

## Overview

The LibSilver Node.js bindings now provide **standalone modules** for each ML-KEM and ML-DSA variant, enabling direct function calls like `MlKem512Crypto.encapsulate()` as requested. This eliminates the need for generic functions with security level parameters.

## 🔄 Migration from Generic API

### Before (Generic API)
```javascript
const { PostQuantumCrypto } = require('libsilver-nodejs');

// Old generic approach
const keypair = PostQuantumCrypto.generateMlKemKeypairWithLevel(512);
const encapsulation = PostQuantumCrypto.mlKemEncapsulate(
  keypair.publicKeyBytes, 
  keypair.level
);
const sharedSecret = PostQuantumCrypto.mlKemDecapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes,
  keypair.level
);
```

### After (Standalone Variants)
```javascript
const { MlKem512Crypto } = require('libsilver-nodejs');

// New standalone approach
const keypair = MlKem512Crypto.generateKeypair();
const encapsulation = MlKem512Crypto.encapsulate(keypair.publicKeyBytes);
const sharedSecret = MlKem512Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

## 🎯 Available Standalone Modules

### ML-KEM (Key Encapsulation Mechanism)

| Variant | Security Level | Module | Key Pair Type | Encapsulation Type |
|---------|---------------|--------|---------------|-------------------|
| ML-KEM-512 | NIST Level 1 | `MlKem512Crypto` | `MlKem512KeyPairJs` | `MlKem512EncapsulationJs` |
| ML-KEM-768 | NIST Level 3 (Recommended) | `MlKem768Crypto` | `MlKem768KeyPairJs` | `MlKem768EncapsulationJs` |
| ML-KEM-1024 | NIST Level 5 | `MlKem1024Crypto` | `MlKem1024KeyPairJs` | `MlKem1024EncapsulationJs` |

### ML-DSA (Digital Signature Algorithm)

| Variant | Security Level | Module | Key Pair Type |
|---------|---------------|--------|---------------|
| ML-DSA-44 | NIST Level 2 | `MlDsa44Crypto` | `MlDsa44KeyPairJs` |
| ML-DSA-65 | NIST Level 3 (Recommended) | `MlDsa65Crypto` | `MlDsa65KeyPairJs` |
| ML-DSA-87 | NIST Level 5 | `MlDsa87Crypto` | `MlDsa87KeyPairJs` |

## 📋 Direct Function Calls

### ML-KEM-512 Example
```javascript
const { MlKem512Crypto } = require('libsilver-nodejs');

// Generate key pair
const keypair = MlKem512Crypto.generateKeypair();

// Encapsulate
const encapsulation = MlKem512Crypto.encapsulate(keypair.publicKeyBytes);

// Decapsulate
const sharedSecret = MlKem512Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

### ML-KEM-768 Example (Recommended)
```javascript
const { MlKem768Crypto } = require('libsilver-nodejs');

const keypair = MlKem768Crypto.generateKeypair();
const encapsulation = MlKem768Crypto.encapsulate(keypair.publicKeyBytes);
const sharedSecret = MlKem768Crypto.decapsulate(
  encapsulation.ciphertext,
  keypair.privateKeyBytes
);
```

### ML-DSA-65 Example (Recommended)
```javascript
const { MlDsa65Crypto } = require('libsilver-nodejs');

// Generate key pair
const keypair = MlDsa65Crypto.generateKeypair();

// Sign
const message = Buffer.from('Hello, post-quantum world!', 'utf8');
const signature = MlDsa65Crypto.sign(message, keypair.privateKeyBytes);

// Verify
const isValid = MlDsa65Crypto.verify(message, signature, keypair.publicKeyBytes);
```

## 📏 Size Constants

Each module provides convenient size constants:

### ML-KEM Size Constants
```javascript
const { MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto } = require('libsilver-nodejs');

// ML-KEM-512
const kem512Sizes = MlKem512Crypto.getSizes();
console.log(kem512Sizes.publicKeySize);    // 800
console.log(kem512Sizes.privateKeySize);   // 1632
console.log(kem512Sizes.ciphertextSize);   // 768
console.log(kem512Sizes.sharedSecretSize); // 32

// ML-KEM-768
const kem768Sizes = MlKem768Crypto.getSizes();
console.log(kem768Sizes.publicKeySize);    // 1184
console.log(kem768Sizes.privateKeySize);   // 2400
console.log(kem768Sizes.ciphertextSize);   // 1088
console.log(kem768Sizes.sharedSecretSize); // 32

// ML-KEM-1024
const kem1024Sizes = MlKem1024Crypto.getSizes();
console.log(kem1024Sizes.publicKeySize);    // 1568
console.log(kem1024Sizes.privateKeySize);   // 3168
console.log(kem1024Sizes.ciphertextSize);   // 1568
console.log(kem1024Sizes.sharedSecretSize); // 32
```

### ML-DSA Size Constants
```javascript
const { MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto } = require('libsilver-nodejs');

// ML-DSA-44
const dsa44Sizes = MlDsa44Crypto.getSizes();
console.log(dsa44Sizes.publicKeySize);     // 1312
console.log(dsa44Sizes.privateKeySize);    // 2560
console.log(dsa44Sizes.maxSignatureSize);  // 2420

// ML-DSA-65
const dsa65Sizes = MlDsa65Crypto.getSizes();
console.log(dsa65Sizes.publicKeySize);     // 1952
console.log(dsa65Sizes.privateKeySize);    // 4032
console.log(dsa65Sizes.maxSignatureSize);  // 3309

// ML-DSA-87
const dsa87Sizes = MlDsa87Crypto.getSizes();
console.log(dsa87Sizes.publicKeySize);     // 2592
console.log(dsa87Sizes.privateKeySize);    // 4896
console.log(dsa87Sizes.maxSignatureSize);  // 4627
```

## 🔧 Practical Usage with Pre-allocated Buffers

```javascript
const { MlKem768Crypto } = require('libsilver-nodejs');

// Pre-allocate buffers using size constants
const sizes = MlKem768Crypto.getSizes();
const publicKeyBuffer = Buffer.alloc(sizes.publicKeySize);
const privateKeyBuffer = Buffer.alloc(sizes.privateKeySize);
const ciphertextBuffer = Buffer.alloc(sizes.ciphertextSize);

// Generate and use
const keypair = MlKem768Crypto.generateKeypair();
keypair.publicKeyBytes.copy(publicKeyBuffer);
keypair.privateKeyBytes.copy(privateKeyBuffer);

const encapsulation = MlKem768Crypto.encapsulate(publicKeyBuffer);
encapsulation.ciphertext.copy(ciphertextBuffer);
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
npm run test:all

# Run only post-quantum tests
npm run test:post-quantum

# Run basic tests
npm run test
```

## 📚 Examples

Run these examples to see the standalone variants in action:

```bash
# Basic standalone variants demo
npm run example:standalone

# Comprehensive post-quantum demo
npm run example:post-quantum

# Basic Node.js example
npm run example
```

## 🚀 Benefits

1. **Direct Function Calls**: Use `MlKem512Crypto.encapsulate()` instead of generic functions
2. **Type Safety**: Each variant has its own types, preventing mix-ups
3. **Size Constants**: Easy buffer pre-allocation and validation
4. **Cleaner API**: No need to pass security levels as parameters
5. **Better Performance**: Optimized for each specific variant
6. **Easier Testing**: Variant-specific test cases

## 📦 Installation

```bash
npm install libsilver-nodejs
```

## 🔗 Import

```javascript
// Import specific variants you need
const { 
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto 
} = require('libsilver-nodejs');

// Or import everything
const LibSilver = require('libsilver-nodejs');
const keypair = LibSilver.MlKem768Crypto.generateKeypair();
```

The refactoring maintains full backward compatibility while providing the new standalone API you requested. Each variant now has its own dedicated module with direct function calls, making the API much cleaner and more intuitive!
