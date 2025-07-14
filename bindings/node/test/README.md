# LibSilver Node.js Test Suite

This directory contains a comprehensive test suite for the LibSilver Node.js bindings, covering classical cryptography, post-quantum cryptography, integration scenarios, and performance benchmarks.

## Test Files Overview

### 1. `test.js` - Basic and Advanced Functionality Tests
- **Basic Tests**: Core functionality for all cryptographic primitives
- **Advanced Tests**: Edge cases, different data sizes, key uniqueness
- **Post-Quantum Tests**: All ML-KEM and ML-DSA variants
- **Coverage**: 
  - Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
  - Asymmetric cryptography (RSA, Ed25519, ECDSA)
  - Hash functions (SHA-256, SHA-512, BLAKE3, HMAC)
  - Key derivation (Argon2, PBKDF2, HKDF)
  - Random generation
  - ML-KEM-512/768/1024 (key encapsulation)
  - ML-DSA-44/65/87 (digital signatures)

### 2. `post-quantum-test.js` - Dedicated Post-Quantum Tests
- **ML-KEM Tests**: All three security levels (512, 768, 1024)
- **ML-DSA Tests**: All three security levels (44, 65, 87)
- **Size Validation**: Verifies key, ciphertext, and signature sizes
- **Correctness Tests**: Encapsulation/decapsulation, signing/verification
- **Constants Verification**: Validates size constants match actual sizes

### 3. `integration-test.js` - Real-World Integration Scenarios
- **Secure Messaging System**: ML-KEM + ML-DSA + AES encryption
- **Hybrid Cryptography**: Classical + post-quantum algorithms
- **Secure File Storage**: Password-based encryption with integrity protection
- **Blockchain-like Chain**: Integrity chain with digital signatures
- **Multi-layer Security**: Combining multiple cryptographic primitives

### 4. `performance-test.js` - Performance Benchmarks
- **Symmetric Crypto Benchmarks**: Throughput testing for different data sizes
- **Hash Function Benchmarks**: Performance comparison of hash algorithms
- **Post-Quantum Benchmarks**: Key generation, encapsulation, signing performance
- **Key Derivation Benchmarks**: Argon2, PBKDF2, HKDF performance
- **Memory Usage Analysis**: Memory consumption testing

### 5. `run-all-tests.js` - Comprehensive Test Runner
- **Unified Test Execution**: Runs all test suites with proper reporting
- **Selective Testing**: Run specific test categories
- **Performance Reporting**: Execution time and success/failure tracking
- **Command Line Interface**: Flexible test execution options

## Running Tests

### Quick Start
```bash
# Run all tests
npm run test:all

# Run comprehensive test suite
npm run test:comprehensive
```

### Individual Test Categories
```bash
# Basic functionality tests
npm run test:basic

# Post-quantum cryptography tests
npm run test:post-quantum

# Integration scenario tests
npm run test:integration

# Performance benchmarks
npm run test:performance
```

### Advanced Test Runner Options
```bash
# Run specific test categories
node test/run-all-tests.js --basic
node test/run-all-tests.js --pq --integration
node test/run-all-tests.js --performance

# Get help
node test/run-all-tests.js --help
```

## Test Categories Explained

### Classical Cryptography Tests
- **Symmetric Encryption**: Tests AES-256-GCM and ChaCha20-Poly1305 with various data sizes
- **Asymmetric Cryptography**: RSA encryption/decryption, Ed25519 and ECDSA signing/verification
- **Hash Functions**: SHA-256, SHA-512, BLAKE3, and HMAC operations
- **Key Derivation**: Password-based key derivation using Argon2, PBKDF2, and HKDF
- **Random Generation**: Cryptographically secure random number generation

### Post-Quantum Cryptography Tests
- **ML-KEM (Key Encapsulation Mechanism)**:
  - ML-KEM-512 (NIST Level 1): Fastest, smallest keys
  - ML-KEM-768 (NIST Level 3): Recommended default
  - ML-KEM-1024 (NIST Level 5): Highest security
- **ML-DSA (Digital Signature Algorithm)**:
  - ML-DSA-44 (NIST Level 2): Smaller signatures
  - ML-DSA-65 (NIST Level 3): Recommended default
  - ML-DSA-87 (NIST Level 5): Highest security

### Integration Tests
1. **Secure Messaging System**:
   - Key exchange using ML-KEM-768
   - Message signing using ML-DSA-65
   - Message encryption using AES-256-GCM
   - End-to-end secure communication

2. **Hybrid Cryptography System**:
   - Combines classical (RSA, ECDSA) and post-quantum (ML-KEM, ML-DSA) algorithms
   - Defense-in-depth approach
   - Dual key exchange and dual signatures

3. **Secure File Storage**:
   - Password-based key derivation
   - File encryption with integrity protection
   - Access control using digital signatures
   - Tamper detection

4. **Blockchain-like Integrity Chain**:
   - Chain of cryptographically linked blocks
   - Each block signed with ML-DSA-65
   - Hash-based block linking
   - Chain integrity verification

### Performance Tests
- **Throughput Benchmarks**: MB/s for encryption/decryption operations
- **Latency Measurements**: Time per operation for different algorithms
- **Key Generation Performance**: Speed of keypair generation
- **Memory Usage Analysis**: Heap usage during cryptographic operations
- **Scalability Testing**: Performance with large data sets

## Test Results Interpretation

### Success Criteria
- ✅ **All basic functionality works correctly**
- ✅ **Post-quantum algorithms produce correct results**
- ✅ **Integration scenarios complete successfully**
- ✅ **Performance benchmarks complete without errors**

### Performance Expectations
- **AES-256-GCM**: >100 MB/s for large data
- **ChaCha20-Poly1305**: >80 MB/s for large data
- **SHA-256**: >200 MB/s for large data
- **BLAKE3**: >300 MB/s for large data
- **ML-KEM Key Generation**: <10ms per keypair
- **ML-DSA Signing**: <5ms per signature

### Memory Usage
- **Normal Operations**: <50MB heap usage
- **Bulk Operations**: Memory should be released after operations
- **No Memory Leaks**: Memory usage should stabilize

## Troubleshooting

### Common Issues
1. **Native Module Loading**: Ensure the correct native module is built for your platform
2. **Performance Variations**: Results may vary based on hardware and system load
3. **Memory Tests**: Run with `--expose-gc` flag for accurate memory testing

### Debug Mode
```bash
# Run with detailed error information
NODE_ENV=development npm run test:all

# Run with garbage collection exposed (for memory tests)
node --expose-gc test/performance-test.js
```

### Platform-Specific Notes
- **macOS**: Tests optimized for Apple Silicon and Intel processors
- **Windows**: Supports both x64 and ARM64 architectures
- **Linux**: Supports various architectures and libc variants

## Contributing

When adding new tests:
1. Follow the existing test structure and naming conventions
2. Include both positive and negative test cases
3. Add performance benchmarks for new algorithms
4. Update this README with new test descriptions
5. Ensure tests work across all supported platforms

## Security Considerations

These tests verify:
- **Cryptographic Correctness**: Algorithms produce expected results
- **Key Uniqueness**: Generated keys are cryptographically unique
- **Tamper Detection**: Signatures detect message modifications
- **Side-Channel Resistance**: Constant-time operations where applicable
- **Memory Safety**: No buffer overflows or memory corruption

The test suite helps ensure LibSilver provides secure, reliable cryptographic functionality for Node.js applications.
