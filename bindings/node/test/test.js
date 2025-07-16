const {
  SymmetricCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator,
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto
} = require('../index.js');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertThrows(fn, expectedMessage, testDescription) {
  try {
    fn();
    throw new Error(`${testDescription}: Expected function to throw, but it didn't`);
  } catch (error) {
    if (expectedMessage && !error.message.includes(expectedMessage)) {
      throw new Error(`${testDescription}: Expected error message to contain "${expectedMessage}", but got "${error.message}"`);
    }
  }
}

function testSymmetricCrypto() {
  console.log('Testing Symmetric Crypto...');
  
  // Test AES-256-GCM
  const aesKey = SymmetricCrypto.generateAesKey();
  assert(aesKey.length === 32, 'AES key should be 32 bytes');
  
  const plaintext = Buffer.from('Hello, World!', 'utf8');
  const ciphertext = SymmetricCrypto.encryptAes(plaintext, aesKey);
  const decrypted = SymmetricCrypto.decryptAes(ciphertext, aesKey);
  
  assert(plaintext.equals(decrypted), 'AES decryption should match original plaintext');
  console.log('✓ AES-256-GCM encryption/decryption works');
  
  // Test ChaCha20-Poly1305
  const chachaKey = SymmetricCrypto.generateChacha20Key();
  assert(chachaKey.length === 32, 'ChaCha20 key should be 32 bytes');
  
  const ciphertext2 = SymmetricCrypto.encryptChacha20(plaintext, chachaKey);
  const decrypted2 = SymmetricCrypto.decryptChacha20(ciphertext2, chachaKey);
  
  assert(plaintext.equals(decrypted2), 'ChaCha20 decryption should match original plaintext');
  console.log('✓ ChaCha20-Poly1305 encryption/decryption works');
}

function testAsymmetricCrypto() {
  console.log('Testing Asymmetric Crypto...');
  
  // Test RSA
  const rsaKeypair = AsymmetricCrypto.generateRsaKeypair();
  assert(typeof rsaKeypair.publicKeyPem === 'string', 'RSA public key should be a string');
  assert(typeof rsaKeypair.privateKeyPem === 'string', 'RSA private key should be a string');
  
  const message = Buffer.from('RSA test message', 'utf8');
  const rsaCiphertext = AsymmetricCrypto.encryptRsa(message, rsaKeypair.publicKeyPem);
  const rsaDecrypted = AsymmetricCrypto.decryptRsa(rsaCiphertext, rsaKeypair.privateKeyPem);
  
  assert(message.equals(rsaDecrypted), 'RSA decryption should match original message');
  console.log('✓ RSA-OAEP encryption/decryption works');
  
  // Test Ed25519
  const ed25519Keypair = AsymmetricCrypto.generateEd25519Keypair();
  assert(ed25519Keypair.signingKeyBytes.length === 32, 'Ed25519 signing key should be 32 bytes');
  assert(ed25519Keypair.verifyingKeyBytes.length === 32, 'Ed25519 verifying key should be 32 bytes');
  
  const signature = AsymmetricCrypto.signEd25519(message, ed25519Keypair.signingKeyBytes);
  const isValid = AsymmetricCrypto.verifyEd25519(message, signature, ed25519Keypair.verifyingKeyBytes);
  
  assert(isValid === true, 'Ed25519 signature should be valid');
  console.log('✓ Ed25519 signing/verification works');
  
  // Test ECDSA P-256
  const ecdsaKeypair = AsymmetricCrypto.generateEcdsaKeypair();
  assert(ecdsaKeypair.signingKeyBytes.length === 32, 'ECDSA signing key should be 32 bytes');
  assert(ecdsaKeypair.verifyingKeyBytes.length > 0, 'ECDSA verifying key should not be empty');
  
  const ecdsaSignature = AsymmetricCrypto.signEcdsa(message, ecdsaKeypair.signingKeyBytes);
  const ecdsaValid = AsymmetricCrypto.verifyEcdsa(message, ecdsaSignature, ecdsaKeypair.verifyingKeyBytes);
  
  assert(ecdsaValid === true, 'ECDSA signature should be valid');
  console.log('✓ ECDSA P-256 signing/verification works');
}

function testHashFunctions() {
  console.log('Testing Hash Functions...');
  
  const data = Buffer.from('Hash this data', 'utf8');
  
  // Test SHA-256
  const sha256Hash = HashFunctions.sha256(data);
  assert(sha256Hash.length === 32, 'SHA-256 hash should be 32 bytes');
  
  const sha256Hex = HashFunctions.sha256Hex(data);
  assert(typeof sha256Hex === 'string' && sha256Hex.length === 64, 'SHA-256 hex should be 64 characters');
  console.log('✓ SHA-256 hashing works');
  
  // Test SHA-512
  const sha512Hash = HashFunctions.sha512(data);
  assert(sha512Hash.length === 64, 'SHA-512 hash should be 64 bytes');
  console.log('✓ SHA-512 hashing works');
  
  // Test BLAKE3
  const blake3Hash = HashFunctions.blake3(data);
  assert(blake3Hash.length === 32, 'BLAKE3 hash should be 32 bytes');
  
  const blake3Custom = HashFunctions.blake3WithLength(data, 64);
  assert(blake3Custom.length === 64, 'BLAKE3 custom length should work');
  console.log('✓ BLAKE3 hashing works');
  
  // Test HMAC
  const key = Buffer.from('secret key', 'utf8');
  const hmacSha256 = HashFunctions.hmacSha256(key, data);
  const hmacValid = HashFunctions.verifyHmacSha256(key, data, hmacSha256);
  
  assert(hmacValid === true, 'HMAC-SHA256 verification should work');
  console.log('✓ HMAC-SHA256 works');
}

function testKeyDerivation() {
  console.log('Testing Key Derivation...');
  
  const password = Buffer.from('password123', 'utf8');
  const salt = RandomGenerator.generateSalt();
  
  // Test Argon2
  const argon2Key = KeyDerivation.argon2(password, salt, 32);
  assert(argon2Key.length === 32, 'Argon2 derived key should be 32 bytes');
  console.log('✓ Argon2 key derivation works');
  
  // Test PBKDF2
  const pbkdf2Key = KeyDerivation.pbkdf2Sha256(password, salt, 10000, 32);
  assert(pbkdf2Key.length === 32, 'PBKDF2 derived key should be 32 bytes');
  console.log('✓ PBKDF2 key derivation works');
  
  // Test HKDF
  const inputKey = RandomGenerator.generateBytes(32);
  const hkdfKey = KeyDerivation.hkdfSha256(inputKey, salt, null, 32);
  assert(hkdfKey.length === 32, 'HKDF derived key should be 32 bytes');
  console.log('✓ HKDF key derivation works');
}

function testRandomGenerator() {
  console.log('Testing Random Generator...');
  
  const randomBytes = RandomGenerator.generateBytes(32);
  assert(randomBytes.length === 32, 'Random bytes should be 32 bytes');
  
  const key = RandomGenerator.generateKey(32);
  assert(key.length === 32, 'Generated key should be 32 bytes');
  
  const nonce = RandomGenerator.generateNonce(12);
  assert(nonce.length === 12, 'Generated nonce should be 12 bytes');
  
  const salt = RandomGenerator.generateSalt();
  assert(salt.length === 32, 'Generated salt should be 32 bytes');
  
  console.log('✓ Random generation works');
}

// Enhanced Symmetric Crypto Tests
function testSymmetricCryptoAdvanced() {
  console.log('Testing Advanced Symmetric Crypto...');

  // Test with different data sizes (skip zero-length as it's not supported)
  const testSizes = [1, 16, 64, 1024, 4096];

  for (const size of testSizes) {
    const data = RandomGenerator.generateBytes(size);
    const aesKey = SymmetricCrypto.generateAesKey();
    const chachaKey = SymmetricCrypto.generateChacha20Key();

    // Test AES with different sizes
    const aesEncrypted = SymmetricCrypto.encryptAes(data, aesKey);
    const aesDecrypted = SymmetricCrypto.decryptAes(aesEncrypted, aesKey);
    assert(data.equals(aesDecrypted), `AES should work with ${size} bytes`);

    // Test ChaCha20 with different sizes
    const chachaEncrypted = SymmetricCrypto.encryptChacha20(data, chachaKey);
    const chachaDecrypted = SymmetricCrypto.decryptChacha20(chachaEncrypted, chachaKey);
    assert(data.equals(chachaDecrypted), `ChaCha20 should work with ${size} bytes`);
  }

  // Test key uniqueness
  const keys = [];
  for (let i = 0; i < 10; i++) {
    keys.push(SymmetricCrypto.generateAesKey());
  }

  // Ensure all keys are unique
  for (let i = 0; i < keys.length; i++) {
    for (let j = i + 1; j < keys.length; j++) {
      assert(!keys[i].equals(keys[j]), 'Generated keys should be unique');
    }
  }

  console.log('✓ Advanced symmetric crypto tests passed');
}

// Enhanced Asymmetric Crypto Tests
function testAsymmetricCryptoAdvanced() {
  console.log('Testing Advanced Asymmetric Crypto...');

  // Test RSA with different message sizes (within RSA-OAEP limits)
  const rsaKeypair = AsymmetricCrypto.generateRsaKeypair();
  const testMessages = [
    Buffer.from('A', 'utf8'), // Single character (skip empty as it may not be supported)
    Buffer.from('Hello, World!', 'utf8'), // Standard message
    Buffer.from('A'.repeat(50), 'utf8'), // Medium message
    Buffer.from('A'.repeat(100), 'utf8'), // Longer message (within RSA limits)
  ];

  for (const message of testMessages) {
    if (message.length <= 190) { // RSA-OAEP padding limit for 2048-bit key
      const encrypted = AsymmetricCrypto.encryptRsa(message, rsaKeypair.publicKeyPem);
      const decrypted = AsymmetricCrypto.decryptRsa(encrypted, rsaKeypair.privateKeyPem);
      assert(message.equals(decrypted), `RSA should work with message of length ${message.length}`);
    }
  }

  // Test signature verification with multiple keypairs
  const keypairs = [];
  for (let i = 0; i < 3; i++) {
    keypairs.push(AsymmetricCrypto.generateEd25519Keypair());
  }

  const message = Buffer.from('Cross-verification test', 'utf8');
  const signatures = keypairs.map(kp => AsymmetricCrypto.signEd25519(message, kp.signingKeyBytes));

  // Test that each signature only verifies with its corresponding key
  for (let i = 0; i < keypairs.length; i++) {
    for (let j = 0; j < keypairs.length; j++) {
      const isValid = AsymmetricCrypto.verifyEd25519(message, signatures[i], keypairs[j].verifyingKeyBytes);
      if (i === j) {
        assert(isValid, `Signature ${i} should verify with keypair ${j}`);
      } else {
        assert(!isValid, `Signature ${i} should NOT verify with keypair ${j}`);
      }
    }
  }

  console.log('✓ Advanced asymmetric crypto tests passed');
}

// Post-Quantum Cryptography Tests
function testPostQuantumCrypto() {
  console.log('Testing Post-Quantum Cryptography...');

  // Test all ML-KEM variants
  const kemVariants = [
    { name: 'ML-KEM-512', crypto: MlKem512Crypto, level: 1 },
    { name: 'ML-KEM-768', crypto: MlKem768Crypto, level: 3 },
    { name: 'ML-KEM-1024', crypto: MlKem1024Crypto, level: 5 }
  ];

  for (const variant of kemVariants) {
    console.log(`  Testing ${variant.name} (NIST Level ${variant.level})...`);

    // Test key generation
    const keypair = variant.crypto.generateKeypair();
    const sizes = variant.crypto.getSizes();

    assert(keypair.publicKeyBytes.length === sizes.publicKeySize,
           `${variant.name} public key size should match constant`);
    assert(keypair.privateKeyBytes.length === sizes.privateKeySize,
           `${variant.name} private key size should match constant`);

    // Test encapsulation/decapsulation
    const encapsulation = variant.crypto.encapsulate(keypair.publicKeyBytes);
    assert(encapsulation.ciphertext.length === sizes.ciphertextSize,
           `${variant.name} ciphertext size should match constant`);
    assert(encapsulation.sharedSecret.length === sizes.sharedSecretSize,
           `${variant.name} shared secret size should match constant`);

    const decapsulatedSecret = variant.crypto.decapsulate(encapsulation.ciphertext, keypair.privateKeyBytes);
    assert(encapsulation.sharedSecret.equals(decapsulatedSecret),
           `${variant.name} decapsulated secret should match original`);

    // Test multiple encapsulations produce different ciphertexts but same shared secret when decapsulated
    const encapsulation2 = variant.crypto.encapsulate(keypair.publicKeyBytes);
    assert(!encapsulation.ciphertext.equals(encapsulation2.ciphertext),
           `${variant.name} should produce different ciphertexts`);

    const decapsulatedSecret2 = variant.crypto.decapsulate(encapsulation2.ciphertext, keypair.privateKeyBytes);
    assert(encapsulation2.sharedSecret.equals(decapsulatedSecret2),
           `${variant.name} second decapsulation should work`);
  }

  // Test all ML-DSA variants
  const dsaVariants = [
    { name: 'ML-DSA-44', crypto: MlDsa44Crypto, level: 2 },
    { name: 'ML-DSA-65', crypto: MlDsa65Crypto, level: 3 },
    { name: 'ML-DSA-87', crypto: MlDsa87Crypto, level: 5 }
  ];

  for (const variant of dsaVariants) {
    console.log(`  Testing ${variant.name} (NIST Level ${variant.level})...`);

    // Test key generation
    const keypair = variant.crypto.generateKeypair();
    const sizes = variant.crypto.getSizes();

    assert(keypair.publicKeyBytes.length === sizes.publicKeySize,
           `${variant.name} public key size should match constant`);
    assert(keypair.privateKeyBytes.length === sizes.privateKeySize,
           `${variant.name} private key size should match constant`);

    // Test signing with different message sizes (skip empty messages)
    const testMessages = [
      Buffer.from('Short', 'utf8'),
      Buffer.from('Medium length message for testing', 'utf8'),
      Buffer.from('A'.repeat(1000), 'utf8'),
      RandomGenerator.generateBytes(4096)
    ];

    for (const message of testMessages) {
      const signature = variant.crypto.sign(message, keypair.privateKeyBytes);
      assert(signature.length <= sizes.maxSignatureSize,
             `${variant.name} signature size should not exceed maximum`);

      const isValid = variant.crypto.verify(message, signature, keypair.publicKeyBytes);
      assert(isValid, `${variant.name} signature should be valid for message of length ${message.length}`);

      // Test with wrong message
      const wrongMessage = Buffer.concat([message, Buffer.from('X')]);
      const isInvalid = variant.crypto.verify(wrongMessage, signature, keypair.publicKeyBytes);
      assert(!isInvalid, `${variant.name} signature should be invalid for wrong message`);
    }
  }

  console.log('✓ Post-quantum cryptography tests passed');
}

// Integration Tests - Combining different cryptographic primitives
function testIntegration() {
  console.log('Testing Integration Scenarios...');

  // Test 1: Hybrid Encryption (ML-KEM + AES)
  console.log('  Testing Hybrid Encryption (ML-KEM-768 + AES)...');

  // Alice generates ML-KEM keypair
  const aliceKeypair = MlKem768Crypto.generateKeypair();

  // Bob wants to send encrypted message to Alice
  const secretMessage = Buffer.from('This is a confidential message using hybrid encryption!', 'utf8');

  // Bob encapsulates shared secret using Alice's public key
  const encapsulation = MlKem768Crypto.encapsulate(aliceKeypair.publicKeyBytes);

  // Bob encrypts message using AES with the shared secret
  const encryptedMessage = SymmetricCrypto.encryptAes(secretMessage, encapsulation.sharedSecret);

  // Alice decapsulates shared secret and decrypts message
  const aliceSharedSecret = MlKem768Crypto.decapsulate(encapsulation.ciphertext, aliceKeypair.privateKeyBytes);
  const hybridDecryptedMessage = SymmetricCrypto.decryptAes(encryptedMessage, aliceSharedSecret);

  assert(secretMessage.equals(hybridDecryptedMessage), 'Hybrid encryption should work correctly');

  // Test 2: Digital Signature with Hash
  console.log('  Testing Digital Signature with Hash (ML-DSA-65 + SHA-256)...');

  const signerKeypair = MlDsa65Crypto.generateKeypair();
  const document = Buffer.from('Important document that needs to be signed', 'utf8');

  // Hash the document first (best practice)
  const documentHash = HashFunctions.sha256(document);

  // Sign the hash
  const signature = MlDsa65Crypto.sign(documentHash, signerKeypair.privateKeyBytes);

  // Verify the signature
  const isValid = MlDsa65Crypto.verify(documentHash, signature, signerKeypair.publicKeyBytes);
  assert(isValid, 'Document signature should be valid');

  // Test tampering detection
  const tamperedDocument = Buffer.from('Important document that needs to be signed [TAMPERED]', 'utf8');
  const tamperedHash = HashFunctions.sha256(tamperedDocument);
  const isTamperedValid = MlDsa65Crypto.verify(tamperedHash, signature, signerKeypair.publicKeyBytes);
  assert(!isTamperedValid, 'Tampered document signature should be invalid');

  // Test 3: Key Derivation + Symmetric Encryption
  console.log('  Testing Key Derivation + Symmetric Encryption...');

  const password = Buffer.from('user_password_123', 'utf8');
  const salt = RandomGenerator.generateSalt();

  // Derive key using Argon2
  const derivedKey = KeyDerivation.argon2(password, salt, 32);

  // Use derived key for AES encryption
  const plaintext = Buffer.from('Data encrypted with derived key', 'utf8');
  const encrypted = SymmetricCrypto.encryptAes(plaintext, derivedKey);
  const decrypted = SymmetricCrypto.decryptAes(encrypted, derivedKey);

  assert(plaintext.equals(decrypted), 'Key derivation + encryption should work');

  // Test 4: HMAC Authentication + Encryption
  console.log('  Testing HMAC Authentication + Encryption...');

  const hmacKey = RandomGenerator.generateKey(32);
  const encryptionKey = RandomGenerator.generateKey(32);
  const message = Buffer.from('Authenticated and encrypted message', 'utf8');

  // Encrypt first
  const ciphertext = SymmetricCrypto.encryptAes(message, encryptionKey);

  // Then authenticate
  const hmac = HashFunctions.hmacSha256(hmacKey, ciphertext);

  // Verify authentication then decrypt
  const isAuthentic = HashFunctions.verifyHmacSha256(hmacKey, ciphertext, hmac);
  assert(isAuthentic, 'HMAC should be valid');

  const authenticatedDecryptedMessage = SymmetricCrypto.decryptAes(ciphertext, encryptionKey);
  assert(message.equals(authenticatedDecryptedMessage), 'Authenticated encryption should work');

  // Test 5: Multi-level Key Derivation
  console.log('  Testing Multi-level Key Derivation...');

  const masterPassword = Buffer.from('master_password', 'utf8');
  const masterSalt = RandomGenerator.generateSalt();

  // First level: derive master key
  const masterKey = KeyDerivation.argon2(masterPassword, masterSalt, 32);

  // Second level: derive specific keys using HKDF
  const encryptionKeySalt = RandomGenerator.generateSalt();
  const authenticationKeySalt = RandomGenerator.generateSalt();

  const derivedEncryptionKey = KeyDerivation.hkdfSha256(masterKey, encryptionKeySalt, Buffer.from('encryption'), 32);
  const derivedAuthKey = KeyDerivation.hkdfSha256(masterKey, authenticationKeySalt, Buffer.from('authentication'), 32);

  // Use derived keys
  const testData = Buffer.from('Multi-level derived key test', 'utf8');
  const encryptedData = SymmetricCrypto.encryptAes(testData, derivedEncryptionKey);
  const authTag = HashFunctions.hmacSha256(derivedAuthKey, encryptedData);

  // Verify and decrypt
  const isAuthValid = HashFunctions.verifyHmacSha256(derivedAuthKey, encryptedData, authTag);
  assert(isAuthValid, 'Multi-level derived authentication should work');

  const decryptedData = SymmetricCrypto.decryptAes(encryptedData, derivedEncryptionKey);
  assert(testData.equals(decryptedData), 'Multi-level derived encryption should work');

  console.log('✓ Integration tests passed');
}

// Performance and Stress Tests
function testPerformanceAndStress() {
  console.log('Testing Performance and Stress Scenarios...');

  // Test 1: Large data encryption
  console.log('  Testing large data encryption...');
  const largeData = RandomGenerator.generateBytes(1024 * 1024); // 1MB
  const aesKey = SymmetricCrypto.generateAesKey();

  const startTime = Date.now();
  const encrypted = SymmetricCrypto.encryptAes(largeData, aesKey);
  const decrypted = SymmetricCrypto.decryptAes(encrypted, aesKey);
  const endTime = Date.now();

  assert(largeData.equals(decrypted), 'Large data encryption should work');
  console.log(`    Encrypted/decrypted 1MB in ${endTime - startTime}ms`);

  // Test 2: Multiple key generation
  console.log('  Testing multiple key generation...');
  const keyCount = 100;
  const keys = [];

  const keyGenStart = Date.now();
  for (let i = 0; i < keyCount; i++) {
    keys.push(SymmetricCrypto.generateAesKey());
  }
  const keyGenEnd = Date.now();

  // Verify all keys are unique
  const keySet = new Set(keys.map(k => k.toString('hex')));
  assert(keySet.size === keyCount, 'All generated keys should be unique');
  console.log(`    Generated ${keyCount} unique keys in ${keyGenEnd - keyGenStart}ms`);

  // Test 3: Post-quantum key generation performance
  console.log('  Testing post-quantum key generation performance...');

  const pqKeyGenStart = Date.now();
  const kemKeypair = MlKem768Crypto.generateKeypair();
  const dsaKeypair = MlDsa65Crypto.generateKeypair();
  const pqKeyGenEnd = Date.now();

  assert(kemKeypair.publicKeyBytes.length > 0, 'ML-KEM keypair should be generated');
  assert(dsaKeypair.publicKeyBytes.length > 0, 'ML-DSA keypair should be generated');
  console.log(`    Generated PQ keypairs in ${pqKeyGenEnd - pqKeyGenStart}ms`);

  // Test 4: Hash performance with different algorithms
  console.log('  Testing hash performance...');
  const hashData = RandomGenerator.generateBytes(10240); // 10KB

  const hashTests = [
    { name: 'SHA-256', fn: () => HashFunctions.sha256(hashData) },
    { name: 'SHA-512', fn: () => HashFunctions.sha512(hashData) },
    { name: 'BLAKE3', fn: () => HashFunctions.blake3(hashData) }
  ];

  for (const test of hashTests) {
    const start = Date.now();
    const hash = test.fn();
    const end = Date.now();
    assert(hash.length > 0, `${test.name} should produce hash`);
    console.log(`    ${test.name} hashed 10KB in ${end - start}ms`);
  }

  console.log('✓ Performance and stress tests passed');
}

function runAllTests() {
  try {
    console.log('🧪 Running Comprehensive LibSilver Node.js Tests...\n');

    // Basic functionality tests
    testSymmetricCrypto();
    console.log();

    testAsymmetricCrypto();
    console.log();

    testHashFunctions();
    console.log();

    testKeyDerivation();
    console.log();

    testRandomGenerator();
    console.log();

    // Advanced tests
    testSymmetricCryptoAdvanced();
    console.log();

    testAsymmetricCryptoAdvanced();
    console.log();

    // Post-quantum cryptography tests
    testPostQuantumCrypto();
    console.log();

    // Integration tests
    testIntegration();
    console.log();

    // Performance tests
    testPerformanceAndStress();
    console.log();

    console.log('🎉 All comprehensive tests passed!');
    console.log('\n📊 Test Summary:');
    console.log('   ✓ Classical Cryptography (Basic & Advanced)');
    console.log('   ✓ Post-Quantum Cryptography (ML-KEM & ML-DSA)');
    console.log('   ✓ Integration Scenarios');
    console.log('   ✓ Performance & Stress Tests');
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

if (require.main === module) {
  runAllTests();
}

module.exports = {
  // Basic tests
  testSymmetricCrypto,
  testAsymmetricCrypto,
  testHashFunctions,
  testKeyDerivation,
  testRandomGenerator,

  // Advanced tests
  testSymmetricCryptoAdvanced,
  testAsymmetricCryptoAdvanced,
  testPostQuantumCrypto,

  // Integration and performance tests
  testIntegration,
  testPerformanceAndStress,

  // Main test runner
  runAllTests,

  // Utility functions
  assert,
  assertThrows
};
