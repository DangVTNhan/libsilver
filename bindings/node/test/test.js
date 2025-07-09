const { SymmetricCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator } = require('../index.js');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
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

function runAllTests() {
  try {
    console.log('🧪 Running LibSilver Node.js binding tests...\n');
    
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
    
    console.log('🎉 All tests passed!');
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  runAllTests();
}

module.exports = {
  testSymmetricCrypto,
  testAsymmetricCrypto,
  testHashFunctions,
  testKeyDerivation,
  testRandomGenerator,
  runAllTests
};
