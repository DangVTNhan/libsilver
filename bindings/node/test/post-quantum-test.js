const { 
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto 
} = require('../index.js');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function testMlKem512() {
  console.log('Testing ML-KEM-512...');
  
  // Test key generation
  const keypair = MlKem512Crypto.generateKeypair();
  const sizes = MlKem512Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-KEM-512 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-KEM-512 private key size should match constant');
  
  // Test encapsulation
  const encapsulation = MlKem512Crypto.encapsulate(keypair.publicKeyBytes);
  assert(encapsulation.ciphertext.length === sizes.ciphertextSize, 'ML-KEM-512 ciphertext size should match constant');
  assert(encapsulation.sharedSecret.length === sizes.sharedSecretSize, 'ML-KEM-512 shared secret size should match constant');
  
  // Test decapsulation
  const decapsulatedSecret = MlKem512Crypto.decapsulate(encapsulation.ciphertext, keypair.privateKeyBytes);
  assert(encapsulation.sharedSecret.equals(decapsulatedSecret), 'ML-KEM-512 decapsulated secret should match original');
  
  console.log('✓ ML-KEM-512 works correctly');
}

function testMlKem768() {
  console.log('Testing ML-KEM-768...');
  
  // Test key generation
  const keypair = MlKem768Crypto.generateKeypair();
  const sizes = MlKem768Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-KEM-768 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-KEM-768 private key size should match constant');
  
  // Test encapsulation
  const encapsulation = MlKem768Crypto.encapsulate(keypair.publicKeyBytes);
  assert(encapsulation.ciphertext.length === sizes.ciphertextSize, 'ML-KEM-768 ciphertext size should match constant');
  assert(encapsulation.sharedSecret.length === sizes.sharedSecretSize, 'ML-KEM-768 shared secret size should match constant');
  
  // Test decapsulation
  const decapsulatedSecret = MlKem768Crypto.decapsulate(encapsulation.ciphertext, keypair.privateKeyBytes);
  assert(encapsulation.sharedSecret.equals(decapsulatedSecret), 'ML-KEM-768 decapsulated secret should match original');
  
  console.log('✓ ML-KEM-768 works correctly');
}

function testMlKem1024() {
  console.log('Testing ML-KEM-1024...');
  
  // Test key generation
  const keypair = MlKem1024Crypto.generateKeypair();
  const sizes = MlKem1024Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-KEM-1024 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-KEM-1024 private key size should match constant');
  
  // Test encapsulation
  const encapsulation = MlKem1024Crypto.encapsulate(keypair.publicKeyBytes);
  assert(encapsulation.ciphertext.length === sizes.ciphertextSize, 'ML-KEM-1024 ciphertext size should match constant');
  assert(encapsulation.sharedSecret.length === sizes.sharedSecretSize, 'ML-KEM-1024 shared secret size should match constant');
  
  // Test decapsulation
  const decapsulatedSecret = MlKem1024Crypto.decapsulate(encapsulation.ciphertext, keypair.privateKeyBytes);
  assert(encapsulation.sharedSecret.equals(decapsulatedSecret), 'ML-KEM-1024 decapsulated secret should match original');
  
  console.log('✓ ML-KEM-1024 works correctly');
}

function testMlDsa44() {
  console.log('Testing ML-DSA-44...');
  
  // Test key generation
  const keypair = MlDsa44Crypto.generateKeypair();
  const sizes = MlDsa44Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-DSA-44 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-DSA-44 private key size should match constant');
  
  // Test signing
  const message = Buffer.from('Test message for ML-DSA-44', 'utf8');
  const signature = MlDsa44Crypto.sign(message, keypair.privateKeyBytes);
  assert(signature.length <= sizes.maxSignatureSize, 'ML-DSA-44 signature size should not exceed maximum');
  
  // Test verification
  const isValid = MlDsa44Crypto.verify(message, signature, keypair.publicKeyBytes);
  assert(isValid === true, 'ML-DSA-44 signature should be valid');
  
  // Test with wrong message
  const wrongMessage = Buffer.from('Wrong message', 'utf8');
  const isInvalid = MlDsa44Crypto.verify(wrongMessage, signature, keypair.publicKeyBytes);
  assert(isInvalid === false, 'ML-DSA-44 signature should be invalid for wrong message');
  
  console.log('✓ ML-DSA-44 works correctly');
}

function testMlDsa65() {
  console.log('Testing ML-DSA-65...');
  
  // Test key generation
  const keypair = MlDsa65Crypto.generateKeypair();
  const sizes = MlDsa65Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-DSA-65 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-DSA-65 private key size should match constant');
  
  // Test signing
  const message = Buffer.from('Test message for ML-DSA-65', 'utf8');
  const signature = MlDsa65Crypto.sign(message, keypair.privateKeyBytes);
  assert(signature.length <= sizes.maxSignatureSize, 'ML-DSA-65 signature size should not exceed maximum');
  
  // Test verification
  const isValid = MlDsa65Crypto.verify(message, signature, keypair.publicKeyBytes);
  assert(isValid === true, 'ML-DSA-65 signature should be valid');
  
  // Test with wrong message
  const wrongMessage = Buffer.from('Wrong message', 'utf8');
  const isInvalid = MlDsa65Crypto.verify(wrongMessage, signature, keypair.publicKeyBytes);
  assert(isInvalid === false, 'ML-DSA-65 signature should be invalid for wrong message');
  
  console.log('✓ ML-DSA-65 works correctly');
}

function testMlDsa87() {
  console.log('Testing ML-DSA-87...');
  
  // Test key generation
  const keypair = MlDsa87Crypto.generateKeypair();
  const sizes = MlDsa87Crypto.getSizes();
  
  assert(keypair.publicKeyBytes.length === sizes.publicKeySize, 'ML-DSA-87 public key size should match constant');
  assert(keypair.privateKeyBytes.length === sizes.privateKeySize, 'ML-DSA-87 private key size should match constant');
  
  // Test signing
  const message = Buffer.from('Test message for ML-DSA-87', 'utf8');
  const signature = MlDsa87Crypto.sign(message, keypair.privateKeyBytes);
  assert(signature.length <= sizes.maxSignatureSize, 'ML-DSA-87 signature size should not exceed maximum');
  
  // Test verification
  const isValid = MlDsa87Crypto.verify(message, signature, keypair.publicKeyBytes);
  assert(isValid === true, 'ML-DSA-87 signature should be valid');
  
  // Test with wrong message
  const wrongMessage = Buffer.from('Wrong message', 'utf8');
  const isInvalid = MlDsa87Crypto.verify(wrongMessage, signature, keypair.publicKeyBytes);
  assert(isInvalid === false, 'ML-DSA-87 signature should be invalid for wrong message');
  
  console.log('✓ ML-DSA-87 works correctly');
}

function testSizeConstants() {
  console.log('Testing size constants...');
  
  // Test ML-KEM size constants
  const kem512Sizes = MlKem512Crypto.getSizes();
  const kem768Sizes = MlKem768Crypto.getSizes();
  const kem1024Sizes = MlKem1024Crypto.getSizes();
  
  assert(kem512Sizes.publicKeySize === 800, 'ML-KEM-512 public key size constant should be 800');
  assert(kem512Sizes.privateKeySize === 1632, 'ML-KEM-512 private key size constant should be 1632');
  assert(kem512Sizes.ciphertextSize === 768, 'ML-KEM-512 ciphertext size constant should be 768');
  assert(kem512Sizes.sharedSecretSize === 32, 'ML-KEM-512 shared secret size constant should be 32');
  
  assert(kem768Sizes.publicKeySize === 1184, 'ML-KEM-768 public key size constant should be 1184');
  assert(kem768Sizes.privateKeySize === 2400, 'ML-KEM-768 private key size constant should be 2400');
  assert(kem768Sizes.ciphertextSize === 1088, 'ML-KEM-768 ciphertext size constant should be 1088');
  assert(kem768Sizes.sharedSecretSize === 32, 'ML-KEM-768 shared secret size constant should be 32');
  
  assert(kem1024Sizes.publicKeySize === 1568, 'ML-KEM-1024 public key size constant should be 1568');
  assert(kem1024Sizes.privateKeySize === 3168, 'ML-KEM-1024 private key size constant should be 3168');
  assert(kem1024Sizes.ciphertextSize === 1568, 'ML-KEM-1024 ciphertext size constant should be 1568');
  assert(kem1024Sizes.sharedSecretSize === 32, 'ML-KEM-1024 shared secret size constant should be 32');
  
  // Test ML-DSA size constants
  const dsa44Sizes = MlDsa44Crypto.getSizes();
  const dsa65Sizes = MlDsa65Crypto.getSizes();
  const dsa87Sizes = MlDsa87Crypto.getSizes();
  
  assert(dsa44Sizes.publicKeySize === 1312, 'ML-DSA-44 public key size constant should be 1312');
  assert(dsa44Sizes.privateKeySize === 2560, 'ML-DSA-44 private key size constant should be 2560');
  assert(dsa44Sizes.maxSignatureSize === 2420, 'ML-DSA-44 max signature size constant should be 2420');
  
  assert(dsa65Sizes.publicKeySize === 1952, 'ML-DSA-65 public key size constant should be 1952');
  assert(dsa65Sizes.privateKeySize === 4032, 'ML-DSA-65 private key size constant should be 4032');
  assert(dsa65Sizes.maxSignatureSize === 3309, 'ML-DSA-65 max signature size constant should be 3309');
  
  assert(dsa87Sizes.publicKeySize === 2592, 'ML-DSA-87 public key size constant should be 2592');
  assert(dsa87Sizes.privateKeySize === 4896, 'ML-DSA-87 private key size constant should be 4896');
  assert(dsa87Sizes.maxSignatureSize === 4627, 'ML-DSA-87 max signature size constant should be 4627');
  
  console.log('✓ Size constants are correct');
}

function runPostQuantumTests() {
  try {
    console.log('🧪 Running LibSilver Post-Quantum Node.js binding tests...\n');
    
    testMlKem512();
    console.log();
    
    testMlKem768();
    console.log();
    
    testMlKem1024();
    console.log();
    
    testMlDsa44();
    console.log();
    
    testMlDsa65();
    console.log();
    
    testMlDsa87();
    console.log();
    
    testSizeConstants();
    console.log();
    
    console.log('🎉 All post-quantum tests passed!');
  } catch (error) {
    console.error('❌ Post-quantum test failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  runPostQuantumTests();
}

module.exports = {
  testMlKem512,
  testMlKem768,
  testMlKem1024,
  testMlDsa44,
  testMlDsa65,
  testMlDsa87,
  testSizeConstants,
  runPostQuantumTests
};
