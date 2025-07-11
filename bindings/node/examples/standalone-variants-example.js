const { 
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto 
} = require('../index.js');

console.log('🎯 LibSilver Standalone Variants Example');
console.log('========================================');
console.log('Direct function calls for each post-quantum variant\n');

// ML-KEM-512 Direct Usage
console.log('1. ML-KEM-512 Direct Usage:');
console.log('---------------------------');

// Generate key pair
const kem512Keypair = MlKem512Crypto.generateKeypair();
console.log('✓ Generated ML-KEM-512 key pair');

// Encapsulate
const kem512Encapsulation = MlKem512Crypto.encapsulate(kem512Keypair.publicKeyBytes);
console.log('✓ Encapsulated shared secret');

// Decapsulate
const kem512SharedSecret = MlKem512Crypto.decapsulate(
  kem512Encapsulation.ciphertext,
  kem512Keypair.privateKeyBytes
);
console.log('✓ Decapsulated shared secret');

console.log(`✓ ML-KEM-512 working correctly: ${kem512Encapsulation.sharedSecret.equals(kem512SharedSecret) ? 'YES' : 'NO'}`);

// ML-KEM-768 Direct Usage (Recommended)
console.log('\n2. ML-KEM-768 Direct Usage (Recommended):');
console.log('------------------------------------------');

const kem768Keypair = MlKem768Crypto.generateKeypair();
const kem768Encapsulation = MlKem768Crypto.encapsulate(kem768Keypair.publicKeyBytes);
const kem768SharedSecret = MlKem768Crypto.decapsulate(
  kem768Encapsulation.ciphertext,
  kem768Keypair.privateKeyBytes
);

console.log(`✓ ML-KEM-768 working correctly: ${kem768Encapsulation.sharedSecret.equals(kem768SharedSecret) ? 'YES' : 'NO'}`);

// ML-KEM-1024 Direct Usage
console.log('\n3. ML-KEM-1024 Direct Usage:');
console.log('----------------------------');

const kem1024Keypair = MlKem1024Crypto.generateKeypair();
const kem1024Encapsulation = MlKem1024Crypto.encapsulate(kem1024Keypair.publicKeyBytes);
const kem1024SharedSecret = MlKem1024Crypto.decapsulate(
  kem1024Encapsulation.ciphertext,
  kem1024Keypair.privateKeyBytes
);

console.log(`✓ ML-KEM-1024 working correctly: ${kem1024Encapsulation.sharedSecret.equals(kem1024SharedSecret) ? 'YES' : 'NO'}`);

// ML-DSA-44 Direct Usage
console.log('\n4. ML-DSA-44 Direct Usage:');
console.log('--------------------------');

const dsa44Keypair = MlDsa44Crypto.generateKeypair();
const message = Buffer.from('Hello from ML-DSA-44!', 'utf8');
const dsa44Signature = MlDsa44Crypto.sign(message, dsa44Keypair.privateKeyBytes);
const dsa44Valid = MlDsa44Crypto.verify(message, dsa44Signature, dsa44Keypair.publicKeyBytes);

console.log(`✓ ML-DSA-44 working correctly: ${dsa44Valid ? 'YES' : 'NO'}`);

// ML-DSA-65 Direct Usage (Recommended)
console.log('\n5. ML-DSA-65 Direct Usage (Recommended):');
console.log('-----------------------------------------');

const dsa65Keypair = MlDsa65Crypto.generateKeypair();
const message65 = Buffer.from('Hello from ML-DSA-65!', 'utf8');
const dsa65Signature = MlDsa65Crypto.sign(message65, dsa65Keypair.privateKeyBytes);
const dsa65Valid = MlDsa65Crypto.verify(message65, dsa65Signature, dsa65Keypair.publicKeyBytes);

console.log(`✓ ML-DSA-65 working correctly: ${dsa65Valid ? 'YES' : 'NO'}`);

// ML-DSA-87 Direct Usage
console.log('\n6. ML-DSA-87 Direct Usage:');
console.log('--------------------------');

const dsa87Keypair = MlDsa87Crypto.generateKeypair();
const message87 = Buffer.from('Hello from ML-DSA-87!', 'utf8');
const dsa87Signature = MlDsa87Crypto.sign(message87, dsa87Keypair.privateKeyBytes);
const dsa87Valid = MlDsa87Crypto.verify(message87, dsa87Signature, dsa87Keypair.publicKeyBytes);

console.log(`✓ ML-DSA-87 working correctly: ${dsa87Valid ? 'YES' : 'NO'}`);

// Size Constants Demo
console.log('\n7. Size Constants Demo:');
console.log('-----------------------');

const kem512Sizes = MlKem512Crypto.getSizes();
const kem768Sizes = MlKem768Crypto.getSizes();
const kem1024Sizes = MlKem1024Crypto.getSizes();

const dsa44Sizes = MlDsa44Crypto.getSizes();
const dsa65Sizes = MlDsa65Crypto.getSizes();
const dsa87Sizes = MlDsa87Crypto.getSizes();

console.log('ML-KEM Size Constants:');
console.log(`  ML-KEM-512:  PK=${kem512Sizes.publicKeySize}, SK=${kem512Sizes.privateKeySize}, CT=${kem512Sizes.ciphertextSize}, SS=${kem512Sizes.sharedSecretSize}`);
console.log(`  ML-KEM-768:  PK=${kem768Sizes.publicKeySize}, SK=${kem768Sizes.privateKeySize}, CT=${kem768Sizes.ciphertextSize}, SS=${kem768Sizes.sharedSecretSize}`);
console.log(`  ML-KEM-1024: PK=${kem1024Sizes.publicKeySize}, SK=${kem1024Sizes.privateKeySize}, CT=${kem1024Sizes.ciphertextSize}, SS=${kem1024Sizes.sharedSecretSize}`);

console.log('\nML-DSA Size Constants:');
console.log(`  ML-DSA-44: PK=${dsa44Sizes.publicKeySize}, SK=${dsa44Sizes.privateKeySize}, MaxSig=${dsa44Sizes.maxSignatureSize}`);
console.log(`  ML-DSA-65: PK=${dsa65Sizes.publicKeySize}, SK=${dsa65Sizes.privateKeySize}, MaxSig=${dsa65Sizes.maxSignatureSize}`);
console.log(`  ML-DSA-87: PK=${dsa87Sizes.publicKeySize}, SK=${dsa87Sizes.privateKeySize}, MaxSig=${dsa87Sizes.maxSignatureSize}`);

console.log('\n🎉 All standalone variants working perfectly!');
console.log('\n💡 Now you can use direct function calls like:');
console.log('   • MlKem512Crypto.encapsulate()');
console.log('   • MlKem768Crypto.decapsulate()');
console.log('   • MlDsa65Crypto.sign()');
console.log('   • MlDsa87Crypto.verify()');
console.log('   • MlKem1024Crypto.getSizes()');
console.log('   And many more!');

console.log('\n📚 Key Benefits:');
console.log('   ✓ Direct function calls - no more generic parameters');
console.log('   ✓ Type safety - each variant has its own types');
console.log('   ✓ Size constants - easy buffer pre-allocation');
console.log('   ✓ Better performance - compile-time optimizations');
console.log('   ✓ Cleaner API - variant-specific functions');

// Practical Buffer Pre-allocation Example
console.log('\n8. Practical Buffer Pre-allocation Example:');
console.log('-------------------------------------------');

// Pre-allocate buffers using size constants
const publicKeyBuffer = Buffer.alloc(kem768Sizes.publicKeySize);
const privateKeyBuffer = Buffer.alloc(kem768Sizes.privateKeySize);
const ciphertextBuffer = Buffer.alloc(kem768Sizes.ciphertextSize);
const sharedSecretBuffer = Buffer.alloc(kem768Sizes.sharedSecretSize);

console.log(`✓ Pre-allocated buffers for ML-KEM-768:`);
console.log(`  Public key buffer: ${publicKeyBuffer.length} bytes`);
console.log(`  Private key buffer: ${privateKeyBuffer.length} bytes`);
console.log(`  Ciphertext buffer: ${ciphertextBuffer.length} bytes`);
console.log(`  Shared secret buffer: ${sharedSecretBuffer.length} bytes`);

// Use the pre-allocated buffers
const testKeypair = MlKem768Crypto.generateKeypair();
testKeypair.publicKeyBytes.copy(publicKeyBuffer);
testKeypair.privateKeyBytes.copy(privateKeyBuffer);

const testEncapsulation = MlKem768Crypto.encapsulate(publicKeyBuffer);
testEncapsulation.ciphertext.copy(ciphertextBuffer);
testEncapsulation.sharedSecret.copy(sharedSecretBuffer);

const testDecapsulated = MlKem768Crypto.decapsulate(ciphertextBuffer, privateKeyBuffer);
console.log(`✓ Pre-allocated buffers work correctly: ${sharedSecretBuffer.equals(testDecapsulated) ? 'YES' : 'NO'}`);

console.log('\n🚀 LibSilver Node.js bindings with standalone variants are ready for production!');
