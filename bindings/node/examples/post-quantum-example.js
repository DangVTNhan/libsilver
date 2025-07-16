const {
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto,
  SymmetricCrypto, HashFunctions
} = require('../index.js');

console.log('🔮 LibSilver Post-Quantum Cryptography Examples (Standalone Variants)\n');

// Example 1: ML-KEM (Key Encapsulation Mechanism) - All Variants
console.log('1. ML-KEM Key Encapsulation Mechanism');
console.log('=====================================');

// ML-KEM-512 (NIST Level 1) - Lowest security, smallest keys
console.log('\n1.1. ML-KEM-512 (NIST Level 1):');
const kemKeypair512 = MlKem512Crypto.generateKeypair();
const kem512Sizes = MlKem512Crypto.getSizes();
console.log('✓ Generated ML-KEM-512 key pair');
console.log(`  Public key size: ${kemKeypair512.publicKeyBytes.length} bytes (expected: ${kem512Sizes.publicKeySize})`);
console.log(`  Private key size: ${kemKeypair512.privateKeyBytes.length} bytes (expected: ${kem512Sizes.privateKeySize})`);

const kemEncapsulation512 = MlKem512Crypto.encapsulate(kemKeypair512.publicKeyBytes);
console.log('✓ Encapsulated shared secret');
console.log(`  Ciphertext size: ${kemEncapsulation512.ciphertext.length} bytes (expected: ${kem512Sizes.ciphertextSize})`);
console.log(`  Shared secret size: ${kemEncapsulation512.sharedSecret.length} bytes (expected: ${kem512Sizes.sharedSecretSize})`);

const kemDecapsulated512 = MlKem512Crypto.decapsulate(
  kemEncapsulation512.ciphertext,
  kemKeypair512.privateKeyBytes
);
console.log('✓ Decapsulated shared secret');
console.log(`  Secrets match: ${kemEncapsulation512.sharedSecret.equals(kemDecapsulated512) ? '✓' : '✗'}`);

// ML-KEM-768 (NIST Level 3) - Default and recommended
console.log('\n1.2. ML-KEM-768 (NIST Level 3) - Recommended:');
const kemKeypair768 = MlKem768Crypto.generateKeypair();
const kem768Sizes = MlKem768Crypto.getSizes();
console.log('✓ Generated ML-KEM-768 key pair');
console.log(`  Public key size: ${kemKeypair768.publicKeyBytes.length} bytes (expected: ${kem768Sizes.publicKeySize})`);
console.log(`  Private key size: ${kemKeypair768.privateKeyBytes.length} bytes (expected: ${kem768Sizes.privateKeySize})`);

const kemEncapsulation768 = MlKem768Crypto.encapsulate(kemKeypair768.publicKeyBytes);
console.log('✓ Encapsulated shared secret');
console.log(`  Ciphertext size: ${kemEncapsulation768.ciphertext.length} bytes (expected: ${kem768Sizes.ciphertextSize})`);
console.log(`  Shared secret size: ${kemEncapsulation768.sharedSecret.length} bytes (expected: ${kem768Sizes.sharedSecretSize})`);

const kemDecapsulated768 = MlKem768Crypto.decapsulate(
  kemEncapsulation768.ciphertext,
  kemKeypair768.privateKeyBytes
);
console.log('✓ Decapsulated shared secret');
console.log(`  Secrets match: ${kemEncapsulation768.sharedSecret.equals(kemDecapsulated768) ? '✓' : '✗'}`);

// ML-KEM-1024 (NIST Level 5) - Highest security, largest keys
console.log('\n1.3. ML-KEM-1024 (NIST Level 5):');
const kemKeypair1024 = MlKem1024Crypto.generateKeypair();
const kem1024Sizes = MlKem1024Crypto.getSizes();
console.log('✓ Generated ML-KEM-1024 key pair');
console.log(`  Public key size: ${kemKeypair1024.publicKeyBytes.length} bytes (expected: ${kem1024Sizes.publicKeySize})`);
console.log(`  Private key size: ${kemKeypair1024.privateKeyBytes.length} bytes (expected: ${kem1024Sizes.privateKeySize})`);

const kemEncapsulation1024 = MlKem1024Crypto.encapsulate(kemKeypair1024.publicKeyBytes);
console.log('✓ Encapsulated shared secret');
console.log(`  Ciphertext size: ${kemEncapsulation1024.ciphertext.length} bytes (expected: ${kem1024Sizes.ciphertextSize})`);
console.log(`  Shared secret size: ${kemEncapsulation1024.sharedSecret.length} bytes (expected: ${kem1024Sizes.sharedSecretSize})`);

const kemDecapsulated1024 = MlKem1024Crypto.decapsulate(
  kemEncapsulation1024.ciphertext,
  kemKeypair1024.privateKeyBytes
);
console.log('✓ Decapsulated shared secret');
console.log(`  Secrets match: ${kemEncapsulation1024.sharedSecret.equals(kemDecapsulated1024) ? '✓' : '✗'}`);

console.log();

// Example 2: ML-DSA (Digital Signature Algorithm) - All Variants
console.log('2. ML-DSA Digital Signature Algorithm');
console.log('=====================================');

// ML-DSA-44 (NIST Level 2) - Lower security, smaller keys
console.log('\n2.1. ML-DSA-44 (NIST Level 2):');
const dsaKeypair44 = MlDsa44Crypto.generateKeypair();
const dsa44Sizes = MlDsa44Crypto.getSizes();
console.log('✓ Generated ML-DSA-44 key pair');
console.log(`  Public key size: ${dsaKeypair44.publicKeyBytes.length} bytes (expected: ${dsa44Sizes.publicKeySize})`);
console.log(`  Private key size: ${dsaKeypair44.privateKeyBytes.length} bytes (expected: ${dsa44Sizes.privateKeySize})`);

const message44 = Buffer.from('Hello, post-quantum world! This message is signed with ML-DSA-44.', 'utf8');
const signature44 = MlDsa44Crypto.sign(message44, dsaKeypair44.privateKeyBytes);
console.log('✓ Signed message with ML-DSA-44');
console.log(`  Message: "${message44.toString('utf8')}"`);
console.log(`  Signature size: ${signature44.length} bytes (max: ${dsa44Sizes.maxSignatureSize})`);

const isValid44 = MlDsa44Crypto.verify(message44, signature44, dsaKeypair44.publicKeyBytes);
console.log(`  Signature verification: ${isValid44 ? '✓' : '✗'}`);

// Test with wrong message
const wrongMessage44 = Buffer.from('Wrong message', 'utf8');
const isInvalid44 = MlDsa44Crypto.verify(wrongMessage44, signature44, dsaKeypair44.publicKeyBytes);
console.log(`  Wrong message verification: ${!isInvalid44 ? '✓' : '✗'}`);

// ML-DSA-65 (NIST Level 3) - Default and recommended
console.log('\n2.2. ML-DSA-65 (NIST Level 3) - Recommended:');
const dsaKeypair65 = MlDsa65Crypto.generateKeypair();
const dsa65Sizes = MlDsa65Crypto.getSizes();
console.log('✓ Generated ML-DSA-65 key pair');
console.log(`  Public key size: ${dsaKeypair65.publicKeyBytes.length} bytes (expected: ${dsa65Sizes.publicKeySize})`);
console.log(`  Private key size: ${dsaKeypair65.privateKeyBytes.length} bytes (expected: ${dsa65Sizes.privateKeySize})`);

const message65 = Buffer.from('Hello, post-quantum world! This message is signed with ML-DSA-65.', 'utf8');
const signature65 = MlDsa65Crypto.sign(message65, dsaKeypair65.privateKeyBytes);
console.log('✓ Signed message with ML-DSA-65');
console.log(`  Message: "${message65.toString('utf8')}"`);
console.log(`  Signature size: ${signature65.length} bytes (max: ${dsa65Sizes.maxSignatureSize})`);

const isValid65 = MlDsa65Crypto.verify(message65, signature65, dsaKeypair65.publicKeyBytes);
console.log(`  Signature verification: ${isValid65 ? '✓' : '✗'}`);

// ML-DSA-87 (NIST Level 5) - Highest security, largest keys
console.log('\n2.3. ML-DSA-87 (NIST Level 5):');
const dsaKeypair87 = MlDsa87Crypto.generateKeypair();
const dsa87Sizes = MlDsa87Crypto.getSizes();
console.log('✓ Generated ML-DSA-87 key pair');
console.log(`  Public key size: ${dsaKeypair87.publicKeyBytes.length} bytes (expected: ${dsa87Sizes.publicKeySize})`);
console.log(`  Private key size: ${dsaKeypair87.privateKeyBytes.length} bytes (expected: ${dsa87Sizes.privateKeySize})`);

const message87 = Buffer.from('Hello, post-quantum world! This message is signed with ML-DSA-87.', 'utf8');
const signature87 = MlDsa87Crypto.sign(message87, dsaKeypair87.privateKeyBytes);
console.log('✓ Signed message with ML-DSA-87');
console.log(`  Message: "${message87.toString('utf8')}"`);
console.log(`  Signature size: ${signature87.length} bytes (max: ${dsa87Sizes.maxSignatureSize})`);

const isValid87 = MlDsa87Crypto.verify(message87, signature87, dsaKeypair87.publicKeyBytes);
console.log(`  Signature verification: ${isValid87 ? '✓' : '✗'}`);

console.log();

// Example 3: Hybrid Encryption - Combining ML-KEM with AES
console.log('3. Hybrid Encryption (ML-KEM-768 + AES)');
console.log('=======================================');

// Alice generates ML-KEM-768 key pair
const aliceKemKeypair = MlKem768Crypto.generateKeypair();
console.log('✓ Alice generated ML-KEM-768 key pair');

// Bob wants to send an encrypted message to Alice
const secretMessage = Buffer.from('This is a confidential message that needs post-quantum protection!', 'utf8');
console.log(`📝 Bob's secret message: "${secretMessage.toString('utf8')}"`);

// Bob encapsulates a shared secret using Alice's public key
const bobEncapsulation = MlKem768Crypto.encapsulate(aliceKemKeypair.publicKeyBytes);
console.log('✓ Bob encapsulated shared secret using Alice\'s public key');

// Bob uses the shared secret as AES key to encrypt the message
const encryptedMessage = SymmetricCrypto.encryptAes(secretMessage, bobEncapsulation.sharedSecret);
console.log('✓ Bob encrypted message using AES with the shared secret');
console.log(`  Encrypted message size: ${encryptedMessage.length} bytes`);

// Bob sends: ML-KEM ciphertext + AES encrypted message
console.log('📤 Bob sends: ML-KEM ciphertext + AES encrypted message');

// Alice decapsulates the shared secret using her private key
const aliceSharedSecret = MlKem768Crypto.decapsulate(
  bobEncapsulation.ciphertext,
  aliceKemKeypair.privateKeyBytes
);
console.log('✓ Alice decapsulated shared secret using her private key');

// Alice uses the shared secret to decrypt the message
const decryptedMessage = SymmetricCrypto.decryptAes(encryptedMessage, aliceSharedSecret);
console.log('✓ Alice decrypted message using AES with the shared secret');
console.log(`📖 Alice's decrypted message: "${decryptedMessage.toString('utf8')}"`);
console.log(`  Messages match: ${secretMessage.equals(decryptedMessage) ? '✓' : '✗'}`);

console.log();

// Example 4: Post-Quantum Digital Signatures with Message Integrity
console.log('4. Post-Quantum Signatures + Message Integrity (ML-DSA-65)');
console.log('===========================================================');

// Document to be signed and verified
const document = Buffer.from('Important contract that requires post-quantum digital signature', 'utf8');
console.log(`📄 Document: "${document.toString('utf8')}"`);

// Generate ML-DSA-65 key pair for signing
const signerKeypair = MlDsa65Crypto.generateKeypair();
console.log('✓ Generated ML-DSA-65 key pair for signing');

// Hash the document first (best practice)
const documentHash = HashFunctions.sha256(document);
console.log('✓ Computed SHA-256 hash of document');
console.log(`  Document hash: ${documentHash.toString('hex')}`);

// Sign the hash
const documentSignature = MlDsa65Crypto.sign(documentHash, signerKeypair.privateKeyBytes);
console.log('✓ Signed document hash with ML-DSA-65');
console.log(`  Signature size: ${documentSignature.length} bytes`);

// Verify the signature
const isDocumentValid = MlDsa65Crypto.verify(documentHash, documentSignature, signerKeypair.publicKeyBytes);
console.log(`  Signature verification: ${isDocumentValid ? '✓' : '✗'}`);

// Test tampering detection
const tamperedDocument = Buffer.from('Important contract that requires post-quantum digital signature [TAMPERED]', 'utf8');
const tamperedHash = HashFunctions.sha256(tamperedDocument);
const isTamperedValid = MlDsa65Crypto.verify(tamperedHash, documentSignature, signerKeypair.publicKeyBytes);
console.log(`  Tampered document verification: ${!isTamperedValid ? '✓' : '✗'} (should fail)`);

console.log();

// Example 5: Key Size Comparison with Constants
console.log('5. Post-Quantum Key Size Comparison');
console.log('===================================');

console.log('ML-KEM Key Sizes:');
console.log(`  ML-KEM-512:  Public=${kemKeypair512.publicKeyBytes.length} bytes (${kem512Sizes.publicKeySize}), Private=${kemKeypair512.privateKeyBytes.length} bytes (${kem512Sizes.privateKeySize})`);
console.log(`  ML-KEM-768:  Public=${kemKeypair768.publicKeyBytes.length} bytes (${kem768Sizes.publicKeySize}), Private=${kemKeypair768.privateKeyBytes.length} bytes (${kem768Sizes.privateKeySize})`);
console.log(`  ML-KEM-1024: Public=${kemKeypair1024.publicKeyBytes.length} bytes (${kem1024Sizes.publicKeySize}), Private=${kemKeypair1024.privateKeyBytes.length} bytes (${kem1024Sizes.privateKeySize})`);

console.log('\nML-DSA Key Sizes:');
console.log(`  ML-DSA-44: Public=${dsaKeypair44.publicKeyBytes.length} bytes (${dsa44Sizes.publicKeySize}), Private=${dsaKeypair44.privateKeyBytes.length} bytes (${dsa44Sizes.privateKeySize})`);
console.log(`  ML-DSA-65: Public=${dsaKeypair65.publicKeyBytes.length} bytes (${dsa65Sizes.publicKeySize}), Private=${dsaKeypair65.privateKeyBytes.length} bytes (${dsa65Sizes.privateKeySize})`);
console.log(`  ML-DSA-87: Public=${dsaKeypair87.publicKeyBytes.length} bytes (${dsa87Sizes.publicKeySize}), Private=${dsaKeypair87.privateKeyBytes.length} bytes (${dsa87Sizes.privateKeySize})`);

console.log('\nSignature Sizes:');
console.log(`  ML-DSA-44: ${signature44.length} bytes (max: ${dsa44Sizes.maxSignatureSize})`);
console.log(`  ML-DSA-65: ${signature65.length} bytes (max: ${dsa65Sizes.maxSignatureSize})`);
console.log(`  ML-DSA-87: ${signature87.length} bytes (max: ${dsa87Sizes.maxSignatureSize})`);

console.log('\nCiphertext Sizes:');
console.log(`  ML-KEM-512:  ${kemEncapsulation512.ciphertext.length} bytes (${kem512Sizes.ciphertextSize})`);
console.log(`  ML-KEM-768:  ${kemEncapsulation768.ciphertext.length} bytes (${kem768Sizes.ciphertextSize})`);
console.log(`  ML-KEM-1024: ${kemEncapsulation1024.ciphertext.length} bytes (${kem1024Sizes.ciphertextSize})`);

console.log('\n🎉 All post-quantum cryptography examples completed successfully!');
console.log('\n💡 Key Takeaways:');
console.log('   • ML-KEM provides quantum-resistant key encapsulation');
console.log('   • ML-DSA provides quantum-resistant digital signatures');
console.log('   • Higher security levels = larger keys and signatures');
console.log('   • ML-KEM-768 and ML-DSA-65 are recommended defaults');
console.log('   • Hybrid encryption combines ML-KEM with symmetric ciphers');
console.log('   • Always hash documents before signing for better security');
console.log('   • Size constants help with buffer pre-allocation');
console.log('   • Standalone variants provide direct function calls');
