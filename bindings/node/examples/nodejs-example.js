const { SymmetricCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator } = require('../index.js');

console.log('🔐 LibSilver Node.js Examples\n');

// Example 1: Symmetric Encryption with AES-256-GCM
console.log('1. Symmetric Encryption (AES-256-GCM)');
console.log('=====================================');

const aesKey = SymmetricCrypto.generateAesKey();
console.log('Generated AES key:', aesKey.toString('hex'));

const message = 'This is a secret message!';
const plaintext = Buffer.from(message, 'utf8');

const ciphertext = SymmetricCrypto.encryptAes(plaintext, aesKey);
console.log('Encrypted:', ciphertext.toString('hex'));

const decrypted = SymmetricCrypto.decryptAes(ciphertext, aesKey);
console.log('Decrypted:', decrypted.toString('utf8'));
console.log('Match:', message === decrypted.toString('utf8') ? '✓' : '✗');
console.log();

// Example 2: Digital Signatures with Ed25519
console.log('2. Digital Signatures (Ed25519)');
console.log('================================');

const ed25519Keypair = AsymmetricCrypto.generateEd25519Keypair();
console.log('Signing key:', ed25519Keypair.signingKeyBytes.toString('hex'));
console.log('Verifying key:', ed25519Keypair.verifyingKeyBytes.toString('hex'));

const messageToSign = Buffer.from('Important document to sign', 'utf8');
const signature = AsymmetricCrypto.signEd25519(messageToSign, ed25519Keypair.signingKeyBytes);
console.log('Signature:', signature.toString('hex'));

const isValid = AsymmetricCrypto.verifyEd25519(messageToSign, signature, ed25519Keypair.verifyingKeyBytes);
console.log('Signature valid:', isValid ? '✓' : '✗');
console.log();

// Example 3: RSA Encryption
console.log('3. RSA Encryption (RSA-OAEP)');
console.log('=============================');

const rsaKeypair = AsymmetricCrypto.generateRsaKeypair();
console.log('RSA Public Key (PEM):');
console.log(rsaKeypair.publicKeyPem);

const rsaMessage = Buffer.from('RSA encrypted message', 'utf8');
const rsaCiphertext = AsymmetricCrypto.encryptRsa(rsaMessage, rsaKeypair.publicKeyPem);
console.log('RSA Encrypted:', rsaCiphertext.toString('hex'));

const rsaDecrypted = AsymmetricCrypto.decryptRsa(rsaCiphertext, rsaKeypair.privateKeyPem);
console.log('RSA Decrypted:', rsaDecrypted.toString('utf8'));
console.log('Match:', rsaMessage.equals(rsaDecrypted) ? '✓' : '✗');
console.log();

// Example 4: Cryptographic Hashing
console.log('4. Cryptographic Hashing');
console.log('========================');

const dataToHash = Buffer.from('Data to be hashed', 'utf8');

const sha256Hash = HashFunctions.sha256(dataToHash);
console.log('SHA-256:', sha256Hash.toString('hex'));

const sha256Hex = HashFunctions.sha256Hex(dataToHash);
console.log('SHA-256 (hex):', sha256Hex);

const blake3Hash = HashFunctions.blake3(dataToHash);
console.log('BLAKE3:', blake3Hash.toString('hex'));

const blake3Custom = HashFunctions.blake3WithLength(dataToHash, 64);
console.log('BLAKE3 (64 bytes):', blake3Custom.toString('hex'));
console.log();

// Example 5: HMAC
console.log('5. HMAC (Hash-based Message Authentication Code)');
console.log('=================================================');

const hmacKey = RandomGenerator.generateBytes(32);
const hmacMessage = Buffer.from('Message to authenticate', 'utf8');

const hmac = HashFunctions.hmacSha256(hmacKey, hmacMessage);
console.log('HMAC-SHA256:', hmac.toString('hex'));

const hmacValid = HashFunctions.verifyHmacSha256(hmacKey, hmacMessage, hmac);
console.log('HMAC valid:', hmacValid ? '✓' : '✗');
console.log();

// Example 6: Key Derivation Functions
console.log('6. Key Derivation Functions');
console.log('===========================');

const password = Buffer.from('user_password_123', 'utf8');
const salt = RandomGenerator.generateSalt();
console.log('Salt:', salt.toString('hex'));

// Argon2 (recommended for password hashing)
const argon2Key = KeyDerivation.argon2(password, salt, 32);
console.log('Argon2 derived key:', argon2Key.toString('hex'));

// PBKDF2
const pbkdf2Key = KeyDerivation.pbkdf2Sha256(password, salt, 100000, 32);
console.log('PBKDF2 derived key:', pbkdf2Key.toString('hex'));

// HKDF (for key expansion)
const masterKey = RandomGenerator.generateBytes(32);
const info = Buffer.from('application-specific-info', 'utf8');
const hkdfKey = KeyDerivation.hkdfSha256(masterKey, salt, info, 32);
console.log('HKDF derived key:', hkdfKey.toString('hex'));
console.log();

// Example 7: Secure Random Generation
console.log('7. Secure Random Generation');
console.log('===========================');

const randomBytes = RandomGenerator.generateBytes(16);
console.log('Random bytes (16):', randomBytes.toString('hex'));

const secureKey = RandomGenerator.generateKey(32);
console.log('Secure key (32):', secureKey.toString('hex'));

const nonce = RandomGenerator.generateNonce(12);
console.log('Nonce (12):', nonce.toString('hex'));

const newSalt = RandomGenerator.generateSalt();
console.log('Salt (32):', newSalt.toString('hex'));
console.log();

// Example 8: Complete Workflow - Secure Message Exchange
console.log('8. Complete Workflow - Secure Message Exchange');
console.log('===============================================');

// Alice generates a key pair
const aliceKeypair = AsymmetricCrypto.generateEd25519Keypair();
console.log('Alice\'s public key:', aliceKeypair.verifyingKeyBytes.toString('hex'));

// Bob generates a symmetric key and encrypts a message
const bobSymmetricKey = SymmetricCrypto.generateAesKey();
const secretMessage = Buffer.from('Meet me at the secret location at midnight', 'utf8');
const encryptedMessage = SymmetricCrypto.encryptAes(secretMessage, bobSymmetricKey);

// Bob signs the encrypted message
const messageSignature = AsymmetricCrypto.signEd25519(encryptedMessage, aliceKeypair.signingKeyBytes);

console.log('Encrypted message:', encryptedMessage.toString('hex'));
console.log('Message signature:', messageSignature.toString('hex'));

// Alice verifies the signature and decrypts the message
const signatureValid = AsymmetricCrypto.verifyEd25519(encryptedMessage, messageSignature, aliceKeypair.verifyingKeyBytes);
console.log('Signature verification:', signatureValid ? '✓' : '✗');

if (signatureValid) {
  const decryptedMessage = SymmetricCrypto.decryptAes(encryptedMessage, bobSymmetricKey);
  console.log('Decrypted message:', decryptedMessage.toString('utf8'));
}

console.log('\n🎉 All examples completed successfully!');
