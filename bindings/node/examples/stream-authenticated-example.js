const { StreamEncryption } = require('../index.js');

console.log('=== LibSilver Node.js Stream Cipher Authenticated Encryption Example ===\n');

// Generate a secure key for AES-256-GCM
const key = StreamEncryption.generateKey();
console.log(`Generated 256-bit key: ${key.length} bytes`);

// Create a new stream cipher instance
const cipher = new StreamEncryption(key);
console.log('Stream cipher initialized successfully\n');

// Example 1: Basic authenticated encryption without AAD
console.log('--- Example 1: Basic Authenticated Encryption ---');
const message1 = Buffer.from('Hello, authenticated world!', 'utf8');
console.log(`Original message: "${message1.toString('utf8')}"`);

// Encrypt with separate tag (using regular method for comparison)
const ciphertext1 = cipher.encryptChunk(message1);
console.log(`Regular ciphertext length: ${ciphertext1.length} bytes`);

// Decrypt using regular method
const decrypted1 = cipher.decryptChunk(ciphertext1);
console.log(`Decrypted message: "${decrypted1.toString('utf8')}"\n`);

// Example 2: Authenticated encryption with Additional Authenticated Data (AAD)
console.log('--- Example 2: Authenticated Encryption with AAD ---');
const message2 = Buffer.from('Sensitive financial data', 'utf8');
const aad = Buffer.from('user_id:12345,timestamp:2024-01-15T10:30:00Z', 'utf8');
console.log(`Message: "${message2.toString('utf8')}"`);
console.log(`AAD: "${aad.toString('utf8')}"`);

// Encrypt with AAD
const ciphertext2 = cipher.encryptChunkWithAad(message2, aad);
console.log(`Encrypted with AAD - total ciphertext: ${ciphertext2.length} bytes (includes nonce + ciphertext + tag)`);

// Decrypt with AAD
const decrypted2 = cipher.decryptChunkWithAad(ciphertext2, aad);
console.log(`Decrypted message: "${decrypted2.toString('utf8')}"\n`);

// Example 3: Multiple chunks with different AAD
console.log('--- Example 3: Multiple Chunks with Different AAD ---');
const chunks = [
    { data: Buffer.from('Chunk 1 data', 'utf8'), aad: Buffer.from('metadata:chunk1', 'utf8') },
    { data: Buffer.from('Chunk 2 data', 'utf8'), aad: Buffer.from('metadata:chunk2', 'utf8') },
    { data: Buffer.from('Chunk 3 data', 'utf8'), aad: Buffer.from('metadata:chunk3', 'utf8') },
];

const encryptedChunks = [];

// Encrypt multiple chunks
for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const ciphertext = cipher.encryptChunkWithAad(chunk.data, chunk.aad);
    encryptedChunks.push({ ciphertext, aad: chunk.aad });
    console.log(`Encrypted chunk ${i + 1}: ${chunk.data.length} bytes -> ${ciphertext.length} bytes total`);
}

// Decrypt multiple chunks
console.log('\nDecrypting chunks:');
for (let i = 0; i < encryptedChunks.length; i++) {
    const encrypted = encryptedChunks[i];
    const decrypted = cipher.decryptChunkWithAad(encrypted.ciphertext, encrypted.aad);
    console.log(`Decrypted chunk ${i + 1}: "${decrypted.toString('utf8')}"`);
}

// Example 4: Demonstrating authentication failure
console.log('\n--- Example 4: Authentication Failure Detection ---');
const message4 = Buffer.from('Important message', 'utf8');
const correctAad = Buffer.from('correct_metadata', 'utf8');
const wrongAad = Buffer.from('wrong_metadata', 'utf8');

const ciphertext4 = cipher.encryptChunkWithAad(message4, correctAad);
console.log('Encrypted message with correct AAD');

// Try to decrypt with wrong AAD (should fail)
try {
    cipher.decryptChunkWithAad(ciphertext4, wrongAad);
    console.log('ERROR: Decryption should have failed!');
} catch (error) {
    console.log(`✓ Authentication correctly failed: ${error.message}`);
}

// Try with tampered ciphertext (should fail)
const tamperedCiphertext = Buffer.from(ciphertext4);
if (tamperedCiphertext.length > 12) {
    tamperedCiphertext[12] ^= 0x01; // Flip one bit in the actual ciphertext part
}

try {
    cipher.decryptChunkWithAad(tamperedCiphertext, correctAad);
    console.log('ERROR: Decryption should have failed!');
} catch (error) {
    console.log(`✓ Tampering correctly detected: ${error.message}`);
}

// Example 5: Empty data with AAD
console.log('\n--- Example 5: Empty Data with AAD ---');
const emptyData = Buffer.alloc(0);
const metadata = Buffer.from('empty_file_metadata', 'utf8');

const ciphertext5 = cipher.encryptChunkWithAad(emptyData, metadata);
console.log(`Encrypted empty data - total ciphertext: ${ciphertext5.length} bytes (nonce + tag only)`);

const decrypted5 = cipher.decryptChunkWithAad(ciphertext5, metadata);
console.log(`Decrypted empty data: ${decrypted5.length} bytes`);

// Example 6: Nonce counter management
console.log('\n--- Example 6: Nonce Counter Management ---');
const counterCipher = new StreamEncryption(StreamEncryption.generateKey());
console.log(`Initial nonce counter: ${counterCipher.getNonceCounter()}`);

const testData = Buffer.from('test data', 'utf8');
const testAad = Buffer.from('test metadata', 'utf8');

// Regular encryption
counterCipher.encryptChunk(testData);
console.log(`After regular encryption: ${counterCipher.getNonceCounter()}`);

// AAD encryption
counterCipher.encryptChunkWithAad(testData, testAad);
console.log(`After AAD encryption: ${counterCipher.getNonceCounter()}`);

// Reset counter
counterCipher.reset();
console.log(`After reset: ${counterCipher.getNonceCounter()}`);

// Example 7: Large data handling
console.log('\n--- Example 7: Large Data Handling ---');
const largeData = Buffer.alloc(1024 * 100, 0x42); // 100KB of data
const largeAad = Buffer.from('large_file_metadata', 'utf8');

console.log(`Original data size: ${largeData.length} bytes`);

const start = Date.now();
const largeCiphertext = cipher.encryptChunkWithAad(largeData, largeAad);
const encryptTime = Date.now() - start;

console.log(`Encrypted in ${encryptTime}ms, ciphertext size: ${largeCiphertext.length} bytes`);

const decryptStart = Date.now();
const largeDecrypted = cipher.decryptChunkWithAad(largeCiphertext, largeAad);
const decryptTime = Date.now() - decryptStart;

console.log(`Decrypted in ${decryptTime}ms, verified data integrity: ${Buffer.compare(largeDecrypted, largeData) === 0 ? 'PASS' : 'FAIL'}`);

console.log('\n=== All examples completed successfully! ===');
