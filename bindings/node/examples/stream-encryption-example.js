#!/usr/bin/env node

/**
 * StreamEncryption Example
 * 
 * This example demonstrates how to use the StreamEncryption class for
 * stateful encryption/decryption with automatic nonce management.
 */

const { StreamEncryption } = require('../index.js');

console.log('🔐 LibSilver StreamEncryption Example\n');

// Example 1: Basic Stream Encryption
console.log('1. Basic Stream Encryption');
console.log('==========================');

// Generate a key for stream encryption
const key = StreamEncryption.generateKey();
console.log('Generated key:', key.toString('hex'));

// Create a stream cipher instance
const cipher = new StreamEncryption(key);
console.log('Created StreamEncryption instance');

// Encrypt multiple chunks of data
const chunks = [
    'This is the first chunk of data to encrypt.',
    'Here comes the second chunk with different content.',
    'And finally, the third chunk to complete our example.'
];

console.log('\nEncrypting chunks:');
const encryptedChunks = [];
for (let i = 0; i < chunks.length; i++) {
    const plaintext = Buffer.from(chunks[i], 'utf8');
    const ciphertext = cipher.encryptChunk(plaintext);
    encryptedChunks.push(ciphertext);
    
    console.log(`Chunk ${i + 1}:`);
    console.log(`  Plaintext:  "${chunks[i]}"`);
    console.log(`  Ciphertext: ${ciphertext.toString('hex')}`);
    console.log(`  Size:       ${plaintext.length} -> ${ciphertext.length} bytes (+${ciphertext.length - plaintext.length} overhead)`);
}

console.log(`\nNonce counter after encryption: ${cipher.getNonceCounter()}`);

// Decrypt the chunks
console.log('\nDecrypting chunks:');
for (let i = 0; i < encryptedChunks.length; i++) {
    const decrypted = cipher.decryptChunk(encryptedChunks[i]);
    console.log(`Chunk ${i + 1} decrypted: "${decrypted.toString('utf8')}"`);
}

// Example 2: Stream Cipher Reset
console.log('\n\n2. Stream Cipher Reset');
console.log('======================');

console.log(`Nonce counter before reset: ${cipher.getNonceCounter()}`);
cipher.reset();
console.log(`Nonce counter after reset: ${cipher.getNonceCounter()}`);

// Encrypt new data after reset
const newData = Buffer.from('New data after reset', 'utf8');
const newCiphertext = cipher.encryptChunk(newData);
console.log(`New encryption after reset: ${newCiphertext.toString('hex')}`);
console.log(`Nonce counter after new encryption: ${cipher.getNonceCounter()}`);

// Example 3: Multiple Cipher Instances
console.log('\n\n3. Multiple Cipher Instances');
console.log('=============================');

// Create two different cipher instances with different keys
const key1 = StreamEncryption.generateKey();
const key2 = StreamEncryption.generateKey();

const cipher1 = new StreamEncryption(key1);
const cipher2 = new StreamEncryption(key2);

const testData = Buffer.from('Same data, different keys', 'utf8');

const encrypted1 = cipher1.encryptChunk(testData);
const encrypted2 = cipher2.encryptChunk(testData);

console.log('Same plaintext encrypted with different keys:');
console.log(`Cipher 1: ${encrypted1.toString('hex')}`);
console.log(`Cipher 2: ${encrypted2.toString('hex')}`);
console.log(`Results are different: ${!encrypted1.equals(encrypted2)}`);

// Each cipher can only decrypt its own data
const decrypted1 = cipher1.decryptChunk(encrypted1);
const decrypted2 = cipher2.decryptChunk(encrypted2);

console.log(`Cipher 1 decrypted: "${decrypted1.toString('utf8')}"`);
console.log(`Cipher 2 decrypted: "${decrypted2.toString('utf8')}"`);

// Example 4: Large Data Processing
console.log('\n\n4. Large Data Processing');
console.log('========================');

const largeKey = StreamEncryption.generateKey();
const largeCipher = new StreamEncryption(largeKey);

// Simulate processing large data in chunks
const chunkSize = 1024; // 1KB chunks
const totalSize = 5 * 1024; // 5KB total
const numChunks = Math.ceil(totalSize / chunkSize);

console.log(`Processing ${totalSize} bytes in ${numChunks} chunks of ${chunkSize} bytes each`);

const startTime = process.hrtime.bigint();
const largeEncrypted = [];

for (let i = 0; i < numChunks; i++) {
    const actualChunkSize = Math.min(chunkSize, totalSize - (i * chunkSize));
    const chunk = Buffer.alloc(actualChunkSize, `Chunk ${i + 1} `.repeat(Math.ceil(actualChunkSize / 10)));
    const encrypted = largeCipher.encryptChunk(chunk.slice(0, actualChunkSize));
    largeEncrypted.push(encrypted);
}

const encryptTime = process.hrtime.bigint();

// Decrypt all chunks
for (let i = 0; i < largeEncrypted.length; i++) {
    largeCipher.decryptChunk(largeEncrypted[i]);
}

const decryptTime = process.hrtime.bigint();

const encryptMs = Number(encryptTime - startTime) / 1000000;
const decryptMs = Number(decryptTime - encryptTime) / 1000000;

console.log(`Encryption time: ${encryptMs.toFixed(2)}ms`);
console.log(`Decryption time: ${decryptMs.toFixed(2)}ms`);
console.log(`Total time: ${(encryptMs + decryptMs).toFixed(2)}ms`);
console.log(`Final nonce counter: ${largeCipher.getNonceCounter()}`);

console.log('\n🎉 StreamEncryption example completed successfully!');
console.log('\n💡 Key takeaways:');
console.log('   • StreamEncryption provides stateful encryption with automatic nonce management');
console.log('   • Each instance maintains its own state and nonce counter');
console.log('   • Perfect for streaming data, large file processing, or real-time encryption');
console.log('   • Thread-safe and high-performance with AWS-LC-RS backend');
console.log('   • Use reset() when nonce counter approaches overflow or for new sessions');
