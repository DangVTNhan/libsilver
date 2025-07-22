#!/usr/bin/env node

/**
 * StreamEncryption Wrapper Class Test
 *
 * This test verifies that the StreamEncryption wrapper class works correctly
 * and provides the same functionality as the native StreamCipherJs class.
 */

const { StreamEncryption } = require('../index.js');
const assert = require('assert');

function runStreamEncryptionWrapperTests() {
    console.log('🧪 Running StreamEncryption Wrapper Tests...\n');

    // Store original process.exit to restore later
    const originalExit = process.exit;

    // Override process.exit to throw instead
    process.exit = (code) => {
        if (code !== 0) {
            throw new Error('Test failed');
        }
    };

    try {
        runAllWrapperTests();
    } finally {
        // Restore original process.exit
        process.exit = originalExit;
    }
}

function runAllWrapperTests() {

// Test 1: StreamEncryption Class Creation
console.log('📝 Test 1: StreamEncryption Class Creation');
try {
    const key = StreamEncryption.generateKey();
    assert(key instanceof Buffer, 'Generated key should be a Buffer');
    assert(key.length === 32, 'Generated key should be 32 bytes');
    
    const cipher = new StreamEncryption(key);
    assert(cipher instanceof StreamEncryption, 'Should create StreamEncryption instance');
    
    console.log('✅ StreamEncryption class creation test passed\n');
} catch (error) {
    console.error('❌ StreamEncryption class creation test failed:', error.message);
    process.exit(1);
}

// Test 2: Basic Encryption/Decryption with Wrapper
console.log('📝 Test 2: Basic Encryption/Decryption with Wrapper');
try {
    const key = StreamEncryption.generateKey();
    const cipher = new StreamEncryption(key);
    
    const plaintext = Buffer.from('Hello, StreamEncryption Wrapper!', 'utf8');
    const ciphertext = cipher.encryptChunk(plaintext);
    
    assert(ciphertext instanceof Buffer, 'Ciphertext should be a Buffer');
    assert(ciphertext.length > plaintext.length, 'Ciphertext should be longer than plaintext');
    assert(ciphertext.length === plaintext.length + 28, 'Ciphertext should be plaintext + 28 bytes (12 nonce + 16 tag)');
    
    const decrypted = cipher.decryptChunk(ciphertext);
    assert(Buffer.compare(plaintext, decrypted) === 0, 'Decrypted text should match original plaintext');
    
    console.log('✅ Basic encryption/decryption with wrapper test passed\n');
} catch (error) {
    console.error('❌ Basic encryption/decryption with wrapper test failed:', error.message);
    process.exit(1);
}

// Test 3: Multiple Chunks with Wrapper
console.log('📝 Test 3: Multiple Chunks with Wrapper');
try {
    const key = StreamEncryption.generateKey();
    const cipher = new StreamEncryption(key);
    
    const chunks = [
        Buffer.from('First chunk', 'utf8'),
        Buffer.from('Second chunk', 'utf8'),
        Buffer.from('Third chunk', 'utf8')
    ];
    
    // Encrypt all chunks
    const encrypted = chunks.map(chunk => cipher.encryptChunk(chunk));
    
    // Verify all ciphertexts are different
    assert(Buffer.compare(encrypted[0], encrypted[1]) !== 0, 'Encrypted chunks should be different');
    assert(Buffer.compare(encrypted[1], encrypted[2]) !== 0, 'Encrypted chunks should be different');
    assert(Buffer.compare(encrypted[0], encrypted[2]) !== 0, 'Encrypted chunks should be different');
    
    // Decrypt all chunks
    const decrypted = encrypted.map(ciphertext => cipher.decryptChunk(ciphertext));
    
    // Verify decryption
    for (let i = 0; i < chunks.length; i++) {
        assert(Buffer.compare(chunks[i], decrypted[i]) === 0, `Decrypted chunk ${i + 1} should match original`);
    }
    
    console.log('✅ Multiple chunks with wrapper test passed\n');
} catch (error) {
    console.error('❌ Multiple chunks with wrapper test failed:', error.message);
    process.exit(1);
}

// Test 4: Nonce Counter with Wrapper
console.log('📝 Test 4: Nonce Counter with Wrapper');
try {
    const key = StreamEncryption.generateKey();
    const cipher = new StreamEncryption(key);
    
    assert(cipher.getNonceCounter() === 0, 'Initial nonce counter should be 0');
    
    cipher.encryptChunk(Buffer.from('test1', 'utf8'));
    assert(cipher.getNonceCounter() === 1, 'Nonce counter should be 1 after one encryption');
    
    cipher.encryptChunk(Buffer.from('test2', 'utf8'));
    cipher.encryptChunk(Buffer.from('test3', 'utf8'));
    assert(cipher.getNonceCounter() === 3, 'Nonce counter should be 3 after three encryptions');
    
    console.log('✅ Nonce counter with wrapper test passed\n');
} catch (error) {
    console.error('❌ Nonce counter with wrapper test failed:', error.message);
    process.exit(1);
}

// Test 5: Reset Functionality with Wrapper
console.log('📝 Test 5: Reset Functionality with Wrapper');
try {
    const key = StreamEncryption.generateKey();
    const cipher = new StreamEncryption(key);
    
    // Encrypt some data to increment counter
    cipher.encryptChunk(Buffer.from('test1', 'utf8'));
    cipher.encryptChunk(Buffer.from('test2', 'utf8'));
    assert(cipher.getNonceCounter() === 2, 'Counter should be 2 before reset');
    
    // Reset the cipher
    cipher.reset();
    assert(cipher.getNonceCounter() === 0, 'Counter should be 0 after reset');
    
    // Verify it still works after reset
    const plaintext = Buffer.from('After reset', 'utf8');
    const ciphertext = cipher.encryptChunk(plaintext);
    const decrypted = cipher.decryptChunk(ciphertext);
    assert(Buffer.compare(plaintext, decrypted) === 0, 'Should still work after reset');
    
    console.log('✅ Reset functionality with wrapper test passed\n');
} catch (error) {
    console.error('❌ Reset functionality with wrapper test failed:', error.message);
    process.exit(1);
}

console.log('🎉 All StreamEncryption Wrapper tests passed successfully!');
console.log('📊 Total tests: 5');
console.log('✅ Passed: 5');
console.log('❌ Failed: 0');
}

// Run tests if this file is executed directly
if (require.main === module) {
    runStreamEncryptionWrapperTests();
}

module.exports = {
    runStreamEncryptionWrapperTests
};
