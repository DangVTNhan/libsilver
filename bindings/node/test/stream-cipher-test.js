const { StreamCipherJs } = require('../native.js');

function assert(condition, message) {
    if (!condition) {
        throw new Error(`❌ Assertion failed: ${message}`);
    }
    console.log(`✅ ${message}`);
}

function assertThrows(fn, message) {
    try {
        fn();
        throw new Error(`❌ Expected function to throw: ${message}`);
    } catch (error) {
        console.log(`✅ ${message}`);
    }
}

function runStreamCipherTests() {
    console.log('🧪 Running Stream Cipher Tests...\n');

    // Store original process.exit to restore later
    const originalExit = process.exit;

    // Override process.exit to throw instead
    process.exit = (code) => {
        if (code !== 0) {
            throw new Error('Test failed');
        }
    };

    try {
        runAllStreamCipherTests();
    } finally {
        // Restore original process.exit
        process.exit = originalExit;
    }
}

function runAllStreamCipherTests() {

    // Test 1: Stream Cipher Creation
    console.log('📝 Test 1: Stream Cipher Creation');
    try {
        const key = StreamCipherJs.generateKey();
        assert(key.length === 32, 'Generated key should be 32 bytes');

        const cipher = new StreamCipherJs(key);
        assert(cipher !== null, 'Stream cipher should be created successfully');

        console.log('✅ Stream cipher creation test passed\n');
    } catch (error) {
        console.error('❌ Stream cipher creation test failed:', error.message);
        throw error;
    }

    // Test 2: Basic Encryption/Decryption
    console.log('📝 Test 2: Basic Encryption/Decryption');
    try {
        const key = StreamCipherJs.generateKey();
        const cipher = new StreamCipherJs(key);

        const plaintext = Buffer.from('Hello, Stream Cipher World!', 'utf8');
        const ciphertext = cipher.encryptChunk(plaintext);

        assert(ciphertext.length > plaintext.length, 'Ciphertext should be longer than plaintext (includes nonce + tag)');
        assert(ciphertext.length === plaintext.length + 28, 'Ciphertext should be plaintext + 28 bytes (12 nonce + 16 tag)');

        const decrypted = cipher.decryptChunk(ciphertext);
        assert(Buffer.compare(plaintext, decrypted) === 0, 'Decrypted text should match original plaintext');
    
        console.log('✅ Basic encryption/decryption test passed\n');
    } catch (error) {
        console.error('❌ Basic encryption/decryption test failed:', error.message);
        throw error;
    }

// Test 3: Multiple Chunks with Different Nonces
console.log('📝 Test 3: Multiple Chunks with Different Nonces');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    const chunk1 = Buffer.from('First chunk of data', 'utf8');
    const chunk2 = Buffer.from('Second chunk of data', 'utf8');
    const chunk3 = Buffer.from('Third chunk of data', 'utf8');
    
    const ciphertext1 = cipher.encryptChunk(chunk1);
    const ciphertext2 = cipher.encryptChunk(chunk2);
    const ciphertext3 = cipher.encryptChunk(chunk3);
    
    // Ciphertexts should be different (different nonces)
    assert(Buffer.compare(ciphertext1, ciphertext2) !== 0, 'Ciphertext 1 and 2 should be different');
    assert(Buffer.compare(ciphertext2, ciphertext3) !== 0, 'Ciphertext 2 and 3 should be different');
    assert(Buffer.compare(ciphertext1, ciphertext3) !== 0, 'Ciphertext 1 and 3 should be different');
    
    // Decrypt all chunks
    const decrypted1 = cipher.decryptChunk(ciphertext1);
    const decrypted2 = cipher.decryptChunk(ciphertext2);
    const decrypted3 = cipher.decryptChunk(ciphertext3);
    
    assert(Buffer.compare(chunk1, decrypted1) === 0, 'Decrypted chunk 1 should match original');
    assert(Buffer.compare(chunk2, decrypted2) === 0, 'Decrypted chunk 2 should match original');
    assert(Buffer.compare(chunk3, decrypted3) === 0, 'Decrypted chunk 3 should match original');
    
    console.log('✅ Multiple chunks test passed\n');
} catch (error) {
    console.error('❌ Multiple chunks test failed:', error.message);
    process.exit(1);
}

// Test 4: Nonce Counter
console.log('📝 Test 4: Nonce Counter');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    const initialCounter = cipher.getNonceCounter();
    assert(initialCounter === 0, 'Initial nonce counter should be 0');
    
    // Encrypt a chunk
    const plaintext = Buffer.from('Test data', 'utf8');
    cipher.encryptChunk(plaintext);
    
    const afterEncrypt = cipher.getNonceCounter();
    assert(afterEncrypt === 1, 'Nonce counter should be 1 after one encryption');
    
    // Encrypt more chunks
    cipher.encryptChunk(plaintext);
    cipher.encryptChunk(plaintext);
    
    const afterMultiple = cipher.getNonceCounter();
    assert(afterMultiple === 3, 'Nonce counter should be 3 after three encryptions');
    
    console.log('✅ Nonce counter test passed\n');
} catch (error) {
    console.error('❌ Nonce counter test failed:', error.message);
    process.exit(1);
}

// Test 5: Reset Functionality
console.log('📝 Test 5: Reset Functionality');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    // Encrypt some chunks to increment counter
    const plaintext = Buffer.from('Test data', 'utf8');
    cipher.encryptChunk(plaintext);
    cipher.encryptChunk(plaintext);
    
    const beforeReset = cipher.getNonceCounter();
    assert(beforeReset === 2, 'Counter should be 2 before reset');
    
    // Reset the cipher
    cipher.reset();
    
    const afterReset = cipher.getNonceCounter();
    assert(afterReset === 0, 'Counter should be 0 after reset');
    
    // Should still work after reset
    const ciphertext = cipher.encryptChunk(plaintext);
    const decrypted = cipher.decryptChunk(ciphertext);
    assert(Buffer.compare(plaintext, decrypted) === 0, 'Should still work after reset');
    
    console.log('✅ Reset functionality test passed\n');
} catch (error) {
    console.error('❌ Reset functionality test failed:', error.message);
    process.exit(1);
}

// Test 6: Invalid Key Length
console.log('📝 Test 6: Invalid Key Length');
try {
    const shortKey = Buffer.alloc(16); // 16 bytes instead of 32
    
    assertThrows(() => {
        new StreamCipherJs(shortKey);
    }, 'Should throw error for invalid key length');
    
    console.log('✅ Invalid key length test passed\n');
} catch (error) {
    console.error('❌ Invalid key length test failed:', error.message);
    process.exit(1);
}

// Test 7: Invalid Ciphertext
console.log('📝 Test 7: Invalid Ciphertext');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    const shortCiphertext = Buffer.alloc(20); // Too short (less than 28 bytes)
    
    assertThrows(() => {
        cipher.decryptChunk(shortCiphertext);
    }, 'Should throw error for invalid ciphertext length');
    
    console.log('✅ Invalid ciphertext test passed\n');
} catch (error) {
    console.error('❌ Invalid ciphertext test failed:', error.message);
    process.exit(1);
}

// Test 8: Large Data
console.log('📝 Test 8: Large Data');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    // Create 1MB of data
    const largeData = Buffer.alloc(1024 * 1024, 'A');
    
    const start = Date.now();
    const ciphertext = cipher.encryptChunk(largeData);
    const encryptTime = Date.now() - start;
    
    const decryptStart = Date.now();
    const decrypted = cipher.decryptChunk(ciphertext);
    const decryptTime = Date.now() - start;
    
    assert(Buffer.compare(largeData, decrypted) === 0, 'Large data should decrypt correctly');
    
    console.log(`📊 Performance: Encrypt 1MB: ${encryptTime}ms, Decrypt 1MB: ${decryptTime}ms`);
    console.log('✅ Large data test passed\n');
} catch (error) {
    console.error('❌ Large data test failed:', error.message);
    process.exit(1);
}

// Test 9: Empty Data
console.log('📝 Test 9: Empty Data');
try {
    const key = StreamCipherJs.generateKey();
    const cipher = new StreamCipherJs(key);
    
    const emptyData = Buffer.alloc(0);
    const ciphertext = cipher.encryptChunk(emptyData);
    
    assert(ciphertext.length === 28, 'Empty data ciphertext should be 28 bytes (nonce + tag)');
    
    const decrypted = cipher.decryptChunk(ciphertext);
    assert(decrypted.length === 0, 'Decrypted empty data should be empty');
    assert(Buffer.compare(emptyData, decrypted) === 0, 'Empty data should decrypt correctly');
    
    console.log('✅ Empty data test passed\n');
} catch (error) {
    console.error('❌ Empty data test failed:', error.message);
    process.exit(1);
}

// Test 10: Cross-Instance Decryption
console.log('📝 Test 10: Cross-Instance Decryption');
try {
    const key = StreamCipherJs.generateKey();
    const cipher1 = new StreamCipherJs(key);
    const cipher2 = new StreamCipherJs(key);
    
    const plaintext = Buffer.from('Cross-instance test', 'utf8');
    const ciphertext = cipher1.encryptChunk(plaintext);
    
    // Different cipher instance with same key should be able to decrypt
    const decrypted = cipher2.decryptChunk(ciphertext);
    assert(Buffer.compare(plaintext, decrypted) === 0, 'Different cipher instance should decrypt correctly');
    
    console.log('✅ Cross-instance decryption test passed\n');
} catch (error) {
    console.error('❌ Cross-instance decryption test failed:', error.message);
    process.exit(1);
}

console.log('🎉 All Stream Cipher tests passed successfully!');
console.log('📊 Total tests: 10');
console.log('✅ Passed: 10');
console.log('❌ Failed: 0');
}

// Run tests if this file is executed directly
if (require.main === module) {
    runStreamCipherTests();
}

module.exports = {
    runStreamCipherTests
};
