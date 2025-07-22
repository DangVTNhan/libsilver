const { StreamEncryption } = require('../index.js');

function assert(condition, message) {
    if (!condition) {
        throw new Error(`❌ Assertion failed: ${message}`);
    }
    console.log(`✅ ${message}`);
}

function assertThrows(fn, expectedMessage, testMessage) {
    try {
        fn();
        throw new Error(`❌ Expected function to throw: ${testMessage}`);
    } catch (error) {
        if (expectedMessage && !error.message.includes(expectedMessage)) {
            throw new Error(`❌ Expected error message to contain "${expectedMessage}", got: ${error.message}`);
        }
        console.log(`✅ ${testMessage}`);
    }
}

function runStreamCipherAuthenticatedTests() {
    console.log('🧪 Running Stream Cipher Authenticated Encryption Tests...\n');

    // Test 1: Basic authenticated encryption with AAD
    console.log('Testing basic authenticated encryption with AAD...');
    const key = StreamEncryption.generateKey();
    const cipher = new StreamEncryption(key);

    const plaintext = Buffer.from('Hello, authenticated world!', 'utf8');
    const aad = Buffer.from('additional data', 'utf8');

    // Encrypt with AAD
    const ciphertext = cipher.encryptChunkWithAad(plaintext, aad);

    // Verify ciphertext structure (nonce + ciphertext + tag)
    assert(ciphertext.length >= 28, 'Ciphertext should be at least 28 bytes (nonce + tag)');
    assert(ciphertext.length === 12 + plaintext.length + 16, 'Ciphertext length should be nonce + plaintext + tag');

    // Decrypt with AAD
    const decrypted = cipher.decryptChunkWithAad(ciphertext, aad);
    assert(Buffer.compare(decrypted, plaintext) === 0, 'Decrypted text should match original plaintext');

    // Test 2: Empty plaintext with AAD
    console.log('Testing empty plaintext with AAD...');
    const emptyPlaintext = Buffer.alloc(0);
    const aadForEmpty = Buffer.from('metadata for empty file', 'utf8');

    const emptyCiphertext = cipher.encryptChunkWithAad(emptyPlaintext, aadForEmpty);
    assert(emptyCiphertext.length === 28, 'Empty plaintext ciphertext should be 28 bytes (nonce + tag only)');

    const decryptedEmpty = cipher.decryptChunkWithAad(emptyCiphertext, aadForEmpty);
    assert(decryptedEmpty.length === 0, 'Decrypted empty plaintext should be empty');

    // Test 3: Empty AAD
    console.log('Testing empty AAD...');
    const plaintextForEmptyAad = Buffer.from('test with empty aad', 'utf8');
    const emptyAad = Buffer.alloc(0);

    const ciphertextEmptyAad = cipher.encryptChunkWithAad(plaintextForEmptyAad, emptyAad);
    const decryptedEmptyAad = cipher.decryptChunkWithAad(ciphertextEmptyAad, emptyAad);
    assert(Buffer.compare(decryptedEmptyAad, plaintextForEmptyAad) === 0, 'Should work with empty AAD');

    // Test 4: Authentication failure with wrong AAD
    console.log('Testing authentication failure with wrong AAD...');
    const testPlaintext = Buffer.from('Test message', 'utf8');
    const correctAad = Buffer.from('correct aad', 'utf8');
    const wrongAad = Buffer.from('wrong aad', 'utf8');

    const testCiphertext = cipher.encryptChunkWithAad(testPlaintext, correctAad);

    // Should throw when decrypting with wrong AAD
    assertThrows(() => {
        cipher.decryptChunkWithAad(testCiphertext, wrongAad);
    }, 'Authentication tag verification failed', 'Should fail with wrong AAD');

    // Test 5: Ciphertext tampering detection
    console.log('Testing ciphertext tampering detection...');
    const importantMessage = Buffer.from('Important message', 'utf8');
    const metadata = Buffer.from('metadata', 'utf8');

    const importantCiphertext = cipher.encryptChunkWithAad(importantMessage, metadata);

    // Tamper with the ciphertext (flip a bit in the actual ciphertext part)
    const tamperedCiphertext = Buffer.from(importantCiphertext);
    if (tamperedCiphertext.length > 12) {
        tamperedCiphertext[12] ^= 0x01; // Flip one bit after nonce
    }

    // Should throw when decrypting tampered ciphertext
    assertThrows(() => {
        cipher.decryptChunkWithAad(tamperedCiphertext, metadata);
    }, 'Authentication tag verification failed', 'Should detect ciphertext tampering');

    // Test 6: Tag tampering detection
    console.log('Testing tag tampering detection...');
    const tagTestCiphertext = cipher.encryptChunkWithAad(testPlaintext, metadata);

    // Tamper with the tag (last 16 bytes)
    const tagTamperedCiphertext = Buffer.from(tagTestCiphertext);
    tagTamperedCiphertext[tagTamperedCiphertext.length - 1] ^= 0x01;

    // Should throw when decrypting with tampered tag
    assertThrows(() => {
        cipher.decryptChunkWithAad(tagTamperedCiphertext, metadata);
    }, 'Authentication tag verification failed', 'Should detect tag tampering');

    // Test 7: Ciphertext too short
    console.log('Testing ciphertext too short error...');
    const shortCiphertext = Buffer.alloc(20); // Less than minimum 28 bytes
    const shortTestAad = Buffer.from('metadata', 'utf8');

    assertThrows(() => {
        cipher.decryptChunkWithAad(shortCiphertext, shortTestAad);
    }, 'Ciphertext too short', 'Should fail with ciphertext too short');

    // Test 8: Multiple chunks with different AAD
    console.log('Testing multiple chunks with different AAD...');
    const chunks = [
        { data: Buffer.from('Chunk 1 data', 'utf8'), aad: Buffer.from('metadata:chunk1', 'utf8') },
        { data: Buffer.from('Chunk 2 data', 'utf8'), aad: Buffer.from('metadata:chunk2', 'utf8') },
        { data: Buffer.from('Chunk 3 data', 'utf8'), aad: Buffer.from('metadata:chunk3', 'utf8') }
    ];

    const encryptedChunks = [];

    // Encrypt all chunks
    for (const chunk of chunks) {
        const chunkCiphertext = cipher.encryptChunkWithAad(chunk.data, chunk.aad);
        encryptedChunks.push({ ciphertext: chunkCiphertext, aad: chunk.aad, originalData: chunk.data });
    }

    // Verify all ciphertexts are different (different nonces)
    for (let i = 0; i < encryptedChunks.length; i++) {
        for (let j = i + 1; j < encryptedChunks.length; j++) {
            assert(Buffer.compare(encryptedChunks[i].ciphertext, encryptedChunks[j].ciphertext) !== 0,
                   `Chunk ${i} and ${j} ciphertexts should be different`);
        }
    }

    // Decrypt all chunks
    for (let i = 0; i < encryptedChunks.length; i++) {
        const encrypted = encryptedChunks[i];
        const chunkDecrypted = cipher.decryptChunkWithAad(encrypted.ciphertext, encrypted.aad);
        assert(Buffer.compare(chunkDecrypted, encrypted.originalData) === 0,
               `Chunk ${i} should decrypt correctly`);
    }

    // Test 9: Mixing AAD between chunks should fail
    console.log('Testing AAD mixing failure...');
    const chunk1 = { data: Buffer.from('Chunk 1', 'utf8'), aad: Buffer.from('aad1', 'utf8') };
    const chunk2 = { data: Buffer.from('Chunk 2', 'utf8'), aad: Buffer.from('aad2', 'utf8') };

    const chunk1Ciphertext = cipher.encryptChunkWithAad(chunk1.data, chunk1.aad);
    const chunk2Ciphertext = cipher.encryptChunkWithAad(chunk2.data, chunk2.aad);

    // Should work with correct AAD
    const chunk1Decrypted = cipher.decryptChunkWithAad(chunk1Ciphertext, chunk1.aad);
    assert(Buffer.compare(chunk1Decrypted, chunk1.data) === 0, 'Chunk 1 should decrypt with correct AAD');

    // Should fail with wrong AAD
    assertThrows(() => {
        cipher.decryptChunkWithAad(chunk1Ciphertext, chunk2.aad);
    }, 'Authentication tag verification failed', 'Should fail when mixing AAD between chunks');

    // Test 10: Nonce counter management with AAD
    console.log('Testing nonce counter management with AAD...');
    const counterCipher = new StreamEncryption(StreamEncryption.generateKey());

    const initialCounter = counterCipher.getNonceCounter();
    assert(initialCounter === 0, 'Initial nonce counter should be 0');

    const counterPlaintext = Buffer.from('test', 'utf8');
    const counterAad = Buffer.from('metadata', 'utf8');

    counterCipher.encryptChunkWithAad(counterPlaintext, counterAad);
    const afterEncrypt = counterCipher.getNonceCounter();
    assert(afterEncrypt === 1, 'Nonce counter should be 1 after first encryption');

    counterCipher.encryptChunkWithAad(counterPlaintext, counterAad);
    const afterSecondEncrypt = counterCipher.getNonceCounter();
    assert(afterSecondEncrypt === 2, 'Nonce counter should be 2 after second encryption');

    // Test reset
    console.log('Testing nonce counter reset...');
    const beforeReset = counterCipher.getNonceCounter();
    assert(beforeReset === 2, 'Counter should be 2 before reset');

    counterCipher.reset();
    const afterReset = counterCipher.getNonceCounter();
    assert(afterReset === 0, 'Counter should be 0 after reset');

    // Test 11: Compatibility with regular stream cipher operations
    console.log('Testing compatibility with regular stream cipher...');
    const compatCipher = new StreamEncryption(StreamEncryption.generateKey());

    const regularPlaintext = Buffer.from('Regular encryption', 'utf8');
    const aadPlaintext = Buffer.from('AAD encryption', 'utf8');
    const compatAad = Buffer.from('additional data', 'utf8');

    // Regular encryption
    const regularCiphertext = compatCipher.encryptChunk(regularPlaintext);

    // AAD encryption
    const aadCiphertext = compatCipher.encryptChunkWithAad(aadPlaintext, compatAad);

    // Both should decrypt correctly
    const regularDecrypted = compatCipher.decryptChunk(regularCiphertext);
    const aadDecrypted = compatCipher.decryptChunkWithAad(aadCiphertext, compatAad);

    assert(Buffer.compare(regularDecrypted, regularPlaintext) === 0, 'Regular encryption should work');
    assert(Buffer.compare(aadDecrypted, aadPlaintext) === 0, 'AAD encryption should work');

    // Nonce counter should be incremented for both
    assert(compatCipher.getNonceCounter() === 2, 'Nonce counter should be 2 after both operations');

    // Test 12: Large data handling
    console.log('Testing large data handling with AAD...');
    const largeCipher = new StreamEncryption(StreamEncryption.generateKey());
    const largeData = Buffer.alloc(1024 * 1024, 0x42); // 1MB of data
    const largeAad = Buffer.from('large file metadata', 'utf8');

    const largeCiphertext = largeCipher.encryptChunkWithAad(largeData, largeAad);
    const largeDecrypted = largeCipher.decryptChunkWithAad(largeCiphertext, largeAad);

    assert(Buffer.compare(largeDecrypted, largeData) === 0, 'Large data should encrypt/decrypt correctly');
    assert(largeCiphertext.length === 12 + largeData.length + 16, 'Large ciphertext should have correct length');

    console.log('\n🎉 All Stream Cipher Authenticated Encryption tests passed!\n');
}

// Run the tests if this file is executed directly
if (require.main === module) {
    try {
        runStreamCipherAuthenticatedTests();
        console.log('✅ All tests completed successfully!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

module.exports = { runStreamCipherAuthenticatedTests };
