const { AwsLcAesCrypto } = require('../index.js');

console.log('🧪 AWS-LC-RS AES Node.js Bindings Test');
console.log('=====================================\n');

function testAwsLcAesBasicEncryption() {
    console.log('1. Testing AWS-LC-RS AES Basic Encryption/Decryption');
    console.log('----------------------------------------------------');
    
    try {
        // Generate key
        const key = AwsLcAesCrypto.generateKey();
        console.log(`✅ Generated key: ${key.length} bytes`);
        
        // Test data
        const plaintext = Buffer.from('Hello, AWS-LC-RS AES from Node.js!', 'utf8');
        console.log(`📝 Plaintext: "${plaintext.toString()}" (${plaintext.length} bytes)`);
        
        // Encrypt
        const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
        console.log(`🔒 Ciphertext: ${ciphertext.length} bytes`);
        
        // Decrypt
        const decrypted = AwsLcAesCrypto.decrypt(ciphertext, key);
        console.log(`🔓 Decrypted: "${decrypted.toString()}" (${decrypted.length} bytes)`);
        
        // Verify
        if (plaintext.equals(decrypted)) {
            console.log('✅ Basic encryption/decryption test PASSED\n');
            return true;
        } else {
            console.log('❌ Basic encryption/decryption test FAILED\n');
            return false;
        }
    } catch (error) {
        console.log(`❌ Basic encryption/decryption test ERROR: ${error.message}\n`);
        return false;
    }
}

function testAwsLcAesWithAAD() {
    console.log('2. Testing AWS-LC-RS AES with Additional Authenticated Data (AAD)');
    console.log('----------------------------------------------------------------');
    
    try {
        // Generate key
        const key = AwsLcAesCrypto.generateKey();
        console.log(`✅ Generated key: ${key.length} bytes`);
        
        // Test data
        const plaintext = Buffer.from('Secret message with AAD', 'utf8');
        const aad = Buffer.from('user_id:12345,session:abc123', 'utf8');
        console.log(`📝 Plaintext: "${plaintext.toString()}"`);
        console.log(`🏷️  AAD: "${aad.toString()}"`);
        
        // Encrypt with AAD
        const ciphertext = AwsLcAesCrypto.encryptWithAad(plaintext, key, aad);
        console.log(`🔒 Ciphertext with AAD: ${ciphertext.length} bytes`);
        
        // Decrypt with AAD
        const decrypted = AwsLcAesCrypto.decryptWithAad(ciphertext, key, aad);
        console.log(`🔓 Decrypted: "${decrypted.toString()}"`);
        
        // Verify
        if (plaintext.equals(decrypted)) {
            console.log('✅ AAD encryption/decryption test PASSED\n');
            return true;
        } else {
            console.log('❌ AAD encryption/decryption test FAILED\n');
            return false;
        }
    } catch (error) {
        console.log(`❌ AAD encryption/decryption test ERROR: ${error.message}\n`);
        return false;
    }
}

function testAwsLcAesWithWrongAAD() {
    console.log('3. Testing AWS-LC-RS AES with Wrong AAD (Should Fail)');
    console.log('----------------------------------------------------');
    
    try {
        // Generate key
        const key = AwsLcAesCrypto.generateKey();
        
        // Test data
        const plaintext = Buffer.from('Secret message', 'utf8');
        const correctAad = Buffer.from('correct_aad', 'utf8');
        const wrongAad = Buffer.from('wrong_aad', 'utf8');
        
        console.log(`📝 Plaintext: "${plaintext.toString()}"`);
        console.log(`🏷️  Correct AAD: "${correctAad.toString()}"`);
        console.log(`🏷️  Wrong AAD: "${wrongAad.toString()}"`);
        
        // Encrypt with correct AAD
        const ciphertext = AwsLcAesCrypto.encryptWithAad(plaintext, key, correctAad);
        console.log(`🔒 Encrypted with correct AAD`);
        
        // Try to decrypt with wrong AAD (should fail)
        try {
            const decrypted = AwsLcAesCrypto.decryptWithAad(ciphertext, key, wrongAad);
            console.log('❌ Wrong AAD test FAILED - decryption should have failed\n');
            return false;
        } catch (decryptError) {
            console.log(`✅ Wrong AAD correctly rejected: ${decryptError.message}`);
            console.log('✅ Wrong AAD test PASSED\n');
            return true;
        }
    } catch (error) {
        console.log(`❌ Wrong AAD test ERROR: ${error.message}\n`);
        return false;
    }
}

function testAwsLcAesWithNonce() {
    console.log('4. Testing AWS-LC-RS AES with Fixed Nonce');
    console.log('----------------------------------------');
    
    try {
        // Generate key
        const key = AwsLcAesCrypto.generateKey();
        console.log(`✅ Generated key: ${key.length} bytes`);
        
        // Test data
        const plaintext = Buffer.from('Test with fixed nonce', 'utf8');
        const nonce = Buffer.alloc(12, 0); // 12-byte nonce filled with zeros
        console.log(`📝 Plaintext: "${plaintext.toString()}"`);
        console.log(`🔢 Nonce: ${nonce.length} bytes (all zeros)`);
        
        // Encrypt with fixed nonce
        const ciphertext1 = AwsLcAesCrypto.encryptWithNonce(plaintext, key, nonce);
        const ciphertext2 = AwsLcAesCrypto.encryptWithNonce(plaintext, key, nonce);
        
        console.log(`🔒 Ciphertext 1: ${ciphertext1.length} bytes`);
        console.log(`🔒 Ciphertext 2: ${ciphertext2.length} bytes`);
        
        // With same nonce, ciphertexts should be identical
        if (ciphertext1.equals(ciphertext2)) {
            console.log('✅ Fixed nonce produces identical ciphertexts');
            console.log('✅ Fixed nonce test PASSED\n');
            return true;
        } else {
            console.log('❌ Fixed nonce test FAILED - ciphertexts should be identical\n');
            return false;
        }
    } catch (error) {
        console.log(`❌ Fixed nonce test ERROR: ${error.message}\n`);
        return false;
    }
}

function testAwsLcAesLargeData() {
    console.log('5. Testing AWS-LC-RS AES with Large Data');
    console.log('---------------------------------------');
    
    try {
        // Generate key
        const key = AwsLcAesCrypto.generateKey();
        console.log(`✅ Generated key: ${key.length} bytes`);
        
        // Create large test data (1MB)
        const dataSize = 1024 * 1024; // 1MB
        const plaintext = Buffer.alloc(dataSize);
        for (let i = 0; i < dataSize; i++) {
            plaintext[i] = i % 256;
        }
        console.log(`📝 Large plaintext: ${plaintext.length} bytes`);
        
        // Measure encryption time
        const encryptStart = process.hrtime.bigint();
        const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
        const encryptEnd = process.hrtime.bigint();
        const encryptTime = Number(encryptEnd - encryptStart) / 1000000; // Convert to milliseconds
        
        console.log(`🔒 Ciphertext: ${ciphertext.length} bytes`);
        console.log(`⏱️  Encryption time: ${encryptTime.toFixed(2)} ms`);
        
        // Measure decryption time
        const decryptStart = process.hrtime.bigint();
        const decrypted = AwsLcAesCrypto.decrypt(ciphertext, key);
        const decryptEnd = process.hrtime.bigint();
        const decryptTime = Number(decryptEnd - decryptStart) / 1000000; // Convert to milliseconds
        
        console.log(`🔓 Decrypted: ${decrypted.length} bytes`);
        console.log(`⏱️  Decryption time: ${decryptTime.toFixed(2)} ms`);
        
        // Calculate throughput
        const encryptThroughput = (dataSize / 1024 / 1024) / (encryptTime / 1000); // MB/s
        const decryptThroughput = (dataSize / 1024 / 1024) / (decryptTime / 1000); // MB/s
        
        console.log(`🚀 Encryption throughput: ${encryptThroughput.toFixed(2)} MB/s`);
        console.log(`🚀 Decryption throughput: ${decryptThroughput.toFixed(2)} MB/s`);
        
        // Verify
        if (plaintext.equals(decrypted)) {
            console.log('✅ Large data test PASSED\n');
            return true;
        } else {
            console.log('❌ Large data test FAILED\n');
            return false;
        }
    } catch (error) {
        console.log(`❌ Large data test ERROR: ${error.message}\n`);
        return false;
    }
}

function testAwsLcAesErrorHandling() {
    console.log('6. Testing AWS-LC-RS AES Error Handling');
    console.log('--------------------------------------');
    
    let passedTests = 0;
    const totalTests = 3;
    
    try {
        // Test 1: Invalid key length
        try {
            const shortKey = Buffer.alloc(16); // Too short (should be 32 bytes)
            const plaintext = Buffer.from('test', 'utf8');
            AwsLcAesCrypto.encrypt(plaintext, shortKey);
            console.log('❌ Invalid key length test FAILED - should have thrown error');
        } catch (error) {
            console.log(`✅ Invalid key length correctly rejected: ${error.message}`);
            passedTests++;
        }
        
        // Test 2: Invalid ciphertext (too short)
        try {
            const key = AwsLcAesCrypto.generateKey();
            const shortCiphertext = Buffer.alloc(10); // Too short
            AwsLcAesCrypto.decrypt(shortCiphertext, key);
            console.log('❌ Invalid ciphertext test FAILED - should have thrown error');
        } catch (error) {
            console.log(`✅ Invalid ciphertext correctly rejected: ${error.message}`);
            passedTests++;
        }
        
        // Test 3: Tampered ciphertext
        try {
            const key = AwsLcAesCrypto.generateKey();
            const plaintext = Buffer.from('test message', 'utf8');
            const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
            
            // Tamper with the ciphertext
            ciphertext[20] = ciphertext[20] ^ 1;
            
            AwsLcAesCrypto.decrypt(ciphertext, key);
            console.log('❌ Tampered ciphertext test FAILED - should have thrown error');
        } catch (error) {
            console.log(`✅ Tampered ciphertext correctly rejected: ${error.message}`);
            passedTests++;
        }
        
        if (passedTests === totalTests) {
            console.log('✅ Error handling test PASSED\n');
            return true;
        } else {
            console.log(`❌ Error handling test FAILED (${passedTests}/${totalTests} passed)\n`);
            return false;
        }
    } catch (error) {
        console.log(`❌ Error handling test ERROR: ${error.message}\n`);
        return false;
    }
}

// Run all tests
function runAllTests() {
    console.log('Starting AWS-LC-RS AES Node.js bindings tests...\n');
    
    const tests = [
        testAwsLcAesBasicEncryption,
        testAwsLcAesWithAAD,
        testAwsLcAesWithWrongAAD,
        testAwsLcAesWithNonce,
        testAwsLcAesLargeData,
        testAwsLcAesErrorHandling
    ];
    
    let passedTests = 0;
    const totalTests = tests.length;
    
    for (const test of tests) {
        if (test()) {
            passedTests++;
        }
    }
    
    console.log('='.repeat(50));
    console.log(`📊 Test Results: ${passedTests}/${totalTests} tests passed`);
    
    if (passedTests === totalTests) {
        console.log('🎉 All AWS-LC-RS AES Node.js binding tests PASSED!');
        process.exit(0);
    } else {
        console.log('❌ Some tests FAILED!');
        process.exit(1);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    runAllTests();
}

module.exports = {
    testAwsLcAesBasicEncryption,
    testAwsLcAesWithAAD,
    testAwsLcAesWithWrongAAD,
    testAwsLcAesWithNonce,
    testAwsLcAesLargeData,
    testAwsLcAesErrorHandling,
    runAllTests
};
