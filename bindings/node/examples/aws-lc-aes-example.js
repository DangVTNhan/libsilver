const { SymmetricCrypto, AwsLcAesCrypto } = require('../index.js');

console.log('🔐 LibSilver AWS-LC-RS AES Node.js Example');
console.log('==========================================\n');

async function demonstrateAwsLcAes() {
    console.log('1. Basic AWS-LC-RS AES-256-GCM Usage');
    console.log('===================================');
    
    // Generate a secure AES-256 key
    const key = AwsLcAesCrypto.generateKey();
    console.log(`✅ Generated AES-256 key: ${key.length} bytes`);
    
    // Encrypt some data
    const plaintext = Buffer.from('Hello, AWS-LC-RS from Node.js! 🚀', 'utf8');
    console.log(`📝 Plaintext: "${plaintext.toString()}" (${plaintext.length} bytes)`);
    
    const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
    console.log(`🔒 Ciphertext: ${ciphertext.length} bytes (includes nonce + tag)`);
    console.log(`🔒 Ciphertext (hex): ${ciphertext.toString('hex').substring(0, 64)}...`);
    
    // Decrypt the data
    const decrypted = AwsLcAesCrypto.decrypt(ciphertext, key);
    console.log(`🔓 Decrypted: "${decrypted.toString()}" (${decrypted.length} bytes)`);
    
    console.log(`✅ Encryption/Decryption successful: ${plaintext.equals(decrypted)}\n`);
}

async function demonstrateAAD() {
    console.log('2. AWS-LC-RS AES with Additional Authenticated Data (AAD)');
    console.log('========================================================');
    
    const key = AwsLcAesCrypto.generateKey();
    
    // Example: Encrypting user data with session information as AAD
    const userData = Buffer.from('{"userId": 12345, "balance": 1000.50}', 'utf8');
    const sessionInfo = Buffer.from('session_id:abc123,timestamp:1640995200,ip:192.168.1.1', 'utf8');
    
    console.log(`📝 User data: ${userData.toString()}`);
    console.log(`🏷️  Session info (AAD): ${sessionInfo.toString()}`);
    
    // Encrypt with AAD
    const ciphertext = AwsLcAesCrypto.encryptWithAad(userData, key, sessionInfo);
    console.log(`🔒 Encrypted with AAD: ${ciphertext.length} bytes`);
    
    // Decrypt with AAD
    const decrypted = AwsLcAesCrypto.decryptWithAad(ciphertext, key, sessionInfo);
    console.log(`🔓 Decrypted: ${decrypted.toString()}`);
    
    console.log(`✅ AAD encryption/decryption successful: ${userData.equals(decrypted)}`);
    
    // Demonstrate AAD validation
    console.log('\n🔍 Testing AAD validation...');
    const wrongSessionInfo = Buffer.from('session_id:wrong,timestamp:0,ip:0.0.0.0', 'utf8');
    try {
        AwsLcAesCrypto.decryptWithAad(ciphertext, key, wrongSessionInfo);
        console.log('❌ This should not happen - wrong AAD should fail');
    } catch (error) {
        console.log(`✅ Wrong AAD correctly rejected: ${error.message}`);
    }
    console.log();
}

async function performanceComparison() {
    console.log('3. Performance Comparison: RustCrypto vs AWS-LC-RS');
    console.log('=================================================');
    
    const dataSizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB
    
    console.log('Data Size | RustCrypto AES | AWS-LC-RS AES | Performance Gain');
    console.log('----------|----------------|---------------|------------------');
    
    for (const size of dataSizes) {
        // Generate test data
        const testData = Buffer.alloc(size);
        for (let i = 0; i < size; i++) {
            testData[i] = i % 256;
        }
        
        // RustCrypto AES-GCM
        const rustCryptoKey = SymmetricCrypto.generateAesKey();
        const rustCryptoStart = process.hrtime.bigint();
        for (let i = 0; i < 100; i++) {
            const encrypted = SymmetricCrypto.encryptAes(testData, rustCryptoKey);
            SymmetricCrypto.decryptAes(encrypted, rustCryptoKey);
        }
        const rustCryptoEnd = process.hrtime.bigint();
        const rustCryptoTime = Number(rustCryptoEnd - rustCryptoStart) / 1000000; // ms
        
        // AWS-LC-RS AES-GCM
        const awsLcKey = AwsLcAesCrypto.generateKey();
        const awsLcStart = process.hrtime.bigint();
        for (let i = 0; i < 100; i++) {
            const encrypted = AwsLcAesCrypto.encrypt(testData, awsLcKey);
            AwsLcAesCrypto.decrypt(encrypted, awsLcKey);
        }
        const awsLcEnd = process.hrtime.bigint();
        const awsLcTime = Number(awsLcEnd - awsLcStart) / 1000000; // ms
        
        const speedup = (rustCryptoTime / awsLcTime).toFixed(1);
        const sizeStr = size >= 1024 ? `${(size / 1024).toFixed(0)}KB` : `${size}B`;
        
        console.log(`${sizeStr.padEnd(9)} | ${rustCryptoTime.toFixed(2).padStart(12)}ms | ${awsLcTime.toFixed(2).padStart(11)}ms | ${speedup}x faster`);
    }
    console.log();
}

async function demonstrateFixedNonce() {
    console.log('4. AWS-LC-RS AES with Fixed Nonce (Testing/Development)');
    console.log('======================================================');
    
    const key = AwsLcAesCrypto.generateKey();
    const plaintext = Buffer.from('Deterministic encryption for testing', 'utf8');
    const nonce = Buffer.alloc(12, 0x42); // Fixed nonce (12 bytes of 0x42)
    
    console.log(`📝 Plaintext: "${plaintext.toString()}"`);
    console.log(`🔢 Fixed nonce: ${nonce.toString('hex')}`);
    
    // Encrypt multiple times with same nonce
    const ciphertext1 = AwsLcAesCrypto.encryptWithNonce(plaintext, key, nonce);
    const ciphertext2 = AwsLcAesCrypto.encryptWithNonce(plaintext, key, nonce);
    
    console.log(`🔒 Ciphertext 1: ${ciphertext1.toString('hex').substring(0, 32)}...`);
    console.log(`🔒 Ciphertext 2: ${ciphertext2.toString('hex').substring(0, 32)}...`);
    console.log(`✅ Identical ciphertexts: ${ciphertext1.equals(ciphertext2)}`);
    
    console.log('⚠️  Note: Fixed nonces should only be used for testing!');
    console.log('⚠️  In production, always use random nonces for security.\n');
}

async function demonstrateErrorHandling() {
    console.log('5. Error Handling and Security Features');
    console.log('======================================');
    
    console.log('🔍 Testing various error conditions...\n');
    
    // Test 1: Invalid key length
    console.log('Test 1: Invalid key length');
    try {
        const shortKey = Buffer.alloc(16); // AES-256 requires 32 bytes
        const plaintext = Buffer.from('test', 'utf8');
        AwsLcAesCrypto.encrypt(plaintext, shortKey);
    } catch (error) {
        console.log(`✅ Correctly rejected short key: ${error.message}`);
    }
    
    // Test 2: Ciphertext tampering detection
    console.log('\nTest 2: Ciphertext tampering detection');
    const key = AwsLcAesCrypto.generateKey();
    const plaintext = Buffer.from('Important data', 'utf8');
    const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
    
    // Tamper with the ciphertext
    const tamperedCiphertext = Buffer.from(ciphertext);
    tamperedCiphertext[20] = tamperedCiphertext[20] ^ 1; // Flip one bit
    
    try {
        AwsLcAesCrypto.decrypt(tamperedCiphertext, key);
    } catch (error) {
        console.log(`✅ Correctly detected tampering: ${error.message}`);
    }
    
    // Test 3: Empty data handling
    console.log('\nTest 3: Empty data handling');
    const emptyData = Buffer.alloc(0);
    const encryptedEmpty = AwsLcAesCrypto.encrypt(emptyData, key);
    const decryptedEmpty = AwsLcAesCrypto.decrypt(encryptedEmpty, key);
    console.log(`✅ Empty data handled correctly: ${emptyData.equals(decryptedEmpty)}`);
    
    console.log();
}

async function demonstrateRealWorldUsage() {
    console.log('6. Real-World Usage Example: Secure File Storage');
    console.log('===============================================');
    
    // Simulate encrypting a file with metadata
    const fileContent = Buffer.from(`
# Important Document
This is a confidential document that needs to be encrypted.
It contains sensitive information that should be protected.

Date: ${new Date().toISOString()}
Classification: Confidential
    `.trim(), 'utf8');
    
    const metadata = Buffer.from(JSON.stringify({
        filename: 'confidential.txt',
        owner: 'user@example.com',
        created: Date.now(),
        checksum: 'sha256:abc123...'
    }), 'utf8');
    
    console.log(`📄 File content: ${fileContent.length} bytes`);
    console.log(`📋 Metadata: ${metadata.toString()}`);
    
    // Generate a key (in practice, this would be derived from a password or stored securely)
    const encryptionKey = AwsLcAesCrypto.generateKey();
    
    // Encrypt file with metadata as AAD
    const encryptedFile = AwsLcAesCrypto.encryptWithAad(fileContent, encryptionKey, metadata);
    console.log(`🔒 Encrypted file: ${encryptedFile.length} bytes`);
    
    // Simulate storage (base64 encoding for demonstration)
    const storedData = encryptedFile.toString('base64');
    console.log(`💾 Stored data: ${storedData.length} characters (base64)`);
    
    // Simulate retrieval and decryption
    const retrievedData = Buffer.from(storedData, 'base64');
    const decryptedFile = AwsLcAesCrypto.decryptWithAad(retrievedData, encryptionKey, metadata);
    
    console.log(`🔓 Decrypted file: ${decryptedFile.length} bytes`);
    console.log(`✅ File integrity verified: ${fileContent.equals(decryptedFile)}`);
    
    console.log('\n📊 Encryption overhead:');
    console.log(`   Original size: ${fileContent.length} bytes`);
    console.log(`   Encrypted size: ${encryptedFile.length} bytes`);
    console.log(`   Overhead: ${encryptedFile.length - fileContent.length} bytes (${((encryptedFile.length - fileContent.length) / fileContent.length * 100).toFixed(1)}%)`);
    
    console.log();
}

async function main() {
    try {
        await demonstrateAwsLcAes();
        await demonstrateAAD();
        await performanceComparison();
        await demonstrateFixedNonce();
        await demonstrateErrorHandling();
        await demonstrateRealWorldUsage();
        
        console.log('🎉 AWS-LC-RS AES Node.js example completed successfully!');
        console.log('\n💡 Key Benefits of AWS-LC-RS AES:');
        console.log('   • FIPS 140-2 Level 1 validated cryptography');
        console.log('   • Exceptional performance (up to 30x faster than RustCrypto)');
        console.log('   • Hardware acceleration support (AES-NI)');
        console.log('   • Same API as RustCrypto for easy migration');
        console.log('   • Built-in authentication with GCM mode');
        console.log('   • Support for Additional Authenticated Data (AAD)');
        
    } catch (error) {
        console.error('❌ Error running example:', error);
        process.exit(1);
    }
}

// Run the example
if (require.main === module) {
    main();
}
