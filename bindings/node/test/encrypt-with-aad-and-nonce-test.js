const {
    SymmetricCrypto,
    AwsLcAesCrypto,
    RustCryptoAesCrypto,
    RandomGenerator
} = require('../index.js');

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || 'Assertion failed');
    }
}

function testEncryptWithAadAndNonce() {
    console.log('Testing encrypt_with_aad_and_nonce functionality...');

    // Test data
    const plaintext = Buffer.from('This is a secret message that needs encryption with AAD and custom nonce!');
    const aad = Buffer.from('additional authenticated data - user metadata');
    const customNonce = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]); // 12 bytes

    // Generate a key
    const key = SymmetricCrypto.generateAesKey();
    assert(key.length === 32, 'AES key should be 32 bytes');
    assert(customNonce.length === 12, 'Nonce should be 12 bytes');

    // === Test with default SymmetricCrypto (AWS-LC-RS) ===
    const ciphertext = SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, customNonce);
    assert(ciphertext.length > plaintext.length, 'Ciphertext should be longer than plaintext');

    // Create full ciphertext format for decryption (nonce + ciphertext)
    const fullCiphertext = Buffer.concat([customNonce, ciphertext]);

    const decrypted = SymmetricCrypto.decryptAesWithAad(fullCiphertext, key, aad);
    assert(decrypted.equals(plaintext), 'SymmetricCrypto decryption should match original plaintext');
    console.log('✓ SymmetricCrypto encrypt_with_aad_and_nonce works');

    // === Test with AWS-LC-RS implementation directly ===
    const awsLcCiphertext = AwsLcAesCrypto.encryptWithAadAndNonce(plaintext, key, aad, customNonce);
    assert(awsLcCiphertext.length > plaintext.length, 'AWS-LC-RS ciphertext should be longer than plaintext');

    // Create full ciphertext format for decryption
    const awsLcFullCiphertext = Buffer.concat([customNonce, awsLcCiphertext]);

    const awsLcDecrypted = AwsLcAesCrypto.decryptWithAad(awsLcFullCiphertext, key, aad);
    assert(awsLcDecrypted.equals(plaintext), 'AWS-LC-RS decryption should match original plaintext');
    console.log('✓ AwsLcAesCrypto encrypt_with_aad_and_nonce works');

    // === Test with RustCrypto implementation ===
    const rustCryptoCiphertext = RustCryptoAesCrypto.encryptWithAadAndNonce(plaintext, key, aad, customNonce);
    assert(rustCryptoCiphertext.length > plaintext.length, 'RustCrypto ciphertext should be longer than plaintext');

    // Create full ciphertext format for decryption
    const rustCryptoFullCiphertext = Buffer.concat([customNonce, rustCryptoCiphertext]);

    const rustCryptoDecrypted = RustCryptoAesCrypto.decryptWithAad(rustCryptoFullCiphertext, key, aad);
    assert(rustCryptoDecrypted.equals(plaintext), 'RustCrypto decryption should match original plaintext');
    console.log('✓ RustCryptoAesCrypto encrypt_with_aad_and_nonce works');

    // === Cross-implementation compatibility test ===
    const symCiphertext2 = SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, customNonce);
    const awsLcCiphertext2 = AwsLcAesCrypto.encryptWithAadAndNonce(plaintext, key, aad, customNonce);
    const rustCryptoCiphertext2 = RustCryptoAesCrypto.encryptWithAadAndNonce(plaintext, key, aad, customNonce);

    assert(symCiphertext2.equals(awsLcCiphertext2), 'SymmetricCrypto and AwsLcAesCrypto should produce same ciphertext');
    assert(rustCryptoCiphertext2.equals(awsLcCiphertext2), 'RustCrypto and AWS-LC-RS should produce same ciphertext');

    // Test cross-decryption
    const symFullCiphertext2 = Buffer.concat([customNonce, symCiphertext2]);
    const awsLcFullCiphertext2 = Buffer.concat([customNonce, awsLcCiphertext2]);
    const rustCryptoFullCiphertext2 = Buffer.concat([customNonce, rustCryptoCiphertext2]);

    const crossDecrypted1 = RustCryptoAesCrypto.decryptWithAad(awsLcFullCiphertext2, key, aad);
    const crossDecrypted2 = AwsLcAesCrypto.decryptWithAad(rustCryptoFullCiphertext2, key, aad);
    const crossDecrypted3 = SymmetricCrypto.decryptAesWithAad(rustCryptoFullCiphertext2, key, aad);

    assert(crossDecrypted1.equals(plaintext), 'Cross-decryption 1 should work');
    assert(crossDecrypted2.equals(plaintext), 'Cross-decryption 2 should work');
    assert(crossDecrypted3.equals(plaintext), 'Cross-decryption 3 should work');
    console.log('✓ Cross-implementation compatibility works');

    // === Demonstrate deterministic encryption ===
    const ciphertext1 = SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, customNonce);
    const ciphertext2 = SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, customNonce);
    assert(ciphertext1.equals(ciphertext2), 'Same nonce should produce identical ciphertext');
    console.log('✓ Deterministic encryption with same nonce works');

    // === Demonstrate AAD authentication ===
    const wrongAad = Buffer.from('wrong additional authenticated data');

    const testCiphertext = SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, customNonce);
    const testFullCiphertext = Buffer.concat([customNonce, testCiphertext]);

    let aadTestFailed = false;
    try {
        SymmetricCrypto.decryptAesWithAad(testFullCiphertext, key, wrongAad);
    } catch (decryptError) {
        aadTestFailed = true;
    }
    assert(aadTestFailed, 'Decryption should fail with wrong AAD');
    console.log('✓ AAD authentication works correctly');

    // === Test error handling ===
    // Test with invalid nonce length
    const invalidNonce = Buffer.from([0x01, 0x02, 0x03]); // Too short
    let nonceTestFailed = false;
    try {
        SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, aad, invalidNonce);
    } catch (nonceError) {
        nonceTestFailed = true;
    }
    assert(nonceTestFailed, 'Should fail with invalid nonce length');
    console.log('✓ Invalid nonce length error handling works');

    // Test with invalid key length
    const invalidKey = Buffer.from([0x01, 0x02, 0x03]); // Too short
    let keyTestFailed = false;
    try {
        SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, invalidKey, aad, customNonce);
    } catch (keyError) {
        keyTestFailed = true;
    }
    assert(keyTestFailed, 'Should fail with invalid key length');
    console.log('✓ Invalid key length error handling works');
}

if (require.main === module) {
    console.log('🧪 Running encrypt_with_aad_and_nonce tests...\n');
    try {
        testEncryptWithAadAndNonce();
        console.log('\n✅ All encrypt_with_aad_and_nonce tests passed!');
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

module.exports = { testEncryptWithAadAndNonce };
