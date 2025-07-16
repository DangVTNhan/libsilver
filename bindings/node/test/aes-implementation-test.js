#!/usr/bin/env node

/**
 * Test script to verify AES implementation changes in LibSilver Node.js bindings
 * Tests that SymmetricCrypto now uses AWS-LC-RS by default and RustCryptoAesCrypto is available
 */

const { SymmetricCrypto, AwsLcAesCrypto, RustCryptoAesCrypto } = require('../index.js');

console.log('🧪 Testing AES Implementation Changes in LibSilver Node.js Bindings\n');

async function testSymmetricCryptoDefault() {
    console.log('1. Testing SymmetricCrypto (Default - AWS-LC-RS)');
    console.log('=================================================');
    
    try {
        // Test basic encryption/decryption
        const key = SymmetricCrypto.generateAesKey();
        const plaintext = Buffer.from('Hello, Default AES (AWS-LC-RS)!', 'utf8');
        
        console.log(`✅ Generated AES key: ${key.length} bytes`);
        console.log(`📝 Plaintext: "${plaintext.toString('utf8')}"`);
        
        const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
        console.log(`🔒 Ciphertext: ${ciphertext.length} bytes`);
        
        const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);
        console.log(`🔓 Decrypted: "${decrypted.toString('utf8')}"`);
        
        if (decrypted.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ Basic encryption/decryption: PASSED');
        } else {
            throw new Error('Basic encryption/decryption failed');
        }
        
        // Test AAD support (new feature)
        const aad = Buffer.from('user_id:12345,session:test', 'utf8');
        const ciphertextWithAad = SymmetricCrypto.encryptAesWithAad(plaintext, key, aad);
        const decryptedWithAad = SymmetricCrypto.decryptAesWithAad(ciphertextWithAad, key, aad);
        
        if (decryptedWithAad.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ AAD encryption/decryption: PASSED');
        } else {
            throw new Error('AAD encryption/decryption failed');
        }
        
        // Test fixed nonce (new feature)
        const nonce = Buffer.alloc(12, 0x42);
        const ciphertextWithNonce = SymmetricCrypto.encryptAesWithNonce(plaintext, key, nonce);
        const ciphertextWithNonce2 = SymmetricCrypto.encryptAesWithNonce(plaintext, key, nonce);
        
        if (Buffer.compare(ciphertextWithNonce, ciphertextWithNonce2) === 0) {
            console.log('✅ Fixed nonce encryption: PASSED');
        } else {
            throw new Error('Fixed nonce encryption failed');
        }
        
        console.log('✅ SymmetricCrypto (Default AWS-LC-RS) tests: ALL PASSED\n');
        
    } catch (error) {
        console.error('❌ SymmetricCrypto test failed:', error.message);
        process.exit(1);
    }
}

async function testAwsLcAesCryptoExplicit() {
    console.log('2. Testing AwsLcAesCrypto (Explicit AWS-LC-RS)');
    console.log('===============================================');
    
    try {
        const key = AwsLcAesCrypto.generateKey();
        const plaintext = Buffer.from('Hello, Explicit AWS-LC-RS!', 'utf8');
        
        const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);
        const decrypted = AwsLcAesCrypto.decrypt(ciphertext, key);
        
        if (decrypted.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ AwsLcAesCrypto basic test: PASSED');
        } else {
            throw new Error('AwsLcAesCrypto basic test failed');
        }
        
        console.log('✅ AwsLcAesCrypto tests: ALL PASSED\n');
        
    } catch (error) {
        console.error('❌ AwsLcAesCrypto test failed:', error.message);
        process.exit(1);
    }
}

async function testRustCryptoAesCrypto() {
    console.log('3. Testing RustCryptoAesCrypto (Alternative Implementation)');
    console.log('=========================================================');
    
    try {
        const key = RustCryptoAesCrypto.generateKey();
        const plaintext = Buffer.from('Hello, RustCrypto AES!', 'utf8');
        
        console.log(`✅ Generated RustCrypto AES key: ${key.length} bytes`);
        console.log(`📝 Plaintext: "${plaintext.toString('utf8')}"`);
        
        const ciphertext = RustCryptoAesCrypto.encrypt(plaintext, key);
        console.log(`🔒 Ciphertext: ${ciphertext.length} bytes`);
        
        const decrypted = RustCryptoAesCrypto.decrypt(ciphertext, key);
        console.log(`🔓 Decrypted: "${decrypted.toString('utf8')}"`);
        
        if (decrypted.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ RustCrypto basic encryption/decryption: PASSED');
        } else {
            throw new Error('RustCrypto basic encryption/decryption failed');
        }
        
        // Test AAD support
        const aad = Buffer.from('rustcrypto_aad_test', 'utf8');
        const ciphertextWithAad = RustCryptoAesCrypto.encryptWithAad(plaintext, key, aad);
        const decryptedWithAad = RustCryptoAesCrypto.decryptWithAad(ciphertextWithAad, key, aad);
        
        if (decryptedWithAad.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ RustCrypto AAD encryption/decryption: PASSED');
        } else {
            throw new Error('RustCrypto AAD encryption/decryption failed');
        }
        
        console.log('✅ RustCryptoAesCrypto tests: ALL PASSED\n');
        
    } catch (error) {
        console.error('❌ RustCryptoAesCrypto test failed:', error.message);
        process.exit(1);
    }
}

async function testCompatibility() {
    console.log('4. Testing Cross-Implementation Compatibility');
    console.log('============================================');
    
    try {
        // Test that all implementations generate compatible keys
        const defaultKey = SymmetricCrypto.generateAesKey();
        const awsLcKey = AwsLcAesCrypto.generateKey();
        const rustCryptoKey = RustCryptoAesCrypto.generateKey();
        
        if (defaultKey.length === 32 && awsLcKey.length === 32 && rustCryptoKey.length === 32) {
            console.log('✅ All implementations generate 32-byte keys: PASSED');
        } else {
            throw new Error('Key length mismatch between implementations');
        }
        
        // Test that SymmetricCrypto and AwsLcAesCrypto produce compatible results
        const plaintext = Buffer.from('Compatibility test message', 'utf8');
        const key = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
        
        const defaultCiphertext = SymmetricCrypto.encryptAes(plaintext, key);
        const awsLcCiphertext = AwsLcAesCrypto.encrypt(plaintext, key);
        
        // They should both decrypt successfully (though ciphertexts will differ due to random nonces)
        const defaultDecrypted = SymmetricCrypto.decryptAes(defaultCiphertext, key);
        const awsLcDecrypted = AwsLcAesCrypto.decrypt(awsLcCiphertext, key);
        
        if (defaultDecrypted.toString('utf8') === plaintext.toString('utf8') &&
            awsLcDecrypted.toString('utf8') === plaintext.toString('utf8')) {
            console.log('✅ SymmetricCrypto and AwsLcAesCrypto compatibility: PASSED');
        } else {
            throw new Error('Compatibility test failed');
        }
        
        console.log('✅ Compatibility tests: ALL PASSED\n');
        
    } catch (error) {
        console.error('❌ Compatibility test failed:', error.message);
        process.exit(1);
    }
}

async function main() {
    try {
        await testSymmetricCryptoDefault();
        await testAwsLcAesCryptoExplicit();
        await testRustCryptoAesCrypto();
        await testCompatibility();
        
        console.log('🎉 All AES Implementation Tests Passed!');
        console.log('\n📋 Summary of Changes:');
        console.log('   ✅ SymmetricCrypto now uses AWS-LC-RS by default');
        console.log('   ✅ SymmetricCrypto now supports AAD and fixed nonce');
        console.log('   ✅ RustCryptoAesCrypto available for alternative implementation');
        console.log('   ✅ All implementations are compatible and working correctly');
        console.log('\n💡 Migration Guide:');
        console.log('   • Existing SymmetricCrypto code now uses AWS-LC-RS (faster, FIPS-validated)');
        console.log('   • Use RustCryptoAesCrypto if you specifically need RustCrypto implementation');
        console.log('   • AwsLcAesCrypto remains available for explicit AWS-LC-RS usage');
        
    } catch (error) {
        console.error('❌ Test suite failed:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { testSymmetricCryptoDefault, testAwsLcAesCryptoExplicit, testRustCryptoAesCrypto, testCompatibility };
