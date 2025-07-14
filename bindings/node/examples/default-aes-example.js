#!/usr/bin/env node

/**
 * LibSilver Node.js Default AES Example
 * 
 * This example demonstrates the updated AES implementation in LibSilver Node.js bindings:
 * - SymmetricCrypto now uses AWS-LC-RS by default (faster, FIPS-validated)
 * - New AAD and fixed nonce support in SymmetricCrypto
 * - RustCryptoAesCrypto available as alternative implementation
 */

const { SymmetricCrypto, AwsLcAesCrypto, RustCryptoAesCrypto } = require('../index.js');

console.log('🔐 LibSilver Node.js Default AES Implementation Example');
console.log('======================================================\n');

async function demonstrateDefaultAes() {
    console.log('1. SymmetricCrypto (Default - AWS-LC-RS)');
    console.log('========================================');
    
    // Generate key using default implementation (now AWS-LC-RS)
    const key = SymmetricCrypto.generateAesKey();
    console.log(`✅ Generated AES-256 key: ${key.length} bytes`);
    
    // Basic encryption/decryption
    const plaintext = Buffer.from('Hello, Default AES! Now using AWS-LC-RS for better performance! 🚀', 'utf8');
    console.log(`📝 Plaintext: "${plaintext.toString('utf8')}" (${plaintext.length} bytes)`);
    
    const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
    console.log(`🔒 Ciphertext: ${ciphertext.length} bytes (includes nonce + tag)`);
    console.log(`🔒 Ciphertext (hex): ${ciphertext.toString('hex').substring(0, 64)}...`);
    
    const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);
    console.log(`🔓 Decrypted: "${decrypted.toString('utf8')}" (${decrypted.length} bytes)`);
    console.log(`✅ Encryption/Decryption successful: ${decrypted.toString('utf8') === plaintext.toString('utf8')}\n`);
    
    // NEW: AAD support in SymmetricCrypto
    console.log('🏷️  Testing AAD (Additional Authenticated Data) Support');
    const userData = JSON.stringify({ userId: 12345, balance: 1000.50 });
    const sessionInfo = 'session_id:abc123,timestamp:1640995200,ip:192.168.1.1';
    const aad = Buffer.from(sessionInfo, 'utf8');
    
    console.log(`📝 User data: ${userData}`);
    console.log(`🏷️  Session info (AAD): ${sessionInfo}`);
    
    const ciphertextWithAad = SymmetricCrypto.encryptAesWithAad(Buffer.from(userData, 'utf8'), key, aad);
    console.log(`🔒 Encrypted with AAD: ${ciphertextWithAad.length} bytes`);
    
    const decryptedWithAad = SymmetricCrypto.decryptAesWithAad(ciphertextWithAad, key, aad);
    console.log(`🔓 Decrypted: ${decryptedWithAad.toString('utf8')}`);
    console.log(`✅ AAD encryption/decryption successful: ${decryptedWithAad.toString('utf8') === userData}\n`);
    
    // Test AAD validation
    console.log('🔍 Testing AAD validation...');
    const wrongAad = Buffer.from('wrong_session_info', 'utf8');
    try {
        SymmetricCrypto.decryptAesWithAad(ciphertextWithAad, key, wrongAad);
        console.log('❌ AAD validation failed - should have thrown error');
    } catch (error) {
        console.log(`✅ Wrong AAD correctly rejected: ${error.message}\n`);
    }
    
    // NEW: Fixed nonce support (for testing/deterministic encryption)
    console.log('🔢 Testing Fixed Nonce Support (Testing/Development)');
    const testPlaintext = Buffer.from('Deterministic encryption for testing', 'utf8');
    const fixedNonce = Buffer.alloc(12, 0x42); // Fixed nonce for deterministic results
    
    console.log(`📝 Plaintext: "${testPlaintext.toString('utf8')}"`);
    console.log(`🔢 Fixed nonce: ${fixedNonce.toString('hex')}`);
    
    const deterministicCiphertext1 = SymmetricCrypto.encryptAesWithNonce(testPlaintext, key, fixedNonce);
    const deterministicCiphertext2 = SymmetricCrypto.encryptAesWithNonce(testPlaintext, key, fixedNonce);
    
    console.log(`🔒 Ciphertext 1: ${deterministicCiphertext1.toString('hex').substring(0, 32)}...`);
    console.log(`🔒 Ciphertext 2: ${deterministicCiphertext2.toString('hex').substring(0, 32)}...`);
    console.log(`✅ Identical ciphertexts: ${Buffer.compare(deterministicCiphertext1, deterministicCiphertext2) === 0}`);
    console.log('⚠️  Note: Fixed nonces should only be used for testing!');
    console.log('⚠️  In production, always use random nonces for security.\n');
}

async function demonstrateImplementationComparison() {
    console.log('2. Implementation Comparison');
    console.log('===========================');
    
    const plaintext = Buffer.from('Performance comparison test data', 'utf8');
    const key = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
    
    console.log('Testing all three AES implementations:\n');
    
    // Default (AWS-LC-RS)
    console.log('📊 SymmetricCrypto (Default - AWS-LC-RS):');
    const start1 = process.hrtime.bigint();
    const ciphertext1 = SymmetricCrypto.encryptAes(plaintext, key);
    const decrypted1 = SymmetricCrypto.decryptAes(ciphertext1, key);
    const end1 = process.hrtime.bigint();
    console.log(`   ✅ Success: ${decrypted1.toString('utf8') === plaintext.toString('utf8')}`);
    console.log(`   ⏱️  Time: ${Number(end1 - start1) / 1000000}ms`);
    console.log(`   📦 Ciphertext size: ${ciphertext1.length} bytes\n`);
    
    // Explicit AWS-LC-RS
    console.log('📊 AwsLcAesCrypto (Explicit AWS-LC-RS):');
    const start2 = process.hrtime.bigint();
    const ciphertext2 = AwsLcAesCrypto.encrypt(plaintext, key);
    const decrypted2 = AwsLcAesCrypto.decrypt(ciphertext2, key);
    const end2 = process.hrtime.bigint();
    console.log(`   ✅ Success: ${decrypted2.toString('utf8') === plaintext.toString('utf8')}`);
    console.log(`   ⏱️  Time: ${Number(end2 - start2) / 1000000}ms`);
    console.log(`   📦 Ciphertext size: ${ciphertext2.length} bytes\n`);
    
    // RustCrypto
    console.log('📊 RustCryptoAesCrypto (Alternative):');
    const start3 = process.hrtime.bigint();
    const ciphertext3 = RustCryptoAesCrypto.encrypt(plaintext, key);
    const decrypted3 = RustCryptoAesCrypto.decrypt(ciphertext3, key);
    const end3 = process.hrtime.bigint();
    console.log(`   ✅ Success: ${decrypted3.toString('utf8') === plaintext.toString('utf8')}`);
    console.log(`   ⏱️  Time: ${Number(end3 - start3) / 1000000}ms`);
    console.log(`   📦 Ciphertext size: ${ciphertext3.length} bytes\n`);
    
    console.log('💡 Key Differences:');
    console.log('   • SymmetricCrypto & AwsLcAesCrypto: AWS-LC-RS (FIPS-validated, optimized)');
    console.log('   • RustCryptoAesCrypto: Pure Rust implementation (portable, ecosystem)');
    console.log('   • All implementations are secure and compatible');
    console.log('   • Choose based on your specific requirements (FIPS compliance, performance, etc.)\n');
}

async function demonstrateMigrationGuide() {
    console.log('3. Migration Guide');
    console.log('=================');
    
    console.log('📋 What Changed:');
    console.log('   • SymmetricCrypto now uses AWS-LC-RS by default (was RustCrypto)');
    console.log('   • SymmetricCrypto gained AAD and fixed nonce support');
    console.log('   • RustCryptoAesCrypto added for users who need RustCrypto specifically\n');
    
    console.log('🔄 Migration Scenarios:');
    console.log('   1. No changes needed: Existing SymmetricCrypto code works but now uses AWS-LC-RS');
    console.log('   2. Want RustCrypto specifically: Replace SymmetricCrypto with RustCryptoAesCrypto');
    console.log('   3. Want explicit AWS-LC-RS: Use AwsLcAesCrypto (same as before)\n');
    
    console.log('📝 Code Examples:');
    console.log('   // Before (still works, now uses AWS-LC-RS):');
    console.log('   const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);');
    console.log('   ');
    console.log('   // For RustCrypto specifically:');
    console.log('   const ciphertext = RustCryptoAesCrypto.encrypt(plaintext, key);');
    console.log('   ');
    console.log('   // For explicit AWS-LC-RS:');
    console.log('   const ciphertext = AwsLcAesCrypto.encrypt(plaintext, key);\n');
    
    console.log('⚡ Performance Benefits:');
    console.log('   • AWS-LC-RS is typically 5-20x faster than RustCrypto');
    console.log('   • Hardware acceleration (AES-NI) support');
    console.log('   • FIPS 140-2 Level 1 validated cryptography');
    console.log('   • Same security guarantees as RustCrypto\n');
}

async function main() {
    try {
        await demonstrateDefaultAes();
        await demonstrateImplementationComparison();
        await demonstrateMigrationGuide();
        
        console.log('🎉 Default AES Implementation Example completed successfully!');
        console.log('\n💡 Key Takeaways:');
        console.log('   • SymmetricCrypto now uses AWS-LC-RS by default for better performance');
        console.log('   • New AAD and fixed nonce support in SymmetricCrypto');
        console.log('   • RustCryptoAesCrypto available for users who need RustCrypto specifically');
        console.log('   • All implementations are compatible and secure');
        console.log('   • Migration is seamless - existing code works with performance improvements');
        
    } catch (error) {
        console.error('❌ Example failed:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { demonstrateDefaultAes, demonstrateImplementationComparison, demonstrateMigrationGuide };
