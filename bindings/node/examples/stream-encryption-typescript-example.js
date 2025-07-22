#!/usr/bin/env node
"use strict";
/**
 * StreamEncryption TypeScript Example
 *
 * This example demonstrates how to use the StreamEncryption class
 * with TypeScript for type-safe stateful encryption/decryption.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../index");
console.log('🔐 LibSilver StreamEncryption TypeScript Example\n');
// Example 1: Type-safe Stream Encryption
console.log('1. Type-safe Stream Encryption');
console.log('===============================');
// Generate a key with proper typing
const key = index_1.StreamEncryption.generateKey();
console.log('Generated key length:', key.length, 'bytes');
// Create a stream cipher instance with type safety
const cipher = new index_1.StreamEncryption(key);
console.log('Created StreamEncryption instance');
const dataChunks = [
    { id: 1, content: 'First secure message', timestamp: new Date() },
    { id: 2, content: 'Second secure message', timestamp: new Date() },
    { id: 3, content: 'Third secure message', timestamp: new Date() }
];
// Encrypt with type safety
console.log('\nEncrypting typed data:');
const encryptedChunks = [];
for (const chunk of dataChunks) {
    const jsonData = JSON.stringify(chunk);
    const plaintext = Buffer.from(jsonData, 'utf8');
    const ciphertext = cipher.encryptChunk(plaintext);
    encryptedChunks.push(ciphertext);
    console.log(`Encrypted chunk ${chunk.id}: ${ciphertext.length} bytes`);
}
// Type-safe nonce counter access
const nonceCounter = cipher.getNonceCounter();
console.log(`Nonce counter: ${nonceCounter}`);
// Decrypt with type safety
console.log('\nDecrypting typed data:');
const decryptedChunks = [];
for (let i = 0; i < encryptedChunks.length; i++) {
    const decryptedBuffer = cipher.decryptChunk(encryptedChunks[i]);
    const jsonString = decryptedBuffer.toString('utf8');
    const parsedChunk = JSON.parse(jsonString);
    decryptedChunks.push(parsedChunk);
    console.log(`Decrypted chunk ${parsedChunk.id}: "${parsedChunk.content}"`);
}
// Example 2: Type-safe Error Handling
console.log('\n\n2. Type-safe Error Handling');
console.log('============================');
try {
    // This should work fine
    const validKey = index_1.StreamEncryption.generateKey();
    const validCipher = new index_1.StreamEncryption(validKey);
    const testData = Buffer.from('Test data', 'utf8');
    const encrypted = validCipher.encryptChunk(testData);
    const decrypted = validCipher.decryptChunk(encrypted);
    console.log('✅ Valid operations completed successfully');
    console.log(`Original: "${testData.toString('utf8')}"`);
    console.log(`Decrypted: "${decrypted.toString('utf8')}"`);
}
catch (error) {
    if (error instanceof Error) {
        console.error('❌ Error occurred:', error.message);
    }
    else {
        console.error('❌ Unknown error occurred');
    }
}
// Example 3: Type-safe Reset Functionality
console.log('\n\n3. Type-safe Reset Functionality');
console.log('=================================');
const resetKey = index_1.StreamEncryption.generateKey();
const resetCipher = new index_1.StreamEncryption(resetKey);
// Encrypt some data
const beforeResetData = Buffer.from('Before reset', 'utf8');
resetCipher.encryptChunk(beforeResetData);
resetCipher.encryptChunk(beforeResetData);
const counterBeforeReset = resetCipher.getNonceCounter();
console.log(`Counter before reset: ${counterBeforeReset}`);
// Reset with proper typing
resetCipher.reset();
const counterAfterReset = resetCipher.getNonceCounter();
console.log(`Counter after reset: ${counterAfterReset}`);
// Verify functionality after reset
const afterResetData = Buffer.from('After reset', 'utf8');
const afterResetEncrypted = resetCipher.encryptChunk(afterResetData);
const afterResetDecrypted = resetCipher.decryptChunk(afterResetEncrypted);
console.log(`Data after reset: "${afterResetDecrypted.toString('utf8')}"`);
// Example 4: Type-safe Streaming Interface
console.log('\n\n4. Type-safe Streaming Interface');
console.log('=================================');
class SecureStreamProcessor {
    constructor(key) {
        this.processedChunks = 0;
        this.cipher = new index_1.StreamEncryption(key);
    }
    processChunk(data) {
        const encrypted = this.cipher.encryptChunk(data);
        this.processedChunks++;
        return encrypted;
    }
    getStats() {
        return {
            processed: this.processedChunks,
            nonceCounter: this.cipher.getNonceCounter()
        };
    }
}
// Use the type-safe streaming processor
const processorKey = index_1.StreamEncryption.generateKey();
const processor = new SecureStreamProcessor(processorKey);
const streamData = [
    'Stream chunk 1',
    'Stream chunk 2',
    'Stream chunk 3'
];
console.log('Processing stream data:');
const processedResults = [];
for (const data of streamData) {
    const chunk = Buffer.from(data, 'utf8');
    const result = processor.processChunk(chunk);
    processedResults.push(result);
    console.log(`Processed: "${data}" -> ${result.length} bytes`);
}
const stats = processor.getStats();
console.log(`\nStream processing stats:`);
console.log(`  Chunks processed: ${stats.processed}`);
console.log(`  Nonce counter: ${stats.nonceCounter}`);
console.log('\n🎉 TypeScript StreamEncryption example completed successfully!');
console.log('\n💡 TypeScript benefits:');
console.log('   • Compile-time type checking for all operations');
console.log('   • IntelliSense support in IDEs');
console.log('   • Clear interface definitions for better code organization');
console.log('   • Type-safe error handling');
console.log('   • Better refactoring support');
