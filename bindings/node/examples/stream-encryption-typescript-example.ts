#!/usr/bin/env node

/**
 * StreamEncryption TypeScript Example
 * 
 * This example demonstrates how to use the StreamEncryption class
 * with TypeScript for type-safe stateful encryption/decryption.
 */

import { StreamEncryption } from '../index';

console.log('🔐 LibSilver StreamEncryption TypeScript Example\n');

// Example 1: Type-safe Stream Encryption
console.log('1. Type-safe Stream Encryption');
console.log('===============================');

// Generate a key with proper typing
const key: Buffer = StreamEncryption.generateKey();
console.log('Generated key length:', key.length, 'bytes');

// Create a stream cipher instance with type safety
const cipher: StreamEncryption = new StreamEncryption(key);
console.log('Created StreamEncryption instance');

// Define typed data
interface DataChunk {
    id: number;
    content: string;
    timestamp: Date;
}

const dataChunks: DataChunk[] = [
    { id: 1, content: 'First secure message', timestamp: new Date() },
    { id: 2, content: 'Second secure message', timestamp: new Date() },
    { id: 3, content: 'Third secure message', timestamp: new Date() }
];

// Encrypt with type safety
console.log('\nEncrypting typed data:');
const encryptedChunks: Buffer[] = [];

for (const chunk of dataChunks) {
    const jsonData: string = JSON.stringify(chunk);
    const plaintext: Buffer = Buffer.from(jsonData, 'utf8');
    const ciphertext: Buffer = cipher.encryptChunk(plaintext);
    encryptedChunks.push(ciphertext);
    
    console.log(`Encrypted chunk ${chunk.id}: ${ciphertext.length} bytes`);
}

// Type-safe nonce counter access
const nonceCounter: number = cipher.getNonceCounter();
console.log(`Nonce counter: ${nonceCounter}`);

// Decrypt with type safety
console.log('\nDecrypting typed data:');
const decryptedChunks: DataChunk[] = [];

for (let i = 0; i < encryptedChunks.length; i++) {
    const decryptedBuffer: Buffer = cipher.decryptChunk(encryptedChunks[i]);
    const jsonString: string = decryptedBuffer.toString('utf8');
    const parsedChunk: DataChunk = JSON.parse(jsonString);
    decryptedChunks.push(parsedChunk);
    
    console.log(`Decrypted chunk ${parsedChunk.id}: "${parsedChunk.content}"`);
}

// Example 2: Type-safe Error Handling
console.log('\n\n2. Type-safe Error Handling');
console.log('============================');

try {
    // This should work fine
    const validKey: Buffer = StreamEncryption.generateKey();
    const validCipher: StreamEncryption = new StreamEncryption(validKey);
    
    const testData: Buffer = Buffer.from('Test data', 'utf8');
    const encrypted: Buffer = validCipher.encryptChunk(testData);
    const decrypted: Buffer = validCipher.decryptChunk(encrypted);
    
    console.log('✅ Valid operations completed successfully');
    console.log(`Original: "${testData.toString('utf8')}"`);
    console.log(`Decrypted: "${decrypted.toString('utf8')}"`);
    
} catch (error: unknown) {
    if (error instanceof Error) {
        console.error('❌ Error occurred:', error.message);
    } else {
        console.error('❌ Unknown error occurred');
    }
}

// Example 3: Type-safe Reset Functionality
console.log('\n\n3. Type-safe Reset Functionality');
console.log('=================================');

const resetKey: Buffer = StreamEncryption.generateKey();
const resetCipher: StreamEncryption = new StreamEncryption(resetKey);

// Encrypt some data
const beforeResetData: Buffer = Buffer.from('Before reset', 'utf8');
resetCipher.encryptChunk(beforeResetData);
resetCipher.encryptChunk(beforeResetData);

const counterBeforeReset: number = resetCipher.getNonceCounter();
console.log(`Counter before reset: ${counterBeforeReset}`);

// Reset with proper typing
resetCipher.reset();

const counterAfterReset: number = resetCipher.getNonceCounter();
console.log(`Counter after reset: ${counterAfterReset}`);

// Verify functionality after reset
const afterResetData: Buffer = Buffer.from('After reset', 'utf8');
const afterResetEncrypted: Buffer = resetCipher.encryptChunk(afterResetData);
const afterResetDecrypted: Buffer = resetCipher.decryptChunk(afterResetEncrypted);

console.log(`Data after reset: "${afterResetDecrypted.toString('utf8')}"`);

// Example 4: Type-safe Streaming Interface
console.log('\n\n4. Type-safe Streaming Interface');
console.log('=================================');

interface StreamProcessor {
    cipher: StreamEncryption;
    processChunk(data: Buffer): Buffer;
    getStats(): { processed: number; nonceCounter: number };
}

class SecureStreamProcessor implements StreamProcessor {
    public cipher: StreamEncryption;
    private processedChunks: number = 0;

    constructor(key: Buffer) {
        this.cipher = new StreamEncryption(key);
    }

    processChunk(data: Buffer): Buffer {
        const encrypted: Buffer = this.cipher.encryptChunk(data);
        this.processedChunks++;
        return encrypted;
    }

    getStats(): { processed: number; nonceCounter: number } {
        return {
            processed: this.processedChunks,
            nonceCounter: this.cipher.getNonceCounter()
        };
    }
}

// Use the type-safe streaming processor
const processorKey: Buffer = StreamEncryption.generateKey();
const processor: StreamProcessor = new SecureStreamProcessor(processorKey);

const streamData: string[] = [
    'Stream chunk 1',
    'Stream chunk 2', 
    'Stream chunk 3'
];

console.log('Processing stream data:');
const processedResults: Buffer[] = [];

for (const data of streamData) {
    const chunk: Buffer = Buffer.from(data, 'utf8');
    const result: Buffer = processor.processChunk(chunk);
    processedResults.push(result);
    console.log(`Processed: "${data}" -> ${result.length} bytes`);
}

const stats: { processed: number; nonceCounter: number } = processor.getStats();
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
