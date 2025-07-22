#!/usr/bin/env node

/**
 * Comprehensive Stream Cipher Benchmark
 * 
 * This consolidated benchmark combines all stream cipher performance tests:
 * - Basic LibSilver StreamCipher performance
 * - LibSilver vs Node.js crypto comparison
 * - Streaming vs chunk-based processing comparison
 * - Memory usage analysis
 * - Large file processing benchmarks
 */

const crypto = require('crypto');
const { StreamCipherJs } = require('../native.js');
const { Transform } = require('stream');
const fs = require('fs');
const path = require('path');

console.log('🚀 LibSilver Comprehensive Stream Cipher Benchmark Suite\n');
console.log('=' .repeat(80));

// Configuration
const CHUNK_SIZES = [1024, 16384, 65536, 262144, 1048576]; // 1KB to 1MB
const ITERATIONS = 100;
const LARGE_FILE_SIZE = 16 * 1024 * 1024; // 16MB
const STREAMING_CHUNK_SIZE = 64 * 1024; // 64KB chunks for streaming

// Helper functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatTime(ms) {
    if (ms < 1) return (ms * 1000).toFixed(2) + ' μs';
    if (ms < 1000) return ms.toFixed(2) + ' ms';
    return (ms / 1000).toFixed(2) + ' s';
}

function calculateThroughput(bytes, timeMs) {
    const bytesPerSecond = (bytes / timeMs) * 1000;
    return formatBytes(bytesPerSecond) + '/s';
}

function generateTestData(size) {
    return Buffer.alloc(size, 'A');
}

function getMemoryUsage() {
    const usage = process.memoryUsage();
    return {
        rss: formatBytes(usage.rss),
        heapUsed: formatBytes(usage.heapUsed),
        heapTotal: formatBytes(usage.heapTotal),
        external: formatBytes(usage.external)
    };
}

// 1. Basic LibSilver Stream Cipher Performance Test
function benchmarkBasicStreamCipher() {
    console.log('📊 1. Basic LibSilver Stream Cipher Performance');
    console.log('-'.repeat(50));
    
    const testConfigs = [
        { size: 64 * 1024, chunks: 16, name: '64KB in 16 chunks (4KB each)' },
        { size: 256 * 1024, chunks: 16, name: '256KB in 16 chunks (16KB each)' },
        { size: 1024 * 1024, chunks: 16, name: '1MB in 16 chunks (64KB each)' }
    ];
    
    const results = [];
    
    for (const config of testConfigs) {
        const key = StreamCipherJs.generateKey();
        const cipher = new StreamCipherJs(key);
        
        const chunkSize = Math.floor(config.size / config.chunks);
        const testData = Buffer.alloc(chunkSize, 'A');
        
        // Encryption test
        const encryptStart = process.hrtime.bigint();
        const ciphertexts = [];
        
        for (let i = 0; i < config.chunks; i++) {
            ciphertexts.push(cipher.encryptChunk(testData));
        }
        
        const encryptEnd = process.hrtime.bigint();
        const encryptTime = Number(encryptEnd - encryptStart) / 1000000;
        
        // Decryption test
        const decryptStart = process.hrtime.bigint();
        
        for (const ciphertext of ciphertexts) {
            cipher.decryptChunk(ciphertext);
        }
        
        const decryptEnd = process.hrtime.bigint();
        const decryptTime = Number(decryptEnd - decryptStart) / 1000000;
        
        const result = {
            name: config.name,
            size: config.size,
            chunks: config.chunks,
            encryptTime,
            decryptTime,
            totalTime: encryptTime + decryptTime,
            encryptThroughput: calculateThroughput(config.size, encryptTime),
            decryptThroughput: calculateThroughput(config.size, decryptTime)
        };
        
        results.push(result);
        
        console.log(`${config.name}:`);
        console.log(`  Encrypt: ${formatTime(encryptTime)} (${result.encryptThroughput})`);
        console.log(`  Decrypt: ${formatTime(decryptTime)} (${result.decryptThroughput})`);
        console.log(`  Total:   ${formatTime(result.totalTime)}`);
        console.log(`  Nonce Counter: ${cipher.getNonceCounter()}`);
        console.log();
    }
    
    return results;
}

// 2. LibSilver vs Node.js Crypto Comparison
function benchmarkLibSilverVsNodeJS() {
    console.log('📊 2. LibSilver vs Node.js Crypto Comparison');
    console.log('-'.repeat(50));
    
    const results = [];
    
    for (const chunkSize of CHUNK_SIZES) {
        const testData = generateTestData(chunkSize);
        
        // LibSilver benchmark
        const libsilverKey = StreamCipherJs.generateKey();
        const libsilverCipher = new StreamCipherJs(libsilverKey);
        
        // Warmup
        for (let i = 0; i < 10; i++) {
            const ciphertext = libsilverCipher.encryptChunk(testData);
            libsilverCipher.decryptChunk(ciphertext);
        }
        libsilverCipher.reset();
        
        // LibSilver encryption benchmark
        const libsilverEncryptStart = process.hrtime.bigint();
        const libsilverCiphertexts = [];
        
        for (let i = 0; i < ITERATIONS; i++) {
            libsilverCiphertexts.push(libsilverCipher.encryptChunk(testData));
        }
        
        const libsilverEncryptEnd = process.hrtime.bigint();
        const libsilverEncryptTime = Number(libsilverEncryptEnd - libsilverEncryptStart) / 1000000;
        
        // LibSilver decryption benchmark
        const libsilverDecryptStart = process.hrtime.bigint();
        
        for (let i = 0; i < ITERATIONS; i++) {
            libsilverCipher.decryptChunk(libsilverCiphertexts[i]);
        }
        
        const libsilverDecryptEnd = process.hrtime.bigint();
        const libsilverDecryptTime = Number(libsilverDecryptEnd - libsilverDecryptStart) / 1000000;
        
        // Node.js crypto benchmark
        const nodejsKey = crypto.randomBytes(32);
        
        // Node.js encryption benchmark
        const nodejsEncryptStart = process.hrtime.bigint();
        const nodejsCiphertexts = [];
        
        for (let i = 0; i < ITERATIONS; i++) {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', nodejsKey, iv);
            
            let encrypted = cipher.update(testData);
            encrypted = Buffer.concat([encrypted, cipher.final()]);
            const tag = cipher.getAuthTag();
            
            nodejsCiphertexts.push(Buffer.concat([iv, encrypted, tag]));
        }
        
        const nodejsEncryptEnd = process.hrtime.bigint();
        const nodejsEncryptTime = Number(nodejsEncryptEnd - nodejsEncryptStart) / 1000000;
        
        // Node.js decryption benchmark
        const nodejsDecryptStart = process.hrtime.bigint();
        
        for (const ciphertext of nodejsCiphertexts) {
            const iv = ciphertext.slice(0, 12);
            const tag = ciphertext.slice(-16);
            const encrypted = ciphertext.slice(12, -16);
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', nodejsKey, iv);
            decipher.setAuthTag(tag);
            
            let decrypted = decipher.update(encrypted);
            decipher.final();
        }
        
        const nodejsDecryptEnd = process.hrtime.bigint();
        const nodejsDecryptTime = Number(nodejsDecryptEnd - nodejsDecryptStart) / 1000000;
        
        const totalDataSize = chunkSize * ITERATIONS;
        
        const result = {
            chunkSize: formatBytes(chunkSize),
            libsilver: {
                encryptTime: libsilverEncryptTime,
                decryptTime: libsilverDecryptTime,
                totalTime: libsilverEncryptTime + libsilverDecryptTime,
                encryptThroughput: calculateThroughput(totalDataSize, libsilverEncryptTime),
                decryptThroughput: calculateThroughput(totalDataSize, libsilverDecryptTime)
            },
            nodejs: {
                encryptTime: nodejsEncryptTime,
                decryptTime: nodejsDecryptTime,
                totalTime: nodejsEncryptTime + nodejsDecryptTime,
                encryptThroughput: calculateThroughput(totalDataSize, nodejsEncryptTime),
                decryptThroughput: calculateThroughput(totalDataSize, nodejsDecryptTime)
            }
        };
        
        results.push(result);
        
        console.log(`Chunk Size: ${result.chunkSize} (${ITERATIONS} iterations)`);
        console.log(`  LibSilver - Encrypt: ${formatTime(result.libsilver.encryptTime)} (${result.libsilver.encryptThroughput})`);
        console.log(`  LibSilver - Decrypt: ${formatTime(result.libsilver.decryptTime)} (${result.libsilver.decryptThroughput})`);
        console.log(`  Node.js   - Encrypt: ${formatTime(result.nodejs.encryptTime)} (${result.nodejs.encryptThroughput})`);
        console.log(`  Node.js   - Decrypt: ${formatTime(result.nodejs.decryptTime)} (${result.nodejs.decryptThroughput})`);
        
        const encryptSpeedup = result.nodejs.encryptTime / result.libsilver.encryptTime;
        const decryptSpeedup = result.nodejs.decryptTime / result.libsilver.decryptTime;
        
        console.log(`  Speedup   - Encrypt: ${encryptSpeedup.toFixed(2)}x, Decrypt: ${decryptSpeedup.toFixed(2)}x`);
        console.log();
    }
    
    return results;
}

// 3. Streaming vs Chunk-based Processing Comparison
function benchmarkStreamingComparison() {
    console.log('📊 3. Streaming vs Chunk-based Processing Comparison');
    console.log('-'.repeat(50));

    const largeData = generateTestData(LARGE_FILE_SIZE);
    const results = {};

    // LibSilver chunk-based processing
    const libsilverKey = StreamCipherJs.generateKey();
    const libsilverCipher = new StreamCipherJs(libsilverKey);

    const libsilverStart = process.hrtime.bigint();
    const libsilverChunks = [];

    for (let i = 0; i < largeData.length; i += STREAMING_CHUNK_SIZE) {
        const chunk = largeData.slice(i, i + STREAMING_CHUNK_SIZE);
        const encrypted = libsilverCipher.encryptChunk(chunk);
        libsilverChunks.push(encrypted);
    }

    const libsilverEncryptEnd = process.hrtime.bigint();
    const libsilverEncryptTime = Number(libsilverEncryptEnd - libsilverStart) / 1000000;

    // Decrypt LibSilver chunks
    const libsilverDecryptStart = process.hrtime.bigint();
    const libsilverDecrypted = [];

    for (const chunk of libsilverChunks) {
        libsilverDecrypted.push(libsilverCipher.decryptChunk(chunk));
    }

    const libsilverDecryptEnd = process.hrtime.bigint();
    const libsilverDecryptTime = Number(libsilverDecryptEnd - libsilverDecryptStart) / 1000000;

    results.libsilver = {
        encryptTime: libsilverEncryptTime,
        decryptTime: libsilverDecryptTime,
        totalTime: libsilverEncryptTime + libsilverDecryptTime,
        encryptThroughput: calculateThroughput(LARGE_FILE_SIZE, libsilverEncryptTime),
        decryptThroughput: calculateThroughput(LARGE_FILE_SIZE, libsilverDecryptTime),
        chunks: libsilverChunks.length
    };

    // Node.js streaming approach
    const nodejsKey = crypto.randomBytes(32);

    const nodejsStart = process.hrtime.bigint();
    const nodejsChunks = [];

    for (let i = 0; i < largeData.length; i += STREAMING_CHUNK_SIZE) {
        const chunk = largeData.slice(i, i + STREAMING_CHUNK_SIZE);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', nodejsKey, iv);

        let encrypted = cipher.update(chunk);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const tag = cipher.getAuthTag();

        nodejsChunks.push(Buffer.concat([iv, encrypted, tag]));
    }

    const nodejsEncryptEnd = process.hrtime.bigint();
    const nodejsEncryptTime = Number(nodejsEncryptEnd - nodejsStart) / 1000000;

    // Decrypt Node.js chunks
    const nodejsDecryptStart = process.hrtime.bigint();

    for (const ciphertext of nodejsChunks) {
        const iv = ciphertext.slice(0, 12);
        const tag = ciphertext.slice(-16);
        const encrypted = ciphertext.slice(12, -16);

        const decipher = crypto.createDecipheriv('aes-256-gcm', nodejsKey, iv);
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(encrypted);
        decipher.final();
    }

    const nodejsDecryptEnd = process.hrtime.bigint();
    const nodejsDecryptTime = Number(nodejsDecryptEnd - nodejsDecryptStart) / 1000000;

    results.nodejs = {
        encryptTime: nodejsEncryptTime,
        decryptTime: nodejsDecryptTime,
        totalTime: nodejsEncryptTime + nodejsDecryptTime,
        encryptThroughput: calculateThroughput(LARGE_FILE_SIZE, nodejsEncryptTime),
        decryptThroughput: calculateThroughput(LARGE_FILE_SIZE, nodejsDecryptTime),
        chunks: nodejsChunks.length
    };

    console.log(`Large File Processing (${formatBytes(LARGE_FILE_SIZE)} in ${formatBytes(STREAMING_CHUNK_SIZE)} chunks):`);
    console.log(`  LibSilver - Encrypt: ${formatTime(results.libsilver.encryptTime)} (${results.libsilver.encryptThroughput})`);
    console.log(`  LibSilver - Decrypt: ${formatTime(results.libsilver.decryptTime)} (${results.libsilver.decryptThroughput})`);
    console.log(`  LibSilver - Total:   ${formatTime(results.libsilver.totalTime)}`);
    console.log(`  LibSilver - Chunks:  ${results.libsilver.chunks}`);
    console.log();
    console.log(`  Node.js   - Encrypt: ${formatTime(results.nodejs.encryptTime)} (${results.nodejs.encryptThroughput})`);
    console.log(`  Node.js   - Decrypt: ${formatTime(results.nodejs.decryptTime)} (${results.nodejs.decryptThroughput})`);
    console.log(`  Node.js   - Total:   ${formatTime(results.nodejs.totalTime)}`);
    console.log(`  Node.js   - Chunks:  ${results.nodejs.chunks}`);
    console.log();

    const encryptSpeedup = results.nodejs.encryptTime / results.libsilver.encryptTime;
    const decryptSpeedup = results.nodejs.decryptTime / results.libsilver.decryptTime;

    console.log(`  Performance Comparison:`);
    console.log(`    Encrypt Speedup: ${encryptSpeedup.toFixed(2)}x ${encryptSpeedup > 1 ? '(LibSilver faster)' : '(Node.js faster)'}`);
    console.log(`    Decrypt Speedup: ${decryptSpeedup.toFixed(2)}x ${decryptSpeedup > 1 ? '(LibSilver faster)' : '(Node.js faster)'}`);
    console.log();

    return results;
}

// 4. Memory Usage Analysis
function benchmarkMemoryUsage() {
    console.log('📊 4. Memory Usage Analysis');
    console.log('-'.repeat(50));

    const initialMemory = getMemoryUsage();
    console.log('Initial Memory Usage:');
    console.log(`  RSS: ${initialMemory.rss}, Heap Used: ${initialMemory.heapUsed}`);
    console.log(`  Heap Total: ${initialMemory.heapTotal}, External: ${initialMemory.external}`);
    console.log();

    // Test with different data sizes
    const testSizes = [1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024]; // 1MB, 4MB, 8MB

    for (const size of testSizes) {
        console.log(`Testing with ${formatBytes(size)} data:`);

        const testData = generateTestData(size);
        const key = StreamCipherJs.generateKey();
        const cipher = new StreamCipherJs(key);

        const beforeEncrypt = getMemoryUsage();

        // Encrypt in chunks
        const chunkSize = 64 * 1024; // 64KB chunks
        const encryptedChunks = [];

        for (let i = 0; i < testData.length; i += chunkSize) {
            const chunk = testData.slice(i, i + chunkSize);
            encryptedChunks.push(cipher.encryptChunk(chunk));
        }

        const afterEncrypt = getMemoryUsage();

        // Decrypt chunks
        for (const chunk of encryptedChunks) {
            cipher.decryptChunk(chunk);
        }

        const afterDecrypt = getMemoryUsage();

        console.log(`  Before: RSS ${beforeEncrypt.rss}, Heap ${beforeEncrypt.heapUsed}`);
        console.log(`  After Encrypt: RSS ${afterEncrypt.rss}, Heap ${afterEncrypt.heapUsed}`);
        console.log(`  After Decrypt: RSS ${afterDecrypt.rss}, Heap ${afterDecrypt.heapUsed}`);
        console.log();

        // Force garbage collection if available
        if (global.gc) {
            global.gc();
        }
    }

    const finalMemory = getMemoryUsage();
    console.log('Final Memory Usage:');
    console.log(`  RSS: ${finalMemory.rss}, Heap Used: ${finalMemory.heapUsed}`);
    console.log(`  Heap Total: ${finalMemory.heapTotal}, External: ${finalMemory.external}`);
    console.log();
}

// 5. Generate Performance Report
function generatePerformanceReport(basicResults, comparisonResults, streamingResults) {
    console.log('📊 5. Performance Report Summary');
    console.log('-'.repeat(50));

    // Basic performance summary
    console.log('Basic Stream Cipher Performance:');
    for (const result of basicResults) {
        console.log(`  ${result.name}: ${formatTime(result.totalTime)} total`);
    }
    console.log();

    // Comparison summary
    console.log('LibSilver vs Node.js Comparison (Average Speedup):');
    let totalEncryptSpeedup = 0;
    let totalDecryptSpeedup = 0;

    for (const result of comparisonResults) {
        const encryptSpeedup = result.nodejs.encryptTime / result.libsilver.encryptTime;
        const decryptSpeedup = result.nodejs.decryptTime / result.libsilver.decryptTime;
        totalEncryptSpeedup += encryptSpeedup;
        totalDecryptSpeedup += decryptSpeedup;
    }

    const avgEncryptSpeedup = totalEncryptSpeedup / comparisonResults.length;
    const avgDecryptSpeedup = totalDecryptSpeedup / comparisonResults.length;

    console.log(`  Average Encrypt Speedup: ${avgEncryptSpeedup.toFixed(2)}x`);
    console.log(`  Average Decrypt Speedup: ${avgDecryptSpeedup.toFixed(2)}x`);
    console.log();

    // Streaming performance summary
    console.log('Large File Streaming Performance:');
    console.log(`  LibSilver Total: ${formatTime(streamingResults.libsilver.totalTime)}`);
    console.log(`  Node.js Total:   ${formatTime(streamingResults.nodejs.totalTime)}`);

    const streamingSpeedup = streamingResults.nodejs.totalTime / streamingResults.libsilver.totalTime;
    console.log(`  Overall Speedup: ${streamingSpeedup.toFixed(2)}x`);
    console.log();

    // Save results to JSON file
    const reportData = {
        timestamp: new Date().toISOString(),
        basic: basicResults,
        comparison: comparisonResults,
        streaming: streamingResults,
        summary: {
            avgEncryptSpeedup,
            avgDecryptSpeedup,
            streamingSpeedup
        }
    };

    const reportPath = path.join(__dirname, 'comprehensive-stream-benchmark-results.json');
    fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2));
    console.log(`📄 Detailed results saved to: ${reportPath}`);
    console.log();

    return reportData;
}

// Main execution function
async function runComprehensiveBenchmark() {
    console.log('🚀 Starting Comprehensive Stream Cipher Benchmark Suite...\n');

    const startTime = process.hrtime.bigint();

    try {
        // Run all benchmark categories
        const basicResults = benchmarkBasicStreamCipher();
        console.log();

        const comparisonResults = benchmarkLibSilverVsNodeJS();
        console.log();

        const streamingResults = benchmarkStreamingComparison();
        console.log();

        benchmarkMemoryUsage();
        console.log();

        const report = generatePerformanceReport(basicResults, comparisonResults, streamingResults);

        const endTime = process.hrtime.bigint();
        const totalTime = Number(endTime - startTime) / 1000000;

        console.log('=' .repeat(80));
        console.log('🎉 Comprehensive Stream Cipher Benchmark Complete!');
        console.log(`⏱️  Total benchmark time: ${formatTime(totalTime)}`);
        console.log('=' .repeat(80));

        // Print key findings
        console.log('\n🔍 Key Findings:');
        if (report.summary.avgEncryptSpeedup > 1) {
            console.log(`✅ LibSilver is ${report.summary.avgEncryptSpeedup.toFixed(2)}x faster at encryption on average`);
        } else {
            console.log(`⚠️  Node.js is ${(1/report.summary.avgEncryptSpeedup).toFixed(2)}x faster at encryption on average`);
        }

        if (report.summary.avgDecryptSpeedup > 1) {
            console.log(`✅ LibSilver is ${report.summary.avgDecryptSpeedup.toFixed(2)}x faster at decryption on average`);
        } else {
            console.log(`⚠️  Node.js is ${(1/report.summary.avgDecryptSpeedup).toFixed(2)}x faster at decryption on average`);
        }

        if (report.summary.streamingSpeedup > 1) {
            console.log(`✅ LibSilver is ${report.summary.streamingSpeedup.toFixed(2)}x faster for large file streaming`);
        } else {
            console.log(`⚠️  Node.js is ${(1/report.summary.streamingSpeedup).toFixed(2)}x faster for large file streaming`);
        }

        console.log('\n💡 Recommendations:');
        console.log('   • Use LibSilver StreamCipher for stateful encryption with automatic nonce management');
        console.log('   • Consider chunk size optimization based on your use case');
        console.log('   • Monitor memory usage for large file processing');
        console.log('   • Use reset() method when nonce counter approaches overflow');

    } catch (error) {
        console.error('❌ Benchmark failed:', error.message);
        process.exit(1);
    }
}

// Run the benchmark if this file is executed directly
if (require.main === module) {
    runComprehensiveBenchmark();
}

module.exports = {
    runComprehensiveBenchmark,
    benchmarkBasicStreamCipher,
    benchmarkLibSilverVsNodeJS,
    benchmarkStreamingComparison,
    benchmarkMemoryUsage,
    generatePerformanceReport
};
