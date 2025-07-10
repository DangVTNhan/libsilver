#!/usr/bin/env node

/**
 * Benchmark comparing preloaded vs non-preloaded LibSilver performance
 */

import Benchmark from 'benchmark';
import crypto from 'crypto';
import { SymmetricCrypto } from 'libsilver-nodejs';
import { preloadedCrypto } from '../src/preloaded-crypto.js';

// Test configuration
const DATA_SIZES = [
  { name: '1KB', size: 1024 },
  { name: '4KB', size: 4096 },
  { name: '16KB', size: 16384 }
];

const NUM_KEYS = 5; // Number of different keys to test with

// Generate test data
function generateTestData(size) {
  return crypto.randomBytes(size);
}

// Generate test keys
function generateTestKeys(count) {
  const aesKeys = [];
  const chachaKeys = [];
  
  for (let i = 0; i < count; i++) {
    aesKeys.push(SymmetricCrypto.generateAesKey());
    chachaKeys.push(SymmetricCrypto.generateChacha20Key());
  }
  
  return { aesKeys, chachaKeys };
}

// Node.js native crypto for comparison
class NodeCrypto {
  static encryptAES(plaintext, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([iv, encrypted, tag]);
  }
  
  static decryptAES(ciphertext, key) {
    const iv = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(-16);
    const encrypted = ciphertext.slice(12, -16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encrypted);
    decipher.final();
    
    return decrypted;
  }
}

async function runPreloadBenchmarks() {
  console.log('🚀 LibSilver Preloaded vs Standard Performance Benchmark\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('\n' + '='.repeat(80) + '\n');

  // Generate test keys and data
  const { aesKeys, chachaKeys } = generateTestKeys(NUM_KEYS);
  
  // Preload ciphers
  console.log('🔥 Preloading cipher instances...');
  await preloadedCrypto.preloadCiphers(aesKeys, chachaKeys);
  console.log('✅ Preloading complete\n');

  for (const dataSize of DATA_SIZES) {
    console.log(`📊 Benchmarking ${dataSize.name} (${dataSize.size.toLocaleString()} bytes)\n`);
    
    const plaintext = generateTestData(dataSize.size);
    const testKey = aesKeys[0]; // Use first key for consistency
    
    // Pre-encrypt data for decryption benchmarks
    const nodeAESCiphertext = NodeCrypto.encryptAES(plaintext, testKey);
    const standardCiphertext = SymmetricCrypto.encryptAes(plaintext, testKey);
    const preloadedCiphertext = preloadedCrypto.encryptAES(plaintext, testKey);

    const suite = new Benchmark.Suite();

    // AES-256-GCM Encryption Benchmarks
    suite
      .add(`Node.js Native AES Encrypt (${dataSize.name})`, function() {
        NodeCrypto.encryptAES(plaintext, testKey);
      })
      .add(`LibSilver Standard AES Encrypt (${dataSize.name})`, function() {
        SymmetricCrypto.encryptAes(plaintext, testKey);
      })
      .add(`LibSilver Preloaded AES Encrypt (${dataSize.name})`, function() {
        preloadedCrypto.encryptAES(plaintext, testKey);
      })
      .add(`LibSilver Cached AES Encrypt (${dataSize.name})`, function() {
        SymmetricCrypto.encryptAesCached(plaintext, testKey);
      })

      // AES-256-GCM Decryption Benchmarks
      .add(`Node.js Native AES Decrypt (${dataSize.name})`, function() {
        NodeCrypto.decryptAES(nodeAESCiphertext, testKey);
      })
      .add(`LibSilver Standard AES Decrypt (${dataSize.name})`, function() {
        SymmetricCrypto.decryptAes(standardCiphertext, testKey);
      })
      .add(`LibSilver Preloaded AES Decrypt (${dataSize.name})`, function() {
        preloadedCrypto.decryptAES(preloadedCiphertext, testKey);
      })
      .add(`LibSilver Cached AES Decrypt (${dataSize.name})`, function() {
        SymmetricCrypto.decryptAesCached(preloadedCiphertext, testKey);
      })

      .on('cycle', function(event) {
        const benchmark = event.target;
        const opsPerSec = benchmark.hz.toFixed(2);
        const throughputMBps = ((dataSize.size * benchmark.hz) / (1024 * 1024)).toFixed(2);
        console.log(`  ${benchmark.name}: ${opsPerSec} ops/sec (${throughputMBps} MB/s)`);
      })
      .on('complete', function() {
        console.log('\n' + '-'.repeat(60) + '\n');
      })
      .run({ 'async': false });
  }

  // Batch operation benchmarks
  console.log('📦 Batch Operation Benchmarks\n');
  
  const batchSize = 100;
  const batchData = Array(batchSize).fill().map(() => generateTestData(1024));
  const batchKey = aesKeys[0];
  
  const batchSuite = new Benchmark.Suite();
  
  batchSuite
    .add(`LibSilver Standard Batch Encrypt (${batchSize} x 1KB)`, function() {
      batchData.forEach(data => SymmetricCrypto.encryptAes(data, batchKey));
    })
    .add(`LibSilver Preloaded Batch Encrypt (${batchSize} x 1KB)`, function() {
      preloadedCrypto.encryptBatch(batchData, batchKey, 'aes');
    })
    .add(`LibSilver Cached Individual Encrypt (${batchSize} x 1KB)`, function() {
      batchData.forEach(data => SymmetricCrypto.encryptAesCached(data, batchKey));
    })
    
    .on('cycle', function(event) {
      const benchmark = event.target;
      const opsPerSec = benchmark.hz.toFixed(2);
      const totalThroughputMBps = ((1024 * batchSize * benchmark.hz) / (1024 * 1024)).toFixed(2);
      console.log(`  ${benchmark.name}: ${opsPerSec} ops/sec (${totalThroughputMBps} MB/s total)`);
    })
    .on('complete', function() {
      console.log('\n');
    })
    .run({ 'async': false });

  // Performance statistics
  console.log('📈 Performance Statistics\n');
  const stats = preloadedCrypto.getStats();
  console.log('Cache Hit Rate:', (stats.cacheHitRate * 100).toFixed(2) + '%');
  console.log('Cache Hits:', stats.cacheHits);
  console.log('Cache Misses:', stats.cacheMisses);
  console.log('Preloaded Ciphers:', stats.preloadedCiphers);
  console.log('Native Cache Info:', stats.nativeCacheInfo);
  
  console.log('\n✅ Preload benchmark completed!\n');
}

// Multi-key performance test
async function runMultiKeyTest() {
  console.log('🔑 Multi-Key Performance Test\n');
  
  const numKeys = 20;
  const { aesKeys } = generateTestKeys(numKeys);
  const plaintext = generateTestData(4096); // 4KB test data
  
  console.log(`Testing with ${numKeys} different keys...`);
  
  // Test without preloading
  console.time('Standard (no preload)');
  for (let i = 0; i < 100; i++) {
    const key = aesKeys[i % numKeys];
    SymmetricCrypto.encryptAes(plaintext, key);
  }
  console.timeEnd('Standard (no preload)');
  
  // Test with preloading
  await preloadedCrypto.preloadCiphers(aesKeys, []);
  console.time('Preloaded');
  for (let i = 0; i < 100; i++) {
    const key = aesKeys[i % numKeys];
    preloadedCrypto.encryptAES(plaintext, key);
  }
  console.timeEnd('Preloaded');
  
  const stats = preloadedCrypto.getStats();
  console.log(`Cache hit rate: ${(stats.cacheHitRate * 100).toFixed(2)}%\n`);
}

// Run all benchmarks
async function main() {
  try {
    await runPreloadBenchmarks();
    await runMultiKeyTest();
  } catch (error) {
    console.error('Benchmark failed:', error);
    process.exit(1);
  }
}

main();
