#!/usr/bin/env node

import crypto from 'crypto';
import { gcm } from '@noble/ciphers/aes';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { SymmetricCrypto } from 'libsilver-nodejs';

// Memory measurement utilities
function getMemoryUsage() {
  const usage = process.memoryUsage();
  return {
    rss: usage.rss,
    heapUsed: usage.heapUsed,
    heapTotal: usage.heapTotal,
    external: usage.external
  };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function measureMemory(name, fn, iterations = 1000) {
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
  
  const startMemory = getMemoryUsage();
  const startTime = process.hrtime.bigint();
  
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  
  const endTime = process.hrtime.bigint();
  const endMemory = getMemoryUsage();
  
  // Force garbage collection again
  if (global.gc) {
    global.gc();
  }
  
  const afterGCMemory = getMemoryUsage();
  
  const memoryDelta = {
    rss: endMemory.rss - startMemory.rss,
    heapUsed: endMemory.heapUsed - startMemory.heapUsed,
    heapTotal: endMemory.heapTotal - startMemory.heapTotal,
    external: endMemory.external - startMemory.external
  };
  
  const memoryAfterGC = {
    rss: afterGCMemory.rss - startMemory.rss,
    heapUsed: afterGCMemory.heapUsed - startMemory.heapUsed,
    heapTotal: afterGCMemory.heapTotal - startMemory.heapTotal,
    external: afterGCMemory.external - startMemory.external
  };
  
  const executionTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds
  
  return {
    name,
    iterations,
    executionTime,
    memoryDelta,
    memoryAfterGC,
    avgTimePerOp: executionTime / iterations
  };
}

// Test implementations
const TEST_DATA_SIZE = 64 * 1024; // 64KB
const ITERATIONS = 1000;

function runMemoryBenchmarks() {
  console.log('🧠 Memory Usage Benchmark\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('Test Data Size:', formatBytes(TEST_DATA_SIZE));
  console.log('Iterations:', ITERATIONS);
  console.log('GC Available:', !!global.gc);
  console.log('\n' + '='.repeat(80) + '\n');

  const plaintext = crypto.randomBytes(TEST_DATA_SIZE);
  const aesKey = crypto.randomBytes(32);
  const chachaKey = crypto.randomBytes(32);

  // AES-256-GCM Encryption Memory Tests
  console.log('📊 AES-256-GCM Encryption Memory Usage:\n');

  const nodeAESEncrypt = measureMemory('Node.js AES-256-GCM Encrypt', () => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    let encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }, ITERATIONS);

  const nobleAESEncrypt = measureMemory('@noble/ciphers AES-256-GCM Encrypt', () => {
    const nonce = crypto.randomBytes(12);
    const aes = gcm(aesKey, nonce);
    const encrypted = aes.encrypt(plaintext);
    return Buffer.concat([nonce, encrypted]);
  }, ITERATIONS);

  const libsilverAESEncrypt = measureMemory('LibSilver AES-256-GCM Encrypt', () => {
    return SymmetricCrypto.encryptAes(plaintext, aesKey);
  }, ITERATIONS);

  printMemoryResults([nodeAESEncrypt, nobleAESEncrypt, libsilverAESEncrypt]);

  // ChaCha20-Poly1305 Encryption Memory Tests
  console.log('\n📊 ChaCha20-Poly1305 Encryption Memory Usage:\n');

  const nodeChaChaEncrypt = measureMemory('Node.js ChaCha20-Poly1305 Encrypt', () => {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('chacha20-poly1305', chachaKey, nonce);
    let encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, encrypted, tag]);
  }, ITERATIONS);

  const nobleChaChaEncrypt = measureMemory('@noble/ciphers ChaCha20-Poly1305 Encrypt', () => {
    const nonce = crypto.randomBytes(12);
    const chacha = chacha20poly1305(chachaKey, nonce);
    const encrypted = chacha.encrypt(plaintext);
    return Buffer.concat([nonce, encrypted]);
  }, ITERATIONS);

  const libsilverChaChaEncrypt = measureMemory('LibSilver ChaCha20-Poly1305 Encrypt', () => {
    return SymmetricCrypto.encryptChacha20(plaintext, chachaKey);
  }, ITERATIONS);

  printMemoryResults([nodeChaChaEncrypt, nobleChaChaEncrypt, libsilverChaChaEncrypt]);

  // Memory efficiency comparison
  console.log('\n📈 Memory Efficiency Summary:\n');
  
  const results = [
    { name: 'AES-256-GCM', node: nodeAESEncrypt, noble: nobleAESEncrypt, libsilver: libsilverAESEncrypt },
    { name: 'ChaCha20-Poly1305', node: nodeChaChaEncrypt, noble: nobleChaChaEncrypt, libsilver: libsilverChaChaEncrypt }
  ];

  for (const result of results) {
    console.log(`${result.name}:`);
    console.log(`  Memory per operation (after GC):`);
    console.log(`    Node.js:        ${formatBytes(result.node.memoryAfterGC.heapUsed / ITERATIONS)}`);
    console.log(`    @noble/ciphers: ${formatBytes(result.noble.memoryAfterGC.heapUsed / ITERATIONS)}`);
    console.log(`    LibSilver:      ${formatBytes(result.libsilver.memoryAfterGC.heapUsed / ITERATIONS)}`);
    console.log(`  Time per operation:`);
    console.log(`    Node.js:        ${result.node.avgTimePerOp.toFixed(3)}ms`);
    console.log(`    @noble/ciphers: ${result.noble.avgTimePerOp.toFixed(3)}ms`);
    console.log(`    LibSilver:      ${result.libsilver.avgTimePerOp.toFixed(3)}ms`);
    console.log();
  }

  console.log('✅ Memory benchmark completed!\n');
}

function printMemoryResults(results) {
  for (const result of results) {
    console.log(`${result.name}:`);
    console.log(`  Total execution time: ${result.executionTime.toFixed(2)}ms`);
    console.log(`  Average time per operation: ${result.avgTimePerOp.toFixed(3)}ms`);
    console.log(`  Memory delta (peak):`);
    console.log(`    RSS: ${formatBytes(result.memoryDelta.rss)}`);
    console.log(`    Heap Used: ${formatBytes(result.memoryDelta.heapUsed)}`);
    console.log(`    External: ${formatBytes(result.memoryDelta.external)}`);
    console.log(`  Memory delta (after GC):`);
    console.log(`    RSS: ${formatBytes(result.memoryAfterGC.rss)}`);
    console.log(`    Heap Used: ${formatBytes(result.memoryAfterGC.heapUsed)}`);
    console.log(`    External: ${formatBytes(result.memoryAfterGC.external)}`);
    console.log();
  }
}

// Run memory benchmarks
runMemoryBenchmarks();
