#!/usr/bin/env node

import crypto from 'crypto';
import { gcm } from '@noble/ciphers/aes';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { SymmetricCrypto } from 'libsilver-nodejs';

// Detailed analysis with statistical measurements
class BenchmarkAnalysis {
  constructor() {
    this.results = [];
  }

  // Run multiple iterations and collect statistics
  measurePerformance(name, fn, iterations = 100, warmupIterations = 10) {
    // Warmup
    for (let i = 0; i < warmupIterations; i++) {
      fn();
    }

    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      fn();
      const end = process.hrtime.bigint();
      times.push(Number(end - start) / 1000000); // Convert to milliseconds
    }

    times.sort((a, b) => a - b);
    
    const stats = {
      name,
      iterations,
      min: times[0],
      max: times[times.length - 1],
      mean: times.reduce((a, b) => a + b, 0) / times.length,
      median: times[Math.floor(times.length / 2)],
      p95: times[Math.floor(times.length * 0.95)],
      p99: times[Math.floor(times.length * 0.99)],
      stdDev: this.calculateStdDev(times)
    };

    this.results.push(stats);
    return stats;
  }

  calculateStdDev(values) {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map(value => Math.pow(value - mean, 2));
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(avgSquaredDiff);
  }

  // Test correctness of implementations
  testCorrectness() {
    console.log('🔍 Testing Implementation Correctness\n');
    
    const testData = crypto.randomBytes(1024);
    const aesKey = crypto.randomBytes(32);
    const chachaKey = crypto.randomBytes(32);

    // Test AES-256-GCM
    console.log('Testing AES-256-GCM:');
    
    try {
      // LibSilver
      const libsilverAESCiphertext = SymmetricCrypto.encryptAes(testData, aesKey);
      const libsilverAESDecrypted = SymmetricCrypto.decryptAes(libsilverAESCiphertext, aesKey);
      console.log('  ✅ LibSilver AES-256-GCM: Encrypt/Decrypt successful');
      console.log(`     Ciphertext size: ${libsilverAESCiphertext.length} bytes (overhead: ${libsilverAESCiphertext.length - testData.length} bytes)`);
      
      if (Buffer.compare(testData, libsilverAESDecrypted) === 0) {
        console.log('  ✅ LibSilver AES-256-GCM: Data integrity verified');
      } else {
        console.log('  ❌ LibSilver AES-256-GCM: Data integrity failed');
      }

      // @noble/ciphers
      const nonce = crypto.randomBytes(12);
      const nobleAES = gcm(aesKey, nonce);
      const nobleAESEncrypted = nobleAES.encrypt(testData);
      const nobleAESDecrypted = nobleAES.decrypt(nobleAESEncrypted);
      console.log('  ✅ @noble/ciphers AES-256-GCM: Encrypt/Decrypt successful');
      console.log(`     Ciphertext size: ${nobleAESEncrypted.length} bytes (overhead: ${nobleAESEncrypted.length - testData.length} bytes)`);
      
      if (Buffer.compare(testData, Buffer.from(nobleAESDecrypted)) === 0) {
        console.log('  ✅ @noble/ciphers AES-256-GCM: Data integrity verified');
      } else {
        console.log('  ❌ @noble/ciphers AES-256-GCM: Data integrity failed');
      }

      // Node.js native
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
      let nodeEncrypted = cipher.update(testData);
      cipher.final();
      const tag = cipher.getAuthTag();
      const nodeCiphertext = Buffer.concat([iv, nodeEncrypted, tag]);

      const nodeIV = nodeCiphertext.slice(0, 12);
      const nodeTag = nodeCiphertext.slice(-16);
      const nodeEncryptedData = nodeCiphertext.slice(12, -16);
      const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nodeIV);
      decipher.setAuthTag(nodeTag);
      const nodeDecrypted = decipher.update(nodeEncryptedData);
      decipher.final();
      
      console.log('  ✅ Node.js AES-256-GCM: Encrypt/Decrypt successful');
      console.log(`     Ciphertext size: ${nodeCiphertext.length} bytes (overhead: ${nodeCiphertext.length - testData.length} bytes)`);
      
      if (Buffer.compare(testData, nodeDecrypted) === 0) {
        console.log('  ✅ Node.js AES-256-GCM: Data integrity verified');
      } else {
        console.log('  ❌ Node.js AES-256-GCM: Data integrity failed');
      }

    } catch (error) {
      console.log('  ❌ AES-256-GCM test failed:', error.message);
    }

    console.log('\nTesting ChaCha20-Poly1305:');
    
    try {
      // LibSilver
      const libsilverChaChatext = SymmetricCrypto.encryptChacha20(testData, chachaKey);
      const libsilverChaChaDecrypted = SymmetricCrypto.decryptChacha20(libsilverChaChatext, chachaKey);
      console.log('  ✅ LibSilver ChaCha20-Poly1305: Encrypt/Decrypt successful');
      console.log(`     Ciphertext size: ${libsilverChaChatext.length} bytes (overhead: ${libsilverChaChatext.length - testData.length} bytes)`);
      
      if (Buffer.compare(testData, libsilverChaChaDecrypted) === 0) {
        console.log('  ✅ LibSilver ChaCha20-Poly1305: Data integrity verified');
      } else {
        console.log('  ❌ LibSilver ChaCha20-Poly1305: Data integrity failed');
      }

      // @noble/ciphers
      const chachaNonce = crypto.randomBytes(12);
      const nobleChacha = chacha20poly1305(chachaKey, chachaNonce);
      const nobleChachaEncrypted = nobleChacha.encrypt(testData);
      const nobleChachaDecrypted = nobleChacha.decrypt(nobleChachaEncrypted);
      console.log('  ✅ @noble/ciphers ChaCha20-Poly1305: Encrypt/Decrypt successful');
      console.log(`     Ciphertext size: ${nobleChachaEncrypted.length} bytes (overhead: ${nobleChachaEncrypted.length - testData.length} bytes)`);
      
      if (Buffer.compare(testData, Buffer.from(nobleChachaDecrypted)) === 0) {
        console.log('  ✅ @noble/ciphers ChaCha20-Poly1305: Data integrity verified');
      } else {
        console.log('  ❌ @noble/ciphers ChaCha20-Poly1305: Data integrity failed');
      }

    } catch (error) {
      console.log('  ❌ ChaCha20-Poly1305 test failed:', error.message);
    }

    console.log('\n' + '='.repeat(80) + '\n');
  }

  // Run comprehensive performance analysis
  runAnalysis() {
    console.log('📊 Comprehensive Performance Analysis\n');
    
    const testSizes = [1024, 16384, 65536]; // 1KB, 16KB, 64KB
    
    for (const size of testSizes) {
      console.log(`Testing with ${(size / 1024).toFixed(0)}KB data:\n`);
      
      const testData = crypto.randomBytes(size);
      const aesKey = crypto.randomBytes(32);
      const chachaKey = crypto.randomBytes(32);

      // AES-256-GCM Performance
      console.log('AES-256-GCM Encryption:');
      
      const nodeAES = this.measurePerformance('Node.js AES-256-GCM', () => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        let encrypted = cipher.update(testData);
        cipher.final();
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, encrypted, tag]);
      });

      const nobleAES = this.measurePerformance('@noble/ciphers AES-256-GCM', () => {
        const nonce = crypto.randomBytes(12);
        const aes = gcm(aesKey, nonce);
        const encrypted = aes.encrypt(testData);
        return Buffer.concat([nonce, encrypted]);
      });

      const libsilverAES = this.measurePerformance('LibSilver AES-256-GCM', () => {
        return SymmetricCrypto.encryptAes(testData, aesKey);
      });

      this.printStats([nodeAES, nobleAES, libsilverAES]);

      // ChaCha20-Poly1305 Performance
      console.log('\nChaCha20-Poly1305 Encryption:');
      
      const nodeChacha = this.measurePerformance('Node.js ChaCha20-Poly1305', () => {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('chacha20-poly1305', chachaKey, nonce);
        let encrypted = cipher.update(testData);
        cipher.final();
        const tag = cipher.getAuthTag();
        return Buffer.concat([nonce, encrypted, tag]);
      });

      const nobleChacha = this.measurePerformance('@noble/ciphers ChaCha20-Poly1305', () => {
        const nonce = crypto.randomBytes(12);
        const chacha = chacha20poly1305(chachaKey, nonce);
        const encrypted = chacha.encrypt(testData);
        return Buffer.concat([nonce, encrypted]);
      });

      const libsilverChacha = this.measurePerformance('LibSilver ChaCha20-Poly1305', () => {
        return SymmetricCrypto.encryptChacha20(testData, chachaKey);
      });

      this.printStats([nodeChacha, nobleChacha, libsilverChacha]);
      
      console.log('\n' + '-'.repeat(60) + '\n');
    }
  }

  printStats(results) {
    for (const result of results) {
      const throughput = ((1000 / result.mean) * 1024 * 1024 / 1024).toFixed(2); // GB/s assuming 1MB data
      console.log(`  ${result.name}:`);
      console.log(`    Mean: ${result.mean.toFixed(3)}ms | Median: ${result.median.toFixed(3)}ms`);
      console.log(`    Min: ${result.min.toFixed(3)}ms | Max: ${result.max.toFixed(3)}ms`);
      console.log(`    P95: ${result.p95.toFixed(3)}ms | P99: ${result.p99.toFixed(3)}ms`);
      console.log(`    Std Dev: ${result.stdDev.toFixed(3)}ms`);
      console.log();
    }
  }

  // Generate summary report
  generateReport() {
    console.log('📋 Performance Summary Report\n');
    
    // Group results by algorithm
    const aesResults = this.results.filter(r => r.name.includes('AES'));
    const chachaResults = this.results.filter(r => r.name.includes('ChaCha'));

    if (aesResults.length > 0) {
      console.log('AES-256-GCM Performance Ranking (by mean time):');
      aesResults.sort((a, b) => a.mean - b.mean);
      aesResults.forEach((result, index) => {
        console.log(`  ${index + 1}. ${result.name}: ${result.mean.toFixed(3)}ms`);
      });
      console.log();
    }

    if (chachaResults.length > 0) {
      console.log('ChaCha20-Poly1305 Performance Ranking (by mean time):');
      chachaResults.sort((a, b) => a.mean - b.mean);
      chachaResults.forEach((result, index) => {
        console.log(`  ${index + 1}. ${result.name}: ${result.mean.toFixed(3)}ms`);
      });
      console.log();
    }

    console.log('✅ Analysis completed!\n');
  }
}

// Run the analysis
const analysis = new BenchmarkAnalysis();
analysis.testCorrectness();
analysis.runAnalysis();
analysis.generateReport();
