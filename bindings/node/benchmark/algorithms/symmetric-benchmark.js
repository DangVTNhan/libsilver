#!/usr/bin/env node

/**
 * Symmetric Encryption Benchmark Module
 */

import crypto from 'crypto';
import Benchmark from 'benchmark';
import { NodeJSSymmetricCrypto } from '../implementations/nodejs-impl.js';
import { NobleSymmetricCrypto } from '../implementations/noble-impl.js';
import { LibSilverSymmetricCrypto, LibSilverAWSSymmetricCrypto, LibSilverRustSymmetricCrypto } from '../implementations/libsilver-impl.js';

const IMPLEMENTATIONS = {
  'nodejs': NodeJSSymmetricCrypto,
  'noble': NobleSymmetricCrypto,
  'libsilver': LibSilverSymmetricCrypto,
  'libsilver-aws': LibSilverAWSSymmetricCrypto,
  'libsilver-rust': LibSilverRustSymmetricCrypto
};

export class SymmetricBenchmark {
  constructor(config) {
    this.config = config;
    this.results = {};
  }

  async runBenchmarks(algorithms, dataSizes) {
    console.log('🔐 Running Symmetric Encryption Benchmarks\n');
    
    for (const [algId, algConfig] of Object.entries(algorithms)) {
      console.log(`📊 Benchmarking ${algConfig.name}...\n`);
      this.results[algId] = {};
      
      for (const dataSize of dataSizes) {
        console.log(`  Testing ${dataSize.name} (${dataSize.size.toLocaleString()} bytes)`);
        this.results[algId][dataSize.name] = await this.benchmarkAlgorithm(algId, algConfig, dataSize);
      }
      console.log();
    }
    
    return this.results;
  }

  async benchmarkAlgorithm(algId, algConfig, dataSize) {
    const plaintext = crypto.randomBytes(dataSize.size);
    const results = {};
    
    for (const implName of algConfig.implementations) {
      if (!IMPLEMENTATIONS[implName]) {
        console.log(`    ⚠️  Implementation ${implName} not available, skipping...`);
        continue;
      }
      
      const impl = IMPLEMENTATIONS[implName];
      results[implName] = {};
      
      try {
        // Generate key
        const key = this.generateKey(impl, algId);
        
        // Benchmark encryption
        if (algConfig.operations.includes('encrypt')) {
          const encryptResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} Encrypt (${dataSize.name})`,
            () => this.encrypt(impl, algId, plaintext, key)
          );
          results[implName].encrypt = encryptResult;
        }
        
        // Benchmark decryption
        if (algConfig.operations.includes('decrypt')) {
          const ciphertext = this.encrypt(impl, algId, plaintext, key);
          const decryptResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} Decrypt (${dataSize.name})`,
            () => this.decrypt(impl, algId, ciphertext, key)
          );
          results[implName].decrypt = decryptResult;
        }
        
      } catch (error) {
        console.log(`    ❌ Error benchmarking ${implName}: ${error.message}`);
        results[implName].error = error.message;
      }
    }
    
    return results;
  }

  generateKey(impl, algId) {
    switch (algId) {
      case 'aes-256-gcm':
        return impl.generateAESKey ? impl.generateAESKey() : crypto.randomBytes(32);
      case 'chacha20-poly1305':
        return impl.generateChaCha20Key ? impl.generateChaCha20Key() : crypto.randomBytes(32);
      default:
        throw new Error(`Unknown algorithm: ${algId}`);
    }
  }

  encrypt(impl, algId, plaintext, key) {
    switch (algId) {
      case 'aes-256-gcm':
        return impl.encryptAES(plaintext, key);
      case 'chacha20-poly1305':
        return impl.encryptChaCha20(plaintext, key);
      default:
        throw new Error(`Unknown algorithm: ${algId}`);
    }
  }

  decrypt(impl, algId, ciphertext, key) {
    switch (algId) {
      case 'aes-256-gcm':
        return impl.decryptAES(ciphertext, key);
      case 'chacha20-poly1305':
        return impl.decryptChaCha20(ciphertext, key);
      default:
        throw new Error(`Unknown algorithm: ${algId}`);
    }
  }

  async benchmarkOperation(name, operation) {
    return new Promise((resolve) => {
      const suite = new Benchmark.Suite();
      
      suite
        .add(name, operation, {
          minSamples: this.config.minSamples,
          maxTime: this.config.maxTime,
          initCount: this.config.initCount,
          minTime: this.config.minTime
        })
        .on('complete', function() {
          const benchmark = this[0];
          const result = {
            name: benchmark.name,
            hz: benchmark.hz,
            rme: benchmark.stats.rme,
            samples: benchmark.stats.sample.length,
            mean: benchmark.stats.mean,
            deviation: benchmark.stats.deviation
          };
          
          console.log(`    ${name}: ${benchmark.hz.toFixed(2)} ops/sec ±${benchmark.stats.rme.toFixed(2)}%`);
          resolve(result);
        })
        .run({ 'async': false });
    });
  }

  async measureMemory(algorithms, testDataSize, iterations) {
    console.log('🧠 Measuring Symmetric Encryption Memory Usage\n');
    
    const memoryResults = {};
    const plaintext = crypto.randomBytes(testDataSize);
    
    for (const [algId, algConfig] of Object.entries(algorithms)) {
      console.log(`📊 Memory test for ${algConfig.name}:`);
      memoryResults[algId] = {};
      
      for (const implName of algConfig.implementations) {
        if (!IMPLEMENTATIONS[implName]) continue;
        
        const impl = IMPLEMENTATIONS[implName];
        
        try {
          const key = this.generateKey(impl, algId);
          
          // Measure encryption memory
          const encryptMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} Encrypt`,
            () => this.encrypt(impl, algId, plaintext, key),
            iterations
          );
          
          // Measure decryption memory
          const ciphertext = this.encrypt(impl, algId, plaintext, key);
          const decryptMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} Decrypt`,
            () => this.decrypt(impl, algId, ciphertext, key),
            iterations
          );
          
          memoryResults[algId][implName] = {
            encrypt: encryptMemory,
            decrypt: decryptMemory
          };
          
          console.log(`  ${implName}:`);
          console.log(`    Encrypt: ${this.formatBytes(encryptMemory.avgMemoryPerOp)} per op`);
          console.log(`    Decrypt: ${this.formatBytes(decryptMemory.avgMemoryPerOp)} per op`);
          
        } catch (error) {
          console.log(`  ❌ ${implName}: ${error.message}`);
          memoryResults[algId][implName] = { error: error.message };
        }
      }
      console.log();
    }
    
    return memoryResults;
  }

  measureOperationMemory(name, operation, iterations) {
    if (global.gc) global.gc();
    
    const startMemory = process.memoryUsage();
    const startTime = process.hrtime.bigint();
    
    for (let i = 0; i < iterations; i++) {
      operation();
    }
    
    const endTime = process.hrtime.bigint();
    const endMemory = process.memoryUsage();
    
    if (global.gc) global.gc();
    const afterGCMemory = process.memoryUsage();
    
    const executionTime = Number(endTime - startTime) / 1000000; // ms
    const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;
    const memoryAfterGC = afterGCMemory.heapUsed - startMemory.heapUsed;
    
    return {
      name,
      iterations,
      executionTime,
      memoryDelta,
      memoryAfterGC,
      avgTimePerOp: executionTime / iterations,
      avgMemoryPerOp: memoryAfterGC / iterations
    };
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}
