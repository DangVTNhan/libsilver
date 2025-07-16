#!/usr/bin/env node

/**
 * Asymmetric Encryption Benchmark Module
 */

import crypto from 'crypto';
import Benchmark from 'benchmark';
import { NodeJSAsymmetricCrypto } from '../implementations/nodejs-impl.js';
import { LibSilverAsymmetricCrypto } from '../implementations/libsilver-impl.js';

const IMPLEMENTATIONS = {
  'nodejs': NodeJSAsymmetricCrypto,
  'libsilver': LibSilverAsymmetricCrypto
};

export class AsymmetricBenchmark {
  constructor(config) {
    this.config = config;
    this.results = {};
  }

  async runBenchmarks(algorithms, dataSizes) {
    console.log('🔐 Running Asymmetric Encryption Benchmarks\n');
    
    for (const [algId, algConfig] of Object.entries(algorithms)) {
      console.log(`📊 Benchmarking ${algConfig.name}...\n`);
      this.results[algId] = {};
      
      // For asymmetric encryption, we need to limit data size
      const effectiveDataSizes = this.getEffectiveDataSizes(algConfig, dataSizes);
      
      for (const dataSize of effectiveDataSizes) {
        console.log(`  Testing ${dataSize.name} (${dataSize.size.toLocaleString()} bytes)`);
        this.results[algId][dataSize.name] = await this.benchmarkAlgorithm(algId, algConfig, dataSize);
      }
      console.log();
    }
    
    return this.results;
  }

  getEffectiveDataSizes(algConfig, dataSizes) {
    if (algConfig.maxDataSize) {
      return dataSizes.filter(size => size.size <= algConfig.maxDataSize);
    }
    return dataSizes;
  }

  async benchmarkAlgorithm(algId, algConfig, dataSize) {
    const plaintext = crypto.randomBytes(Math.min(dataSize.size, algConfig.maxDataSize || dataSize.size));
    const results = {};
    
    for (const implName of algConfig.implementations) {
      if (!IMPLEMENTATIONS[implName]) {
        console.log(`    ⚠️  Implementation ${implName} not available, skipping...`);
        continue;
      }
      
      const impl = IMPLEMENTATIONS[implName];
      results[implName] = {};
      
      try {
        // Generate keypair
        const keypair = this.generateKeypair(impl, algId);
        
        // Benchmark key generation
        if (algConfig.operations.includes('keygen')) {
          const keygenResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} KeyGen`,
            () => this.generateKeypair(impl, algId)
          );
          results[implName].keygen = keygenResult;
        }
        
        // Benchmark encryption
        if (algConfig.operations.includes('encrypt')) {
          const encryptResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} Encrypt (${dataSize.name})`,
            () => this.encrypt(impl, algId, plaintext, keypair)
          );
          results[implName].encrypt = encryptResult;
        }
        
        // Benchmark decryption
        if (algConfig.operations.includes('decrypt')) {
          const ciphertext = this.encrypt(impl, algId, plaintext, keypair);
          const decryptResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} Decrypt (${dataSize.name})`,
            () => this.decrypt(impl, algId, ciphertext, keypair)
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

  generateKeypair(impl, algId) {
    switch (algId) {
      case 'rsa-oaep':
        return impl.generateRSAKeypair();
      default:
        throw new Error(`Unknown algorithm: ${algId}`);
    }
  }

  encrypt(impl, algId, plaintext, keypair) {
    switch (algId) {
      case 'rsa-oaep':
        return impl.encryptRSA(plaintext, keypair.publicKeyPem);
      default:
        throw new Error(`Unknown algorithm: ${algId}`);
    }
  }

  decrypt(impl, algId, ciphertext, keypair) {
    switch (algId) {
      case 'rsa-oaep':
        return impl.decryptRSA(ciphertext, keypair.privateKeyPem);
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
    console.log('🧠 Measuring Asymmetric Encryption Memory Usage\n');
    
    const memoryResults = {};
    
    for (const [algId, algConfig] of Object.entries(algorithms)) {
      console.log(`📊 Memory test for ${algConfig.name}:`);
      memoryResults[algId] = {};
      
      const effectiveDataSize = Math.min(testDataSize, algConfig.maxDataSize || testDataSize);
      const plaintext = crypto.randomBytes(effectiveDataSize);
      
      for (const implName of algConfig.implementations) {
        if (!IMPLEMENTATIONS[implName]) continue;
        
        const impl = IMPLEMENTATIONS[implName];
        
        try {
          const keypair = this.generateKeypair(impl, algId);
          
          // Measure key generation memory
          const keygenMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} KeyGen`,
            () => this.generateKeypair(impl, algId),
            Math.min(iterations, 100) // Fewer iterations for expensive operations
          );
          
          // Measure encryption memory
          const encryptMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} Encrypt`,
            () => this.encrypt(impl, algId, plaintext, keypair),
            iterations
          );
          
          // Measure decryption memory
          const ciphertext = this.encrypt(impl, algId, plaintext, keypair);
          const decryptMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} Decrypt`,
            () => this.decrypt(impl, algId, ciphertext, keypair),
            iterations
          );
          
          memoryResults[algId][implName] = {
            keygen: keygenMemory,
            encrypt: encryptMemory,
            decrypt: decryptMemory
          };
          
          console.log(`  ${implName}:`);
          console.log(`    KeyGen: ${this.formatBytes(keygenMemory.avgMemoryPerOp)} per op`);
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
