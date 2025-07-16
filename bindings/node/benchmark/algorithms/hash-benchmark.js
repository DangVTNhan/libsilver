#!/usr/bin/env node

/**
 * Hash Functions Benchmark Module
 */

import crypto from 'crypto';
import Benchmark from 'benchmark';
import { NodeJSHashFunctions } from '../implementations/nodejs-impl.js';
import { LibSilverHashFunctions } from '../implementations/libsilver-impl.js';

const IMPLEMENTATIONS = {
  'nodejs': NodeJSHashFunctions,
  'libsilver': LibSilverHashFunctions
};

export class HashBenchmark {
  constructor(config) {
    this.config = config;
    this.results = {};
  }

  async runBenchmarks(algorithms, dataSizes) {
    console.log('🔗 Running Hash Functions Benchmarks\n');
    
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
    const data = crypto.randomBytes(dataSize.size);
    const results = {};
    
    for (const implName of algConfig.implementations) {
      if (!IMPLEMENTATIONS[implName]) {
        console.log(`    ⚠️  Implementation ${implName} not available, skipping...`);
        continue;
      }
      
      const impl = IMPLEMENTATIONS[implName];
      results[implName] = {};
      
      try {
        // Benchmark hashing
        if (algConfig.operations.includes('hash')) {
          const hashResult = await this.benchmarkOperation(
            `${implName} ${algConfig.name} Hash (${dataSize.name})`,
            () => this.hash(impl, algId, data)
          );
          results[implName].hash = hashResult;
        }
        
      } catch (error) {
        console.log(`    ❌ Error benchmarking ${implName}: ${error.message}`);
        results[implName].error = error.message;
      }
    }
    
    return results;
  }

  hash(impl, algId, data) {
    switch (algId) {
      case 'sha256':
        return impl.sha256(data);
      case 'sha512':
        return impl.sha512(data);
      case 'blake3':
        return impl.blake3(data);
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
    console.log('🧠 Measuring Hash Functions Memory Usage\n');
    
    const memoryResults = {};
    const data = crypto.randomBytes(testDataSize);
    
    for (const [algId, algConfig] of Object.entries(algorithms)) {
      console.log(`📊 Memory test for ${algConfig.name}:`);
      memoryResults[algId] = {};
      
      for (const implName of algConfig.implementations) {
        if (!IMPLEMENTATIONS[implName]) continue;
        
        const impl = IMPLEMENTATIONS[implName];
        
        try {
          // Measure hashing memory
          const hashMemory = this.measureOperationMemory(
            `${implName} ${algConfig.name} Hash`,
            () => this.hash(impl, algId, data),
            iterations
          );
          
          memoryResults[algId][implName] = {
            hash: hashMemory
          };
          
          console.log(`  ${implName}: ${this.formatBytes(hashMemory.avgMemoryPerOp)} per op`);
          
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
