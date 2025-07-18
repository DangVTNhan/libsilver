#!/usr/bin/env node
// Run with: node --expose-gc benchmark_mlkem768.js (for garbage collection)

/**
 * ML-KEM-768 Encapsulation Benchmark
 * Benchmarks ML-KEM-768 key encapsulation mechanism using LibSilver
 * ML-KEM generates a 32-byte shared secret internally (no input message required)
 */

import os from 'os';
import { LibSilverPostQuantum } from './implementations/libsilver-impl.js';

// Test configuration
const BENCHMARK_CONFIG = {
  minSamples: 100,
  maxTime: 5, // seconds
  minTime: 0.5, // seconds
  warmupRuns: 3
};

// Custom benchmark runner
class CustomBenchmark {
  constructor(name, fn, options = {}) {
    this.name = name;
    this.fn = fn;
    this.minSamples = options.minSamples || BENCHMARK_CONFIG.minSamples;
    this.maxTime = options.maxTime || BENCHMARK_CONFIG.maxTime;
    this.minTime = options.minTime || BENCHMARK_CONFIG.minTime;
    this.warmupRuns = options.warmupRuns || BENCHMARK_CONFIG.warmupRuns;
  }

  async run() {
    // Warmup runs
    for (let i = 0; i < this.warmupRuns; i++) {
      try {
        this.fn();
      } catch (error) {
        return { error: error.message, hz: 0, samples: 0 };
      }
    }

    const samples = [];
    const startTime = Date.now();
    let runs = 0;

    while (samples.length < this.minSamples && (Date.now() - startTime) < this.maxTime * 1000) {
      const runStart = process.hrtime.bigint();

      try {
        this.fn();
        runs++;
      } catch (error) {
        return { error: error.message, hz: 0, samples: samples.length };
      }

      const runEnd = process.hrtime.bigint();
      const duration = Number(runEnd - runStart) / 1e9; // Convert to seconds
      samples.push(duration);

      // Stop if we've run for minimum time and have enough samples
      if ((Date.now() - startTime) >= this.minTime * 1000 && samples.length >= this.minSamples) {
        break;
      }
    }

    if (samples.length === 0) {
      return { error: 'No successful runs', hz: 0, samples: 0 };
    }

    // Calculate operations per second
    const avgDuration = samples.reduce((a, b) => a + b, 0) / samples.length;
    const hz = 1 / avgDuration;

    return {
      hz,
      samples: samples.length,
      avgDuration,
      minDuration: Math.min(...samples),
      maxDuration: Math.max(...samples)
    };
  }
}

// Benchmark suite
class BenchmarkSuite {
  constructor() {
    this.benchmarks = [];
    this.results = [];
  }

  add(name, fn, options = {}) {
    this.benchmarks.push(new CustomBenchmark(name, fn, options));
    return this;
  }

  async run() {
    this.results = [];

    for (const benchmark of this.benchmarks) {
      const result = await benchmark.run();
      result.name = benchmark.name;
      this.results.push(result);

      // Emit cycle event equivalent
      this.onCycle?.(result);

      // Force garbage collection after each benchmark
      if (global.gc) {
        const memBefore = process.memoryUsage();
        global.gc();
        const memAfter = process.memoryUsage();
        const memFreed = ((memBefore.heapUsed - memAfter.heapUsed) / 1024 / 1024).toFixed(2);
        console.log(`    🗑️  GC: freed ${memFreed} MB, heap: ${(memAfter.heapUsed / 1024 / 1024).toFixed(2)} MB`);

        // Warn if memory usage is getting high
        if (memAfter.heapUsed > 100 * 1024 * 1024) { // > 100MB
          console.warn(`    ⚠️  High memory usage: ${(memAfter.heapUsed / 1024 / 1024).toFixed(2)} MB`);
        }
      }
    }

    // Emit complete event equivalent
    this.onComplete?.();
  }

  on(event, handler) {
    if (event === 'cycle') {
      this.onCycle = handler;
    } else if (event === 'complete') {
      this.onComplete = handler;
    }
    return this;
  }
}

// Main benchmark runner
async function runMLKEM768Benchmark() {
  console.log('🔐 ML-KEM-768 Key Encapsulation Mechanism Benchmark\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('V8 Version:', process.versions.v8);
  console.log('CPU:', os.cpus()[0].model);
  console.log('Memory:', Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB');
  console.log('Note: ML-KEM generates a 32-byte shared secret internally');
  console.log('\n' + '='.repeat(80) + '\n');

  console.log('📊 Benchmarking ML-KEM-768 key encapsulation operations\n');

  try {
    // Generate ML-KEM-768 keypair
    console.log('🔑 Generating ML-KEM-768 keypair...');
    const keypair = LibSilverPostQuantum.mlKem768GenerateKeypair();
    console.log('✅ Keypair generated successfully\n');

    const suite = new BenchmarkSuite();

    // ML-KEM-768 Key Generation Benchmark
    suite.add('LibSilver ML-KEM-768 Key Generation', function() {
      return LibSilverPostQuantum.mlKem768GenerateKeypair();
    });

    // ML-KEM-768 Encapsulation Benchmark
    suite.add('LibSilver ML-KEM-768 Encapsulation', function() {
      return LibSilverPostQuantum.mlKem768Encapsulate(keypair.publicKeyBytes);
    });

    // ML-KEM-768 Decapsulation Benchmark
    const encapsulationResult = LibSilverPostQuantum.mlKem768Encapsulate(keypair.publicKeyBytes);
    suite.add('LibSilver ML-KEM-768 Decapsulation', function() {
      return LibSilverPostQuantum.mlKem768Decapsulate(encapsulationResult.ciphertext, keypair.privateKeyBytes);
    });

    // Add event handlers
    suite.on('cycle', function(result) {
      const opsPerSec = result.hz.toFixed(2);
      console.log(`  ${result.name}: ${opsPerSec} ops/sec`);

      // Check for errors in the benchmark
      if (result.error) {
        console.error(`    ❌ Benchmark error: ${result.error}`);
      } else {
        console.log(`    📊 Samples: ${result.samples}, Avg: ${(result.avgDuration * 1000).toFixed(2)}ms, Min: ${(result.minDuration * 1000).toFixed(2)}ms, Max: ${(result.maxDuration * 1000).toFixed(2)}ms`);
      }
    });

    suite.on('complete', function() {
      console.log('\n' + '-'.repeat(60) + '\n');

      // Force garbage collection if available
      if (global.gc) {
        const memBefore = process.memoryUsage();
        global.gc();
        const memAfter = process.memoryUsage();
        console.log(`🗑️  Garbage collection completed`);
        console.log(`   Memory freed: ${((memBefore.heapUsed - memAfter.heapUsed) / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Current heap usage: ${(memAfter.heapUsed / 1024 / 1024).toFixed(2)} MB\n`);
      } else {
        console.log('⚠️  Garbage collection not available. Run with --expose-gc flag.\n');
      }
    });

    await suite.run();

    // Display summary
    console.log('📈 Benchmark Summary:');
    console.log('='.repeat(50));
    suite.results.forEach(result => {
      if (!result.error) {
        console.log(`${result.name}: ${result.hz.toFixed(2)} ops/sec (${(result.avgDuration * 1000).toFixed(2)}ms avg)`);
      } else {
        console.log(`${result.name}: ERROR - ${result.error}`);
      }
    });

  } catch (error) {
    console.error('❌ Benchmark setup failed:', error.message);
    throw error;
  }
}

// Set up process monitoring and timeout
const BENCHMARK_TIMEOUT = 5 * 60 * 1000; // 5 minutes total timeout
const timeoutId = setTimeout(() => {
  console.error('\n❌ Benchmark timed out after 5 minutes. Exiting...');
  process.exit(1);
}, BENCHMARK_TIMEOUT);

// Monitor memory usage
const memoryMonitor = setInterval(() => {
  const mem = process.memoryUsage();
  if (mem.heapUsed > 200 * 1024 * 1024) { // > 200MB
    console.warn(`⚠️  Memory warning: ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB heap used`);
  }
}, 5000); // Check every 5 seconds

// Handle process signals
process.on('SIGINT', () => {
  console.log('\n🛑 Benchmark interrupted by user');
  clearTimeout(timeoutId);
  clearInterval(memoryMonitor);
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Benchmark terminated');
  clearTimeout(timeoutId);
  clearInterval(memoryMonitor);
  process.exit(0);
});

async function main() {
  try {
    // Run ML-KEM-768 benchmark
    await runMLKEM768Benchmark();

    // Clean up
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    console.log('✅ ML-KEM-768 benchmark completed successfully!\n');
  } catch (error) {
    console.error('❌ Benchmark failed:', error.message);
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    process.exit(1);
  }
}

// Execute main function
main();
