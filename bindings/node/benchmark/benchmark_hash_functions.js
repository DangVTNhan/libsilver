#!/usr/bin/env node
// Run with: node --expose-gc benchmark_sha512.js (for garbage collection)
import crypto from 'crypto';
import os from 'os';
import { NodeJSHashFunctions } from './implementations/nodejs-impl.js';
import { LibSilverHashFunctions } from './implementations/libsilver-impl.js';

// Test data sizes (in bytes)
const DATA_SIZES = [
  // Small data sizes for hash functions
  { name: '1KB', size: 1024 },
  { name: '4KB', size: 4096 },
  { name: '16KB', size: 16384 },
  { name: '64KB', size: 65536 },
  { name: '256KB', size: 262144 },
  { name: '1MB', size: 1048576 },
  // Typical chunk size for streaming data
  { name: '8MB', size: 1048576 * 8 },
  // Upper limit for streaming data
  { name: '16MB', size: 1048576 * 16 }
];

// Generate test data
function generateTestData(size) {
  return crypto.randomBytes(size);
}

// Custom benchmark runner
class CustomBenchmark {
  constructor(name, fn, options = {}) {
    this.name = name;
    this.fn = fn;
    this.minSamples = options.minSamples || 1000;
    this.maxTime = options.maxTime || 5; // seconds
    this.minTime = options.minTime || 0.5; // seconds
    this.warmupRuns = options.warmupRuns || 3;
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

// Benchmark runner
async function runBenchmarks() {
  console.log('🚀 LibSilver vs Node.js Crypto Hash Functions Performance Benchmark\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('V8 Version:', process.versions.v8);
  console.log('CPU:', os.cpus()[0].model);
  console.log('Memory:', Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB');
  console.log('\n' + '='.repeat(80) + '\n');

  for (const dataSize of DATA_SIZES) {
    console.log(`📊 Benchmarking Hash Functions ${dataSize.name} (${dataSize.size.toLocaleString()} bytes)\n`);

    const testData = generateTestData(dataSize.size);

    const suite = new BenchmarkSuite();

    // Hash Function Benchmarks
    suite
      .add(`LibSilver SHA-256 (${dataSize.name})`, function() {
        return LibSilverHashFunctions.sha256(testData);
      })
      .add(`LibSilver SHA-512 (${dataSize.name})`, function() {
        return LibSilverHashFunctions.sha512(testData);
      })
      .add(`LibSilver BLAKE3 (${dataSize.name})`, function() {
        return LibSilverHashFunctions.blake3(testData);
      })
      .add(`Node.js SHA-256 (${dataSize.name})`, function() {
        return NodeJSHashFunctions.sha256(testData);
      })
      .add(`Node.js SHA-512 (${dataSize.name})`, function() {
        return NodeJSHashFunctions.sha512(testData);
      });

    // Add event handlers
    suite.on('cycle', function(result) {
        const opsPerSec = result.hz.toFixed(2);
        const throughputMBps = ((dataSize.size * result.hz) / (1024 * 1024)).toFixed(2);
        console.log(`  ${result.name}: ${opsPerSec} ops/sec (${throughputMBps} MB/s)`);

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
  }
}

// Set up process monitoring and timeout
const BENCHMARK_TIMEOUT = 10 * 60 * 1000; // 10 minutes total timeout
const timeoutId = setTimeout(() => {
  console.error('\n❌ Benchmark timed out after 10 minutes. Exiting...');
  process.exit(1);
}, BENCHMARK_TIMEOUT);

// Monitor memory usage
const memoryMonitor = setInterval(() => {
  const mem = process.memoryUsage();
  if (mem.heapUsed > 500 * 1024 * 1024) { // > 500MB
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
    // Run benchmarks
    await runBenchmarks();

    // Clean up
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    console.log('✅ Benchmark completed successfully!\n');
  } catch (error) {
    console.error('❌ Benchmark failed:', error.message);
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    process.exit(1);
  }
}

// Execute main function
main();
