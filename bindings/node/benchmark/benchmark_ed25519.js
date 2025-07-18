#!/usr/bin/env node
// Run with: node --expose-gc benchmark_ed25519.js (for garbage collection)

/**
 * Ed25519 Digital Signature Algorithm Benchmark
 * Tests signing and verification of 32-byte hashes
 */

import os from 'os';
import { AsymmetricBenchmark } from './algorithms/asymmetric-benchmark.js';

// Benchmark configuration - optimized for faster Ed25519 testing
const BENCHMARK_CONFIG = {
  minSamples: 50,    // Reduced from 100 for faster execution
  maxTime: 5,        // Reduced from 10 seconds to 5 seconds max per operation
  minTime: 0.5,      // Reduced from 1 second to 0.5 seconds min per operation
  initCount: 1
};

// Ed25519 algorithm configuration
const ED25519_ALGORITHMS = {
  'ed25519': {
    name: 'Ed25519 Digital Signature',
    implementations: ['nodejs', 'libsilver'],
    operations: ['keygen', 'sign', 'verify'],
    description: 'Ed25519 elliptic curve digital signature algorithm',
    maxDataSize: 1024 * 1024 // 1MB max for practical testing
  }
};

// Fixed 32-byte hash for Ed25519 signing (typical SHA-256 hash)
const HASH_SIZE = 32;

// Display system information
function displaySystemInfo() {
  console.log('🔐 Ed25519 Digital Signature Benchmark Suite\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('V8 Version:', process.versions.v8);
  console.log('CPU:', os.cpus()[0].model);
  console.log('Memory:', Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB');
  console.log('\n' + '='.repeat(80) + '\n');
}

// Display algorithm information
function displayAlgorithmInfo() {
  console.log('📋 Ed25519 Digital Signature Algorithm:\n');

  Object.entries(ED25519_ALGORITHMS).forEach(([, config]) => {
    console.log(`🔹 ${config.name}`);
    console.log(`   Operations: ${config.operations.join(', ')}`);
    console.log(`   Implementations: ${config.implementations.join(', ')}`);
    console.log(`   Description: ${config.description}`);
    console.log();
  });

  console.log('📏 Test Configuration:');
  console.log(`   • Hash size: ${HASH_SIZE} bytes (SHA-256)`);
  console.log('   • Fixed hash input for consistent benchmarking');

  console.log('\n📝 Notes:');
  console.log('   • Ed25519 typically signs 32-byte hashes (SHA-256)');
  console.log('   • Ed25519 signatures are always 64 bytes');
  console.log('   • Public keys are 32 bytes, private keys are 32 bytes (seed)');
  console.log('   • Performance is constant regardless of message size');
  console.log('\n' + '='.repeat(80) + '\n');
}

// Run performance benchmarks
async function runPerformanceBenchmarks() {
  console.log('🚀 Running Ed25519 Performance Benchmarks...\n');

  const benchmark = new AsymmetricBenchmark(BENCHMARK_CONFIG);
  // Use a single data size for Ed25519 - 32-byte hash
  const dataSizes = [{ name: '32-byte hash', size: HASH_SIZE }];
  const results = await benchmark.runBenchmarks(ED25519_ALGORITHMS, dataSizes);

  return results;
}

// Run memory benchmarks
async function runMemoryBenchmarks() {
  console.log('🧠 Running Ed25519 Memory Usage Benchmarks...\n');

  const benchmark = new AsymmetricBenchmark(BENCHMARK_CONFIG);
  // Reduced iterations from 1000 to 100 for faster execution
  const memoryResults = await benchmark.measureMemory(ED25519_ALGORITHMS, HASH_SIZE, 100);

  return memoryResults;
}

// Display performance results
function displayPerformanceResults(results) {
  console.log('📊 Ed25519 Performance Results Summary:\n');
  console.log('='.repeat(80));

  Object.entries(results).forEach(([algId, algResults]) => {
    const algConfig = ED25519_ALGORITHMS[algId];
    console.log(`\n🔹 ${algConfig.name}:`);

    Object.entries(algResults).forEach(([testType, testResults]) => {
      console.log(`\n  📏 ${testType}:`);

      Object.entries(testResults).forEach(([implName, implResults]) => {
        console.log(`    🔧 ${implName}:`);

        Object.entries(implResults).forEach(([operation, opResult]) => {
          if (opResult.error) {
            console.log(`      ❌ ${operation}: ERROR - ${opResult.error}`);
          } else {
            const opsPerSec = opResult.hz.toFixed(2);
            const avgTimeMs = (opResult.mean * 1000).toFixed(2);
            const rme = opResult.stats ? opResult.stats.rme.toFixed(2) : opResult.rme.toFixed(2);
            console.log(`      ✅ ${operation}: ${opsPerSec} ops/sec (${avgTimeMs}ms avg, ±${rme}%)`);
          }
        });
      });
    });
  });

  console.log('\n' + '='.repeat(80));
}

// Display memory results
function displayMemoryResults(memoryResults) {
  console.log('\n🧠 Ed25519 Memory Usage Results Summary:\n');
  console.log('='.repeat(80));
  
  Object.entries(memoryResults).forEach(([algId, algResults]) => {
    const algConfig = ED25519_ALGORITHMS[algId];
    console.log(`\n🔹 ${algConfig.name}:`);
    
    Object.entries(algResults).forEach(([implName, implResults]) => {
      console.log(`  🔧 ${implName}:`);
      
      if (implResults.error) {
        console.log(`    ❌ ERROR: ${implResults.error}`);
      } else {
        Object.entries(implResults).forEach(([operation, opResult]) => {
          if (opResult && !opResult.error) {
            console.log(`    ✅ ${operation}: ${formatBytes(opResult.avgMemoryPerOp)} per op`);
          }
        });
      }
    });
  });
  
  console.log('\n' + '='.repeat(80));
}

// Format bytes helper
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}



// Set up process monitoring and timeout
const BENCHMARK_TIMEOUT = 3 * 60 * 1000; // 3 minutes total timeout (reduced for faster Ed25519)
const timeoutId = setTimeout(() => {
  console.error('\n❌ Benchmark timed out after 3 minutes. Exiting...');
  process.exit(1);
}, BENCHMARK_TIMEOUT);

// Monitor memory usage
const memoryMonitor = setInterval(() => {
  const mem = process.memoryUsage();
  if (mem.heapUsed > 200 * 1024 * 1024) { // > 200MB
    console.warn(`⚠️  Memory warning: ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB heap used`);
  }
}, 10000); // Check every 10 seconds

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

// Main function
async function main() {
  try {
    // Display system and algorithm information
    displaySystemInfo();
    displayAlgorithmInfo();
    
    // Run performance benchmarks
    const performanceResults = await runPerformanceBenchmarks();
    
    // Force garbage collection
    if (global.gc) {
      console.log('🗑️  Running garbage collection...\n');
      global.gc();
    }
    
    // Run memory benchmarks
    const memoryResults = await runMemoryBenchmarks();
    
    // Display results
    displayPerformanceResults(performanceResults);
    displayMemoryResults(memoryResults);
    
    // Clean up
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    
    console.log('\n✅ Ed25519 digital signature benchmark completed successfully!\n');
    
    // Display key insights
    console.log('🔍 Key Insights:');
    console.log('   • Ed25519 provides constant-time operations for 32-byte hash signing');
    console.log('   • Signing performance is typically faster than verification');
    console.log('   • Memory usage should be minimal and consistent');
    console.log('   • Compare LibSilver vs Node.js native implementation performance');
    console.log('   • Ed25519 signatures are always 64 bytes regardless of input');
    
  } catch (error) {
    console.error('❌ Benchmark failed:', error.message);
    console.error(error.stack);
    clearTimeout(timeoutId);
    clearInterval(memoryMonitor);
    process.exit(1);
  }
}

// Execute main function
main();
