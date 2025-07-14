#!/usr/bin/env node

/**
 * Test script to verify the benchmark system works correctly
 */

import { BenchmarkRunner } from './benchmark-runner.js';

async function testBenchmark() {
  console.log('🧪 Testing LibSilver Benchmark System\n');
  
  try {
    const runner = new BenchmarkRunner();
    
    // Test with quick mode and only symmetric category
    await runner.runBenchmarks({
      categories: ['symmetric'],
      quick: true,
      reportOnly: false
    });
    
    console.log('\n✅ Benchmark test completed successfully!');
    
  } catch (error) {
    console.error('❌ Benchmark test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run test
testBenchmark();
