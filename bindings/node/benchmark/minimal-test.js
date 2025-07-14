#!/usr/bin/env node

/**
 * Minimal test to identify the issue causing process kills
 */

import crypto from 'crypto';

console.log('🧪 Minimal LibSilver Benchmark Test\n');

// Test 1: Basic imports
console.log('1. Testing imports...');
try {
  const { SymmetricCrypto } = await import('libsilver-nodejs');
  console.log('✅ LibSilver imported successfully');
} catch (error) {
  console.log('❌ LibSilver import failed:', error.message);
  process.exit(1);
}

// Test 2: Basic crypto operations
console.log('\n2. Testing basic operations...');
try {
  const { SymmetricCrypto } = await import('libsilver-nodejs');
  
  const key = SymmetricCrypto.generateAesKey();
  const plaintext = crypto.randomBytes(1024); // 1KB
  
  console.log('   - Generated key and plaintext');
  
  const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
  console.log('   - Encryption successful');
  
  const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);
  console.log('   - Decryption successful');
  
  const isEqual = Buffer.compare(plaintext, decrypted) === 0;
  console.log(`   - Data integrity: ${isEqual ? '✅' : '❌'}`);
  
} catch (error) {
  console.log('❌ Basic operations failed:', error.message);
  process.exit(1);
}

// Test 3: Memory usage check
console.log('\n3. Testing memory usage...');
try {
  const { SymmetricCrypto } = await import('libsilver-nodejs');
  
  const startMemory = process.memoryUsage();
  console.log('   - Start memory:', Math.round(startMemory.heapUsed / 1024 / 1024), 'MB');
  
  // Perform multiple operations
  for (let i = 0; i < 100; i++) {
    const key = SymmetricCrypto.generateAesKey();
    const plaintext = crypto.randomBytes(1024);
    const ciphertext = SymmetricCrypto.encryptAes(plaintext, key);
    const decrypted = SymmetricCrypto.decryptAes(ciphertext, key);
  }
  
  const midMemory = process.memoryUsage();
  console.log('   - After 100 ops:', Math.round(midMemory.heapUsed / 1024 / 1024), 'MB');
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
    const afterGC = process.memoryUsage();
    console.log('   - After GC:', Math.round(afterGC.heapUsed / 1024 / 1024), 'MB');
  }
  
} catch (error) {
  console.log('❌ Memory test failed:', error.message);
  process.exit(1);
}

// Test 4: Benchmark library import
console.log('\n4. Testing benchmark library...');
try {
  const Benchmark = (await import('benchmark')).default;
  console.log('✅ Benchmark library imported successfully');
  
  // Simple benchmark test
  const suite = new Benchmark.Suite();
  let testCompleted = false;
  
  suite
    .add('Simple Math', function() {
      Math.sqrt(Math.random() * 1000);
    })
    .on('complete', function() {
      console.log('✅ Simple benchmark completed');
      testCompleted = true;
    })
    .run({ 'async': false });
    
  if (!testCompleted) {
    throw new Error('Benchmark did not complete');
  }
  
} catch (error) {
  console.log('❌ Benchmark library test failed:', error.message);
  process.exit(1);
}

// Test 5: Combined test (LibSilver + Benchmark)
console.log('\n5. Testing LibSilver with Benchmark...');
try {
  const { SymmetricCrypto } = await import('libsilver-nodejs');
  const Benchmark = (await import('benchmark')).default;
  
  const key = SymmetricCrypto.generateAesKey();
  const plaintext = crypto.randomBytes(1024);
  
  let benchmarkCompleted = false;
  
  const suite = new Benchmark.Suite();
  suite
    .add('LibSilver AES Encrypt', function() {
      SymmetricCrypto.encryptAes(plaintext, key);
    })
    .on('complete', function() {
      const benchmark = this[0];
      console.log(`✅ LibSilver benchmark: ${benchmark.hz.toFixed(2)} ops/sec`);
      benchmarkCompleted = true;
    })
    .run({ 'async': false, 'maxTime': 1 }); // Short test
    
  if (!benchmarkCompleted) {
    throw new Error('LibSilver benchmark did not complete');
  }
  
} catch (error) {
  console.log('❌ LibSilver benchmark test failed:', error.message);
  process.exit(1);
}

console.log('\n✅ All tests passed! The benchmark system should work.');
console.log('\nIf the full benchmark still gets killed, try:');
console.log('1. Increase Node.js memory limit: node --max-old-space-size=4096 benchmark-runner.js');
console.log('2. Run with fewer iterations: node benchmark-runner.js --quick');
console.log('3. Run one category at a time: node benchmark-runner.js --category symmetric');
