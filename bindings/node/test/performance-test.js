const { 
  SymmetricCrypto, AsymmetricCrypto, HashFunctions, KeyDerivation, RandomGenerator,
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto 
} = require('../index.js');

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function formatTime(ms) {
  if (ms < 1) return `${(ms * 1000).toFixed(2)}μs`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatThroughput(bytes, ms) {
  const mbps = (bytes / 1024 / 1024) / (ms / 1000);
  return `${mbps.toFixed(2)} MB/s`;
}

// Benchmark symmetric encryption performance
function benchmarkSymmetricCrypto() {
  console.log('Benchmarking Symmetric Cryptography...');
  
  const dataSizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB
  const iterations = 100;
  
  console.log('  Data Size | Algorithm    | Encrypt Time | Decrypt Time | Throughput');
  console.log('  ----------|--------------|--------------|--------------|------------');
  
  for (const size of dataSizes) {
    const data = RandomGenerator.generateBytes(size);
    
    // AES-256-GCM
    const aesKey = SymmetricCrypto.generateAesKey();
    let aesEncryptTime = 0;
    let aesDecryptTime = 0;
    
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      const encrypted = SymmetricCrypto.encryptAes(data, aesKey);
      aesEncryptTime += performance.now() - start;
      
      const decryptStart = performance.now();
      const decrypted = SymmetricCrypto.decryptAes(encrypted, aesKey);
      aesDecryptTime += performance.now() - decryptStart;
      
      assert(data.equals(decrypted), 'AES decryption should work');
    }
    
    aesEncryptTime /= iterations;
    aesDecryptTime /= iterations;
    const aesThroughput = formatThroughput(size, aesEncryptTime + aesDecryptTime);
    
    console.log(`  ${(size/1024).toFixed(0).padStart(7)}KB | AES-256-GCM  | ${formatTime(aesEncryptTime).padStart(10)} | ${formatTime(aesDecryptTime).padStart(10)} | ${aesThroughput.padStart(10)}`);
    
    // ChaCha20-Poly1305
    const chachaKey = SymmetricCrypto.generateChacha20Key();
    let chachaEncryptTime = 0;
    let chachaDecryptTime = 0;
    
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      const encrypted = SymmetricCrypto.encryptChacha20(data, chachaKey);
      chachaEncryptTime += performance.now() - start;
      
      const decryptStart = performance.now();
      const decrypted = SymmetricCrypto.decryptChacha20(encrypted, chachaKey);
      chachaDecryptTime += performance.now() - decryptStart;
      
      assert(data.equals(decrypted), 'ChaCha20 decryption should work');
    }
    
    chachaEncryptTime /= iterations;
    chachaDecryptTime /= iterations;
    const chachaThroughput = formatThroughput(size, chachaEncryptTime + chachaDecryptTime);
    
    console.log(`  ${(size/1024).toFixed(0).padStart(7)}KB | ChaCha20     | ${formatTime(chachaEncryptTime).padStart(10)} | ${formatTime(chachaDecryptTime).padStart(10)} | ${chachaThroughput.padStart(10)}`);
  }
  
  console.log('✓ Symmetric crypto benchmarks completed');
}

// Benchmark hash function performance
function benchmarkHashFunctions() {
  console.log('\nBenchmarking Hash Functions...');
  
  const dataSizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB
  const iterations = 1000;
  
  console.log('  Data Size | Algorithm | Time per Hash | Throughput');
  console.log('  ----------|-----------|---------------|------------');
  
  for (const size of dataSizes) {
    const data = RandomGenerator.generateBytes(size);
    
    // SHA-256
    let sha256Time = 0;
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      HashFunctions.sha256(data);
      sha256Time += performance.now() - start;
    }
    sha256Time /= iterations;
    const sha256Throughput = formatThroughput(size, sha256Time);
    
    console.log(`  ${(size/1024).toFixed(0).padStart(7)}KB | SHA-256   | ${formatTime(sha256Time).padStart(11)} | ${sha256Throughput.padStart(10)}`);
    
    // SHA-512
    let sha512Time = 0;
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      HashFunctions.sha512(data);
      sha512Time += performance.now() - start;
    }
    sha512Time /= iterations;
    const sha512Throughput = formatThroughput(size, sha512Time);
    
    console.log(`  ${(size/1024).toFixed(0).padStart(7)}KB | SHA-512   | ${formatTime(sha512Time).padStart(11)} | ${sha512Throughput.padStart(10)}`);
    
    // BLAKE3
    let blake3Time = 0;
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      HashFunctions.blake3(data);
      blake3Time += performance.now() - start;
    }
    blake3Time /= iterations;
    const blake3Throughput = formatThroughput(size, blake3Time);
    
    console.log(`  ${(size/1024).toFixed(0).padStart(7)}KB | BLAKE3    | ${formatTime(blake3Time).padStart(11)} | ${blake3Throughput.padStart(10)}`);
  }
  
  console.log('✓ Hash function benchmarks completed');
}

// Benchmark post-quantum cryptography
function benchmarkPostQuantumCrypto() {
  console.log('\nBenchmarking Post-Quantum Cryptography...');
  
  const iterations = 100;
  
  console.log('  Algorithm  | Key Gen | Encap/Sign | Decap/Verify | Key Sizes (Pub/Priv)');
  console.log('  -----------|---------|------------|--------------|---------------------');
  
  // ML-KEM variants
  const kemVariants = [
    { name: 'ML-KEM-512', crypto: MlKem512Crypto },
    { name: 'ML-KEM-768', crypto: MlKem768Crypto },
    { name: 'ML-KEM-1024', crypto: MlKem1024Crypto }
  ];
  
  for (const variant of kemVariants) {
    let keyGenTime = 0;
    let encapTime = 0;
    let decapTime = 0;
    
    for (let i = 0; i < iterations; i++) {
      // Key generation
      const start = performance.now();
      const keypair = variant.crypto.generateKeypair();
      keyGenTime += performance.now() - start;
      
      // Encapsulation
      const encapStart = performance.now();
      const encapsulation = variant.crypto.encapsulate(keypair.publicKeyBytes);
      encapTime += performance.now() - encapStart;
      
      // Decapsulation
      const decapStart = performance.now();
      variant.crypto.decapsulate(encapsulation.ciphertext, keypair.privateKeyBytes);
      decapTime += performance.now() - decapStart;
    }
    
    keyGenTime /= iterations;
    encapTime /= iterations;
    decapTime /= iterations;
    
    const sizes = variant.crypto.getSizes();
    const keySizes = `${sizes.publicKeySize}/${sizes.privateKeySize}`;
    
    console.log(`  ${variant.name.padEnd(10)} | ${formatTime(keyGenTime).padStart(7)} | ${formatTime(encapTime).padStart(10)} | ${formatTime(decapTime).padStart(12)} | ${keySizes.padStart(19)}`);
  }
  
  // ML-DSA variants
  const dsaVariants = [
    { name: 'ML-DSA-44', crypto: MlDsa44Crypto },
    { name: 'ML-DSA-65', crypto: MlDsa65Crypto },
    { name: 'ML-DSA-87', crypto: MlDsa87Crypto }
  ];
  
  const message = RandomGenerator.generateBytes(1024);
  
  for (const variant of dsaVariants) {
    let keyGenTime = 0;
    let signTime = 0;
    let verifyTime = 0;
    
    for (let i = 0; i < iterations; i++) {
      // Key generation
      const start = performance.now();
      const keypair = variant.crypto.generateKeypair();
      keyGenTime += performance.now() - start;
      
      // Signing
      const signStart = performance.now();
      const signature = variant.crypto.sign(message, keypair.privateKeyBytes);
      signTime += performance.now() - signStart;
      
      // Verification
      const verifyStart = performance.now();
      variant.crypto.verify(message, signature, keypair.publicKeyBytes);
      verifyTime += performance.now() - verifyStart;
    }
    
    keyGenTime /= iterations;
    signTime /= iterations;
    verifyTime /= iterations;
    
    const sizes = variant.crypto.getSizes();
    const keySizes = `${sizes.publicKeySize}/${sizes.privateKeySize}`;
    
    console.log(`  ${variant.name.padEnd(10)} | ${formatTime(keyGenTime).padStart(7)} | ${formatTime(signTime).padStart(10)} | ${formatTime(verifyTime).padStart(12)} | ${keySizes.padStart(19)}`);
  }
  
  console.log('✓ Post-quantum crypto benchmarks completed');
}

// Benchmark key derivation functions
function benchmarkKeyDerivation() {
  console.log('\nBenchmarking Key Derivation Functions...');
  
  const password = Buffer.from('test_password_123', 'utf8');
  const salt = RandomGenerator.generateSalt();
  const iterations = 10;
  
  console.log('  Algorithm | Time per Derivation | Iterations/Params');
  console.log('  ----------|---------------------|------------------');
  
  // Argon2
  let argon2Time = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    KeyDerivation.argon2(password, salt, 32);
    argon2Time += performance.now() - start;
  }
  argon2Time /= iterations;
  
  console.log(`  Argon2    | ${formatTime(argon2Time).padStart(17)} | Default params`);
  
  // PBKDF2
  const pbkdf2Iterations = 10000;
  let pbkdf2Time = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    KeyDerivation.pbkdf2Sha256(password, salt, pbkdf2Iterations, 32);
    pbkdf2Time += performance.now() - start;
  }
  pbkdf2Time /= iterations;
  
  console.log(`  PBKDF2    | ${formatTime(pbkdf2Time).padStart(17)} | ${pbkdf2Iterations} iterations`);
  
  // HKDF
  const inputKey = RandomGenerator.generateBytes(32);
  let hkdfTime = 0;
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    KeyDerivation.hkdfSha256(inputKey, salt, null, 32);
    hkdfTime += performance.now() - start;
  }
  hkdfTime /= iterations;
  
  console.log(`  HKDF      | ${formatTime(hkdfTime).padStart(17)} | SHA-256 based`);
  
  console.log('✓ Key derivation benchmarks completed');
}

// Memory usage test
function testMemoryUsage() {
  console.log('\nTesting Memory Usage...');
  
  const initialMemory = process.memoryUsage();
  console.log(`  Initial memory usage: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  
  // Generate many keys and perform operations
  const operations = 1000;
  const keys = [];
  const signatures = [];
  
  console.log(`  Performing ${operations} cryptographic operations...`);
  
  for (let i = 0; i < operations; i++) {
    // Generate various keys
    keys.push(SymmetricCrypto.generateAesKey());
    keys.push(SymmetricCrypto.generateChacha20Key());
    
    // Generate post-quantum keypairs
    if (i % 10 === 0) { // Every 10th iteration to avoid too much memory usage
      const kemKeypair = MlKem768Crypto.generateKeypair();
      const dsaKeypair = MlDsa65Crypto.generateKeypair();
      
      const message = RandomGenerator.generateBytes(100);
      signatures.push(MlDsa65Crypto.sign(message, dsaKeypair.privateKeyBytes));
    }
  }
  
  const afterOperationsMemory = process.memoryUsage();
  console.log(`  After operations memory: ${(afterOperationsMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
    const afterGCMemory = process.memoryUsage();
    console.log(`  After GC memory: ${(afterGCMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
  }
  
  console.log(`  Generated ${keys.length} symmetric keys and ${signatures.length} signatures`);
  console.log('✓ Memory usage test completed');
}

function runPerformanceTests() {
  try {
    console.log('⚡ Running LibSilver Performance Tests...\n');
    
    benchmarkSymmetricCrypto();
    benchmarkHashFunctions();
    benchmarkPostQuantumCrypto();
    benchmarkKeyDerivation();
    testMemoryUsage();
    
    console.log('\n🎉 All performance tests completed!');
    console.log('\n📊 Performance Test Summary:');
    console.log('   ✓ Symmetric Cryptography Benchmarks');
    console.log('   ✓ Hash Function Benchmarks');
    console.log('   ✓ Post-Quantum Cryptography Benchmarks');
    console.log('   ✓ Key Derivation Benchmarks');
    console.log('   ✓ Memory Usage Analysis');
  } catch (error) {
    console.error('❌ Performance test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

if (require.main === module) {
  runPerformanceTests();
}

module.exports = {
  benchmarkSymmetricCrypto,
  benchmarkHashFunctions,
  benchmarkPostQuantumCrypto,
  benchmarkKeyDerivation,
  testMemoryUsage,
  runPerformanceTests,
  formatTime,
  formatThroughput,
  assert
};
