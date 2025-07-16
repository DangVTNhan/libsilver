#!/usr/bin/env node

const { runAllTests } = require('./test.js');
const { runAllTests: runAwsLcAesTests } = require('./aws-lc-aes-test.js');
const { runPostQuantumTests } = require('./post-quantum-test.js');
const { runIntegrationTests } = require('./integration-test.js');
const { runPerformanceTests } = require('./performance-test.js');

function printHeader(title) {
  const line = '='.repeat(60);
  console.log(`\n${line}`);
  console.log(`${title.toUpperCase().padStart((60 + title.length) / 2)}`);
  console.log(line);
}

function printSeparator() {
  console.log('\n' + '-'.repeat(60));
}

async function runTestSuite(name, testFunction, options = {}) {
  const { skipOnError = false, optional = false } = options;
  
  try {
    printHeader(name);
    const startTime = Date.now();
    
    await testFunction();
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    console.log(`\n✅ ${name} completed successfully in ${duration}ms`);
    return { success: true, duration, error: null };
  } catch (error) {
    console.error(`\n❌ ${name} failed:`, error.message);
    
    if (!skipOnError && !optional) {
      console.error('Stack trace:', error.stack);
      throw error;
    }
    
    return { success: false, duration: 0, error: error.message };
  }
}

async function runAllTestSuites() {
  console.log('🧪 LibSilver Node.js Comprehensive Test Suite');
  console.log('='.repeat(60));
  console.log('Running all test categories...\n');
  
  const results = [];
  const startTime = Date.now();
  
  try {
    // 1. Basic functionality tests
    const basicResult = await runTestSuite('Basic Functionality Tests', () => {
      return new Promise((resolve, reject) => {
        try {
          runAllTests();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    results.push({ name: 'Basic Tests', ...basicResult });

    printSeparator();

    // 2. AWS-LC-RS AES tests
    const awsLcResult = await runTestSuite('AWS-LC-RS AES Tests', () => {
      return new Promise((resolve, reject) => {
        try {
          runAwsLcAesTests();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    results.push({ name: 'AWS-LC-RS AES Tests', ...awsLcResult });

    printSeparator();

    // 3. Post-quantum cryptography tests
    const pqResult = await runTestSuite('Post-Quantum Cryptography Tests', () => {
      return new Promise((resolve, reject) => {
        try {
          runPostQuantumTests();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    results.push({ name: 'Post-Quantum Tests', ...pqResult });

    printSeparator();

    // 4. Integration tests
    const integrationResult = await runTestSuite('Integration Tests', () => {
      return new Promise((resolve, reject) => {
        try {
          runIntegrationTests();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    results.push({ name: 'Integration Tests', ...integrationResult });
    
    printSeparator();
    
    // 5. Performance tests (optional - don't fail the entire suite if these fail)
    const performanceResult = await runTestSuite('Performance Tests', () => {
      return new Promise((resolve, reject) => {
        try {
          runPerformanceTests();
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    }, { optional: true, skipOnError: true });
    results.push({ name: 'Performance Tests', ...performanceResult });
    
    // Print final summary
    const endTime = Date.now();
    const totalDuration = endTime - startTime;
    
    printHeader('Test Suite Summary');
    
    console.log('Test Category                | Status | Duration');
    console.log('-----------------------------|--------|----------');
    
    let totalPassed = 0;
    let totalFailed = 0;
    
    for (const result of results) {
      const status = result.success ? '✅ PASS' : '❌ FAIL';
      const duration = result.success ? `${result.duration}ms` : 'N/A';
      
      console.log(`${result.name.padEnd(28)} | ${status.padEnd(6)} | ${duration.padStart(8)}`);
      
      if (result.success) {
        totalPassed++;
      } else {
        totalFailed++;
        if (result.error) {
          console.log(`  Error: ${result.error}`);
        }
      }
    }
    
    console.log('-'.repeat(50));
    console.log(`Total: ${totalPassed} passed, ${totalFailed} failed`);
    console.log(`Total execution time: ${totalDuration}ms`);
    
    if (totalFailed === 0) {
      console.log('\n🎉 ALL TEST SUITES PASSED! 🎉');
      console.log('\nLibSilver Node.js bindings are working correctly.');
      console.log('The library provides comprehensive cryptographic functionality including:');
      console.log('  • Classical cryptography (AES, ChaCha20, RSA, Ed25519, ECDSA)');
      console.log('  • Post-quantum cryptography (ML-KEM, ML-DSA)');
      console.log('  • Hash functions (SHA-256, SHA-512, BLAKE3, HMAC)');
      console.log('  • Key derivation (Argon2, PBKDF2, HKDF)');
      console.log('  • Secure random generation');
      console.log('  • Integration scenarios and performance optimization');
    } else {
      console.log(`\n⚠️  ${totalFailed} test suite(s) failed.`);
      
      // Only exit with error code if critical tests failed
      const criticalFailures = results.filter(r => !r.success && r.name !== 'Performance Tests');
      if (criticalFailures.length > 0) {
        console.log('Critical test failures detected. Please review the errors above.');
        process.exit(1);
      } else {
        console.log('Only optional tests failed. Core functionality is working.');
      }
    }
    
  } catch (error) {
    console.error('\n💥 Test suite execution failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

// Command line options
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    basic: false,
    postQuantum: false,
    integration: false,
    performance: false,
    all: false,
    help: false
  };
  
  for (const arg of args) {
    switch (arg) {
      case '--basic':
        options.basic = true;
        break;
      case '--post-quantum':
      case '--pq':
        options.postQuantum = true;
        break;
      case '--integration':
        options.integration = true;
        break;
      case '--performance':
      case '--perf':
        options.performance = true;
        break;
      case '--all':
        options.all = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        console.error(`Unknown option: ${arg}`);
        options.help = true;
        break;
    }
  }
  
  // If no specific tests selected, run all
  if (!options.basic && !options.postQuantum && !options.integration && !options.performance) {
    options.all = true;
  }
  
  return options;
}

function printHelp() {
  console.log('LibSilver Node.js Test Runner');
  console.log('');
  console.log('Usage: node run-all-tests.js [options]');
  console.log('');
  console.log('Options:');
  console.log('  --basic         Run basic functionality tests only');
  console.log('  --post-quantum  Run post-quantum cryptography tests only');
  console.log('  --pq            Alias for --post-quantum');
  console.log('  --integration   Run integration tests only');
  console.log('  --performance   Run performance tests only');
  console.log('  --perf          Alias for --performance');
  console.log('  --all           Run all test suites (default)');
  console.log('  --help, -h      Show this help message');
  console.log('');
  console.log('Examples:');
  console.log('  node run-all-tests.js                    # Run all tests');
  console.log('  node run-all-tests.js --basic            # Run basic tests only');
  console.log('  node run-all-tests.js --pq --integration # Run PQ and integration tests');
}

async function main() {
  const options = parseArgs();
  
  if (options.help) {
    printHelp();
    return;
  }
  
  if (options.all) {
    await runAllTestSuites();
  } else {
    // Run selected test suites
    const results = [];
    const startTime = Date.now();
    
    if (options.basic) {
      const result = await runTestSuite('Basic Functionality Tests', () => {
        return new Promise((resolve, reject) => {
          try {
            runAllTests();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
      results.push({ name: 'Basic Tests', ...result });
    }
    
    if (options.postQuantum) {
      const result = await runTestSuite('Post-Quantum Cryptography Tests', () => {
        return new Promise((resolve, reject) => {
          try {
            runPostQuantumTests();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
      results.push({ name: 'Post-Quantum Tests', ...result });
    }
    
    if (options.integration) {
      const result = await runTestSuite('Integration Tests', () => {
        return new Promise((resolve, reject) => {
          try {
            runIntegrationTests();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      });
      results.push({ name: 'Integration Tests', ...result });
    }
    
    if (options.performance) {
      const result = await runTestSuite('Performance Tests', () => {
        return new Promise((resolve, reject) => {
          try {
            runPerformanceTests();
            resolve();
          } catch (error) {
            reject(error);
          }
        });
      }, { optional: true, skipOnError: true });
      results.push({ name: 'Performance Tests', ...result });
    }
    
    // Print summary for selected tests
    const endTime = Date.now();
    const totalDuration = endTime - startTime;
    
    printHeader('Selected Tests Summary');
    
    const passed = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    
    console.log(`Completed ${results.length} test suite(s) in ${totalDuration}ms`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    
    if (failed > 0) {
      process.exit(1);
    }
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = {
  runAllTestSuites,
  runTestSuite,
  parseArgs,
  printHelp
};
