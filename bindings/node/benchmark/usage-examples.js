#!/usr/bin/env node

/**
 * Usage Examples for LibSilver Benchmark Suite v2.0
 * Demonstrates different ways to run benchmarks
 */

console.log(`
🚀 LibSilver Benchmark Suite v2.0 - Usage Examples
==================================================

The new benchmark system supports multiple algorithms and implementations
with comprehensive performance and memory analysis.

📊 Available Commands:
=====================

1. Run all benchmarks (comprehensive):
   npm run benchmark

2. Quick benchmark (fewer data sizes):
   npm run benchmark:quick

3. Category-specific benchmarks:
   npm run benchmark:symmetric    # AES, ChaCha20
   npm run benchmark:asymmetric   # RSA
   npm run benchmark:hash         # SHA-256, SHA-512, BLAKE3
   npm run benchmark:kdf          # PBKDF2, Argon2, HKDF
   npm run benchmark:pqc          # ML-KEM, ML-DSA

4. Memory analysis only:
   npm run memory

5. Generate report from existing results:
   npm run report

🔧 Command Line Options:
=======================

node benchmark-runner.js [options]

--quick              Run with fewer data sizes (1KB, 16KB, 64KB)
--report-only        Generate report without running benchmarks
--category <name>    Run specific category only
--help              Show help message

📈 Supported Algorithms:
=======================

Symmetric Encryption:
- AES-256-GCM (Node.js, @noble/ciphers, LibSilver AWS-LC-RS, LibSilver RustCrypto)
- ChaCha20-Poly1305 (Node.js, @noble/ciphers, LibSilver)

Asymmetric Encryption:
- RSA-OAEP (Node.js, LibSilver)

Digital Signatures:
- Ed25519 (Node.js, LibSilver)
- ECDSA P-256 (Node.js, LibSilver)

Hash Functions:
- SHA-256 (Node.js, LibSilver)
- SHA-512 (Node.js, LibSilver)
- BLAKE3 (LibSilver only)

Key Derivation:
- PBKDF2-SHA256 (Node.js, LibSilver)
- Argon2 (LibSilver only)
- HKDF-SHA256 (Node.js, LibSilver)

Post-Quantum Cryptography:
- ML-KEM (512, 768, 1024) (LibSilver only)
- ML-DSA (44, 65, 87) (LibSilver only)

📊 Output:
=========

The benchmark generates:
1. Real-time console output with progress
2. performance_report.md - Comprehensive markdown report with:
   - System information
   - Executive summary with key findings
   - Detailed performance tables
   - Memory usage analysis
   - Throughput analysis
   - Smart recommendations

🎯 Key Metrics:
==============

- Operations per second (ops/sec): Raw performance
- Relative Margin of Error (RME): Statistical reliability
- Throughput (MB/s): Data processing rate
- Memory per operation: Memory efficiency
- Time per operation: Latency measurement

🔍 Example Results:
==================

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | LibSilver (AWS-LC-RS) | encrypt | 878,711 | ±0.44% | 858.12 MB/s |
| 1KB | Node.js Native | encrypt | 381,573 | ±0.48% | 372.63 MB/s |
| 1KB | @noble/ciphers | encrypt | 48,376 | ±0.29% | 47.24 MB/s |

🚀 Quick Start:
==============

1. Install dependencies:
   cd bindings/node/benchmark
   npm install

2. Run quick benchmark:
   npm run benchmark:quick

3. View generated report:
   cat performance_report.md

4. Run specific category:
   npm run benchmark:symmetric

🔧 Customization:
================

Edit config.js to customize:
- Data sizes for testing
- Performance benchmark settings
- Memory test parameters
- Algorithm categories
- Report format

📝 Architecture:
===============

benchmark/
├── config.js                 # Configuration
├── benchmark-runner.js       # Main orchestrator
├── report-generator.js       # Report generation
├── implementations/          # Implementation wrappers
│   ├── nodejs-impl.js        # Node.js native crypto
│   ├── noble-impl.js         # @noble/ciphers
│   └── libsilver-impl.js     # LibSilver bindings
├── algorithms/               # Algorithm-specific benchmarks
│   ├── symmetric-benchmark.js
│   ├── asymmetric-benchmark.js
│   ├── hash-benchmark.js
│   └── ...
└── README.md

✅ Ready to benchmark!
=====================

The system is now ready to comprehensively analyze LibSilver's performance
across multiple algorithms and implementations.

Run 'npm run benchmark:quick' to get started!
`);
