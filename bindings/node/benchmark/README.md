# LibSilver Node.js Benchmark Suite v2.0

A comprehensive benchmark suite for evaluating the performance and memory usage of LibSilver cryptographic algorithms against industry-standard implementations.

## 🚀 Features

- **Multi-Algorithm Support**: Benchmarks symmetric encryption, asymmetric encryption, hash functions, key derivation, and post-quantum cryptography
- **Multiple Implementations**: Compares LibSilver against Node.js native crypto and @noble/ciphers
- **Performance Analysis**: Measures operations per second, throughput, and statistical reliability
- **Memory Profiling**: Tracks memory usage patterns and garbage collection impact
- **Automated Reporting**: Generates comprehensive markdown reports with analysis and recommendations
- **Flexible Configuration**: Supports quick tests, category-specific benchmarks, and custom data sizes

## 📊 Supported Algorithms

### Symmetric Encryption
- **AES-256-GCM**: Node.js native, @noble/ciphers, LibSilver (AWS-LC-RS), LibSilver (RustCrypto)
- **ChaCha20-Poly1305**: Node.js native, @noble/ciphers, LibSilver

### Asymmetric Encryption
- **RSA-OAEP**: Node.js native, LibSilver

### Digital Signatures
- **Ed25519**: Node.js native, LibSilver
- **ECDSA P-256**: Node.js native, LibSilver

### Hash Functions
- **SHA-256**: Node.js native, LibSilver
- **SHA-512**: Node.js native, LibSilver
- **BLAKE3**: LibSilver only

### Key Derivation Functions
- **PBKDF2-SHA256**: Node.js native, LibSilver
- **Argon2**: LibSilver only
- **HKDF-SHA256**: Node.js native, LibSilver

### Post-Quantum Cryptography
- **ML-KEM** (512, 768, 1024): LibSilver only
- **ML-DSA** (44, 65, 87): LibSilver only

## 🛠️ Installation

```bash
cd bindings/node/benchmark
npm install
```

## 📋 Usage

### Run All Benchmarks
```bash
npm run benchmark
```

### Quick Benchmark (Fewer Data Sizes)
```bash
npm run benchmark:quick
```

### Conservative Benchmark (Minimal Resource Usage)
```bash
npm run benchmark:conservative
```

### Minimal Test (Troubleshooting)
```bash
npm run benchmark:minimal
```

### Category-Specific Benchmarks
```bash
npm run benchmark:symmetric    # Symmetric encryption only
npm run benchmark:asymmetric   # Asymmetric encryption only
npm run benchmark:hash         # Hash functions only
npm run benchmark:kdf          # Key derivation functions only
npm run benchmark:pqc          # Post-quantum cryptography only
```

### Memory Analysis Only
```bash
npm run memory
```

### Generate Report from Existing Results
```bash
npm run report
```

### Command Line Options
```bash
node benchmark-runner.js [options]

Options:
  --quick              Run quick benchmark with fewer data sizes
  --report-only        Generate report from existing results only
  --category <name>    Run benchmarks for specific category only
  --help              Show help message
```

## 📈 Output

The benchmark suite generates:

1. **Console Output**: Real-time progress and results
2. **performance_report.md**: Comprehensive markdown report with:
   - System information
   - Executive summary with key findings
   - Detailed performance results tables
   - Memory usage analysis
   - Throughput analysis with charts
   - Smart recommendations

## 🏗️ Architecture

```
benchmark/
├── config.js                 # Benchmark configuration
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
│   ├── kdf-benchmark.js      # (planned)
│   └── pqc-benchmark.js      # (planned)
└── README.md
```

## ⚙️ Configuration

Edit `config.js` to customize:

- **Data sizes**: Test with different payload sizes
- **Performance settings**: Adjust benchmark duration and samples
- **Memory settings**: Configure memory test parameters
- **Algorithm categories**: Enable/disable specific algorithms
- **Report format**: Customize report generation

## 🧪 Testing

Test the benchmark system:
```bash
node test-benchmark.js
```

## 📊 Sample Results

The benchmark generates tables like:

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | Node.js Native | encrypt | 45,234 | ±1.2% | 44.17 MB/s |
| 1KB | LibSilver (AWS-LC-RS) | encrypt | 52,891 | ±0.8% | 51.65 MB/s |
| 1KB | @noble/ciphers | encrypt | 38,742 | ±1.5% | 37.83 MB/s |

## 🎯 Key Metrics

- **Operations per second (ops/sec)**: Raw performance measurement
- **Relative Margin of Error (RME)**: Statistical reliability indicator
- **Throughput (MB/s)**: Data processing rate
- **Memory per operation**: Memory efficiency
- **Time per operation**: Latency measurement

## 🔧 Troubleshooting

### Common Issues

1. **Process killed (`zsh: killed`)**:
   - Use conservative benchmark: `npm run benchmark:conservative`
   - Increase memory limit: `node --max-old-space-size=4096 benchmark-runner.js`
   - Run category-specific tests: `npm run benchmark:symmetric`

2. **Missing implementations**: Some algorithms may not be available on all platforms

3. **Memory measurement**: Run with `--expose-gc` flag for accurate memory profiling

4. **Long benchmark times**: Use `--quick` flag for faster testing

### Troubleshooting Steps

1. **Test basic functionality**:
   ```bash
   npm run benchmark:minimal
   ```

2. **Run conservative benchmark**:
   ```bash
   npm run benchmark:conservative
   ```

3. **Increase memory limit**:
   ```bash
   node --max-old-space-size=8192 benchmark-runner.js --quick
   ```

4. **Run one category at a time**:
   ```bash
   npm run benchmark:symmetric
   npm run benchmark:hash
   ```

### Debug Mode
```bash
NODE_ENV=debug node --max-old-space-size=4096 benchmark-runner.js
```

## 🤝 Contributing

To add new algorithms or implementations:

1. Add algorithm configuration to `config.js`
2. Create implementation wrapper in `implementations/`
3. Add benchmark module in `algorithms/`
4. Update `benchmark-runner.js` to include new category

## 📝 License

This benchmark suite is part of the LibSilver project and follows the same license terms.
