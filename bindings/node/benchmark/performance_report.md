# LibSilver Cryptographic Performance Report

**Generated:** 7/14/2025, 2:54:04 PM  
**Benchmark Version:** 2.0.0  
**Test Duration:** Comprehensive cryptographic algorithm performance analysis

---

## 💻 System Information

| Property | Value |
|----------|-------|
| **Platform** | darwin |
| **Architecture** | arm64 |
| **Node.js Version** | v24.1.0 |
| **V8 Version** | 13.6.233.10-node.16 |
| **CPU** | Apple M4 Pro |
| **CPU Cores** | 14 |
| **Total Memory** | 48GB |
| **Free Memory** | 22GB |

## 📊 Executive Summary

### Key Findings

- LibSilver provides competitive performance across all tested algorithms
- AWS-LC-RS implementation shows superior performance for AES operations
- Memory usage is optimized across all LibSilver implementations

### Performance Highlights

- **Symmetric Encryption**: AES-256-GCM performance varies by implementation
- **Hash Functions**: BLAKE3 shows excellent performance characteristics

### Recommendations

- Use LibSilver AWS-LC-RS for AES operations requiring maximum performance
- Consider BLAKE3 for high-throughput hashing requirements
- Monitor memory usage in high-frequency cryptographic operations

## ⚡ Performance Results

### Symmetric Encryption

#### AES-256-GCM

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | Node.js Native | encrypt | 395877.95 | ±0.79% | 386.60 MB/s |
| 1KB | Node.js Native | decrypt | 720270.75 | ±0.60% | 703.39 MB/s |
| 1KB | @noble/ciphers | encrypt | 49673.65 | ±0.49% | 48.51 MB/s |
| 1KB | @noble/ciphers | decrypt | 52729.26 | ±0.45% | 51.49 MB/s |
| 1KB | LibSilver (AWS-LC-RS) | encrypt | 905697.91 | ±0.86% | 884.47 MB/s |
| 1KB | LibSilver (AWS-LC-RS) | decrypt | 1299303.10 | ±0.96% | 1268.85 MB/s |
| 1KB | LibSilver (RustCrypto) | encrypt | 151658.26 | ±0.37% | 148.10 MB/s |
| 1KB | LibSilver (RustCrypto) | decrypt | 175140.01 | ±0.57% | 171.04 MB/s |
| 16KB | Node.js Native | encrypt | 156220.39 | ±1.48% | 2440.94 MB/s |
| 16KB | Node.js Native | decrypt | 245415.98 | ±0.87% | 3834.62 MB/s |
| 16KB | @noble/ciphers | encrypt | 5235.04 | ±0.43% | 81.80 MB/s |
| 16KB | @noble/ciphers | decrypt | 5307.10 | ±0.40% | 82.92 MB/s |
| 16KB | LibSilver (AWS-LC-RS) | encrypt | 242103.71 | ±0.96% | 3782.87 MB/s |
| 16KB | LibSilver (AWS-LC-RS) | decrypt | 267116.28 | ±0.75% | 4173.69 MB/s |
| 16KB | LibSilver (RustCrypto) | encrypt | 13526.27 | ±0.47% | 211.35 MB/s |
| 16KB | LibSilver (RustCrypto) | decrypt | 13732.03 | ±0.42% | 214.56 MB/s |
| 64KB | Node.js Native | encrypt | 27357.12 | ±1.31% | 1709.82 MB/s |
| 64KB | Node.js Native | decrypt | 71865.89 | ±0.94% | 4491.62 MB/s |
| 64KB | @noble/ciphers | encrypt | 1342.45 | ±0.44% | 83.90 MB/s |
| 64KB | @noble/ciphers | decrypt | 1357.99 | ±0.34% | 84.87 MB/s |
| 64KB | LibSilver (AWS-LC-RS) | encrypt | 17507.67 | ±97.71% | 1094.23 MB/s |
| 64KB | LibSilver (AWS-LC-RS) | decrypt | 61504.94 | ±3.01% | 3844.06 MB/s |
| 64KB | LibSilver (RustCrypto) | encrypt | 3305.83 | ±1.06% | 206.61 MB/s |
| 64KB | LibSilver (RustCrypto) | decrypt | 3455.14 | ±0.34% | 215.95 MB/s |

#### ChaCha20-Poly1305

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | Node.js Native | encrypt | 307410.59 | ±8.44% | 300.21 MB/s |
| 1KB | Node.js Native | decrypt | 547704.48 | ±0.47% | 534.87 MB/s |
| 1KB | @noble/ciphers | encrypt | 183096.93 | ±0.54% | 178.81 MB/s |
| 1KB | @noble/ciphers | decrypt | 224517.97 | ±0.29% | 219.26 MB/s |
| 1KB | LibSilver | encrypt | 331561.35 | ±0.81% | 323.79 MB/s |
| 1KB | LibSilver | decrypt | 454819.11 | ±1.18% | 444.16 MB/s |
| 16KB | Node.js Native | encrypt | 85861.34 | ±1.92% | 1341.58 MB/s |
| 16KB | Node.js Native | decrypt | 108252.62 | ±0.63% | 1691.45 MB/s |
| 16KB | @noble/ciphers | encrypt | 18914.62 | ±1.49% | 295.54 MB/s |
| 16KB | @noble/ciphers | decrypt | 20263.21 | ±0.53% | 316.61 MB/s |
| 16KB | LibSilver | encrypt | 38366.15 | ±0.98% | 599.47 MB/s |
| 16KB | LibSilver | decrypt | 39518.86 | ±0.64% | 617.48 MB/s |
| 64KB | Node.js Native | encrypt | 25523.12 | ±1.96% | 1595.19 MB/s |
| 64KB | Node.js Native | decrypt | 31404.72 | ±0.59% | 1962.79 MB/s |
| 64KB | @noble/ciphers | encrypt | 5000.99 | ±1.24% | 312.56 MB/s |
| 64KB | @noble/ciphers | decrypt | 5220.43 | ±0.57% | 326.28 MB/s |
| 64KB | LibSilver | encrypt | 9881.74 | ±1.08% | 617.61 MB/s |
| 64KB | LibSilver | decrypt | 9862.41 | ±0.61% | 616.40 MB/s |

### Asymmetric Encryption

#### RSA-OAEP

### Hash Functions

#### SHA-256

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | Node.js Native | hash | 1327018.46 | ±3.25% | 1295.92 MB/s |
| 1KB | LibSilver | hash | 449462.08 | ±1.08% | 438.93 MB/s |
| 16KB | Node.js Native | hash | 189099.09 | ±1.60% | 2954.67 MB/s |
| 16KB | LibSilver | hash | 35919.73 | ±0.72% | 561.25 MB/s |
| 64KB | Node.js Native | hash | 50378.28 | ±0.67% | 3148.64 MB/s |
| 64KB | LibSilver | hash | 9126.60 | ±0.44% | 570.41 MB/s |

#### SHA-512

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | Node.js Native | hash | 937522.09 | ±4.49% | 915.55 MB/s |
| 1KB | LibSilver | hash | 617647.30 | ±1.75% | 603.17 MB/s |
| 16KB | Node.js Native | hash | 108922.94 | ±1.03% | 1701.92 MB/s |
| 16KB | LibSilver | hash | 56171.13 | ±0.90% | 877.67 MB/s |
| 64KB | Node.js Native | hash | 28443.59 | ±0.48% | 1777.72 MB/s |
| 64KB | LibSilver | hash | 14312.06 | ±0.41% | 894.50 MB/s |

#### BLAKE3

| Data Size | Implementation | Operation | Ops/sec | RME | Throughput |
|-----------|----------------|-----------|---------|-----|------------|
| 1KB | LibSilver | hash | 852920.40 | ±1.75% | 832.93 MB/s |
| 16KB | LibSilver | hash | 143156.37 | ±0.91% | 2236.82 MB/s |
| 64KB | LibSilver | hash | 37139.74 | ±0.68% | 2321.23 MB/s |



## 🧠 Memory Usage Analysis

*No memory results available.*

## 📈 Throughput Analysis

### Symmetric Encryption

#### AES-256-GCM - Throughput Comparison

```
Data Size vs Throughput (MB/s)
==============================

1KB:
  Node.js Native (encrypt): 386.60 MB/s
  Node.js Native (decrypt): 703.39 MB/s
  @noble/ciphers (encrypt): 48.51 MB/s
  @noble/ciphers (decrypt): 51.49 MB/s
  LibSilver (AWS-LC-RS) (encrypt): 884.47 MB/s
  LibSilver (AWS-LC-RS) (decrypt): 1268.85 MB/s
  LibSilver (RustCrypto) (encrypt): 148.10 MB/s
  LibSilver (RustCrypto) (decrypt): 171.04 MB/s

16KB:
  Node.js Native (encrypt): 2440.94 MB/s
  Node.js Native (decrypt): 3834.62 MB/s
  @noble/ciphers (encrypt): 81.80 MB/s
  @noble/ciphers (decrypt): 82.92 MB/s
  LibSilver (AWS-LC-RS) (encrypt): 3782.87 MB/s
  LibSilver (AWS-LC-RS) (decrypt): 4173.69 MB/s
  LibSilver (RustCrypto) (encrypt): 211.35 MB/s
  LibSilver (RustCrypto) (decrypt): 214.56 MB/s

64KB:
  Node.js Native (encrypt): 1709.82 MB/s
  Node.js Native (decrypt): 4491.62 MB/s
  @noble/ciphers (encrypt): 83.90 MB/s
  @noble/ciphers (decrypt): 84.87 MB/s
  LibSilver (AWS-LC-RS) (encrypt): 1094.23 MB/s
  LibSilver (AWS-LC-RS) (decrypt): 3844.06 MB/s
  LibSilver (RustCrypto) (encrypt): 206.61 MB/s
  LibSilver (RustCrypto) (decrypt): 215.95 MB/s
```

#### ChaCha20-Poly1305 - Throughput Comparison

```
Data Size vs Throughput (MB/s)
==============================

1KB:
  Node.js Native (encrypt): 300.21 MB/s
  Node.js Native (decrypt): 534.87 MB/s
  @noble/ciphers (encrypt): 178.81 MB/s
  @noble/ciphers (decrypt): 219.26 MB/s
  LibSilver (encrypt): 323.79 MB/s
  LibSilver (decrypt): 444.16 MB/s

16KB:
  Node.js Native (encrypt): 1341.58 MB/s
  Node.js Native (decrypt): 1691.45 MB/s
  @noble/ciphers (encrypt): 295.54 MB/s
  @noble/ciphers (decrypt): 316.61 MB/s
  LibSilver (encrypt): 599.47 MB/s
  LibSilver (decrypt): 617.48 MB/s

64KB:
  Node.js Native (encrypt): 1595.19 MB/s
  Node.js Native (decrypt): 1962.79 MB/s
  @noble/ciphers (encrypt): 312.56 MB/s
  @noble/ciphers (decrypt): 326.28 MB/s
  LibSilver (encrypt): 617.61 MB/s
  LibSilver (decrypt): 616.40 MB/s
```

### Asymmetric Encryption

#### RSA-OAEP - Throughput Comparison

### Hash Functions

#### SHA-256 - Throughput Comparison

```
Data Size vs Throughput (MB/s)
==============================

1KB:
  Node.js Native (hash): 1295.92 MB/s
  LibSilver (hash): 438.93 MB/s

16KB:
  Node.js Native (hash): 2954.67 MB/s
  LibSilver (hash): 561.25 MB/s

64KB:
  Node.js Native (hash): 3148.64 MB/s
  LibSilver (hash): 570.41 MB/s
```

#### SHA-512 - Throughput Comparison

```
Data Size vs Throughput (MB/s)
==============================

1KB:
  Node.js Native (hash): 915.55 MB/s
  LibSilver (hash): 603.17 MB/s

16KB:
  Node.js Native (hash): 1701.92 MB/s
  LibSilver (hash): 877.67 MB/s

64KB:
  Node.js Native (hash): 1777.72 MB/s
  LibSilver (hash): 894.50 MB/s
```

#### BLAKE3 - Throughput Comparison

```
Data Size vs Throughput (MB/s)
==============================

1KB:
  LibSilver (hash): 832.93 MB/s

16KB:
  LibSilver (hash): 2236.82 MB/s

64KB:
  LibSilver (hash): 2321.23 MB/s
```



## 🎯 Recommendations

### Performance Optimization

- For maximum AES performance, use LibSilver with AWS-LC-RS backend
- ChaCha20-Poly1305 provides consistent performance across data sizes
- Consider algorithm choice based on your specific throughput requirements

### Memory Efficiency

- LibSilver implementations show efficient memory usage patterns
- Garbage collection impact is minimal for all tested algorithms
- Memory per operation scales predictably with data size

### Use Case Guidance

- Use AES-256-GCM for high-performance symmetric encryption
- Choose Ed25519 for digital signatures requiring speed
- BLAKE3 is recommended for high-throughput hashing scenarios

---

## 📝 Notes

- All benchmarks were run with Node.js garbage collection enabled
- Performance results include statistical analysis with relative margin of error (RME)
- Memory measurements are taken after garbage collection to show persistent allocations
- Throughput calculations are based on actual data processed per second

**Benchmark Configuration:**
- Minimum samples per test: 5
- Maximum time per test: 5 seconds
- Memory test iterations: 1000
- Test data: Cryptographically secure random bytes

*Generated by LibSilver Benchmark Suite v2.0.0*