#!/usr/bin/env node

/**
 * Benchmark Configuration
 * Defines test parameters, data sizes, and algorithm categories
 */

// Test data sizes (in bytes)
export const DATA_SIZES = [
  { name: '1KB', size: 1024 },
  { name: '4KB', size: 4096 },
  { name: '16KB', size: 16384 },
  { name: '64KB', size: 65536 },
  { name: '256KB', size: 262144 },
  { name: '1MB', size: 1048576 }
];

// Quick test data sizes for faster benchmarks
export const QUICK_DATA_SIZES = [
  { name: '1KB', size: 1024 },
  { name: '16KB', size: 16384 },
  { name: '64KB', size: 65536 }
];

// Memory benchmark configuration
export const MEMORY_CONFIG = {
  testDataSize: 16 * 1024, // 16KB (reduced from 64KB)
  iterations: 100, // reduced from 1000
  gcEnabled: true
};

// Performance benchmark configuration
export const PERFORMANCE_CONFIG = {
  minSamples: 3,
  maxTime: 2, // seconds per test (reduced from 5)
  initCount: 1,
  minTime: 0.02 // minimum time per test (reduced from 0.05)
};

// Algorithm categories and their implementations
export const ALGORITHM_CATEGORIES = {
  symmetric: {
    name: 'Symmetric Encryption',
    algorithms: {
      'aes-256-gcm': {
        name: 'AES-256-GCM',
        implementations: ['nodejs', 'noble', 'libsilver-aws', 'libsilver-rust'],
        keySize: 32,
        operations: ['encrypt', 'decrypt']
      },
      'chacha20-poly1305': {
        name: 'ChaCha20-Poly1305',
        implementations: ['nodejs', 'noble', 'libsilver'],
        keySize: 32,
        operations: ['encrypt', 'decrypt']
      }
    }
  },
  
  asymmetric: {
    name: 'Asymmetric Encryption',
    algorithms: {
      'rsa-oaep': {
        name: 'RSA-OAEP',
        implementations: ['nodejs', 'libsilver'],
        keySize: 2048,
        operations: ['encrypt', 'decrypt', 'keygen'],
        maxDataSize: 190 // RSA-2048 with OAEP padding limit
      }
    }
  },
  
  signatures: {
    name: 'Digital Signatures',
    algorithms: {
      'ed25519': {
        name: 'Ed25519',
        implementations: ['nodejs', 'libsilver'],
        keySize: 32,
        operations: ['sign', 'verify', 'keygen']
      },
      'ecdsa-p256': {
        name: 'ECDSA P-256',
        implementations: ['nodejs', 'libsilver'],
        keySize: 32,
        operations: ['sign', 'verify', 'keygen']
      }
    }
  },
  
  hash: {
    name: 'Hash Functions',
    algorithms: {
      'sha256': {
        name: 'SHA-256',
        implementations: ['nodejs', 'libsilver'],
        operations: ['hash']
      },
      'sha512': {
        name: 'SHA-512',
        implementations: ['nodejs', 'libsilver'],
        operations: ['hash']
      },
      'blake3': {
        name: 'BLAKE3',
        implementations: ['libsilver'],
        operations: ['hash']
      }
    }
  },
  
  kdf: {
    name: 'Key Derivation Functions',
    algorithms: {
      'pbkdf2-sha256': {
        name: 'PBKDF2-SHA256',
        implementations: ['nodejs', 'libsilver'],
        operations: ['derive'],
        iterations: 100000,
        keyLength: 32
      },
      'argon2': {
        name: 'Argon2',
        implementations: ['libsilver'],
        operations: ['derive'],
        keyLength: 32
      },
      'hkdf-sha256': {
        name: 'HKDF-SHA256',
        implementations: ['nodejs', 'libsilver'],
        operations: ['derive'],
        keyLength: 32
      }
    }
  },
  
  pqc: {
    name: 'Post-Quantum Cryptography',
    algorithms: {
      'ml-kem-512': {
        name: 'ML-KEM-512',
        implementations: ['libsilver'],
        operations: ['keygen', 'encapsulate', 'decapsulate']
      },
      'ml-kem-768': {
        name: 'ML-KEM-768',
        implementations: ['libsilver'],
        operations: ['keygen', 'encapsulate', 'decapsulate']
      },
      'ml-kem-1024': {
        name: 'ML-KEM-1024',
        implementations: ['libsilver'],
        operations: ['keygen', 'encapsulate', 'decapsulate']
      },
      'ml-dsa-44': {
        name: 'ML-DSA-44',
        implementations: ['libsilver'],
        operations: ['keygen', 'sign', 'verify']
      },
      'ml-dsa-65': {
        name: 'ML-DSA-65',
        implementations: ['libsilver'],
        operations: ['keygen', 'sign', 'verify']
      },
      'ml-dsa-87': {
        name: 'ML-DSA-87',
        implementations: ['libsilver'],
        operations: ['keygen', 'sign', 'verify']
      }
    }
  }
};

// Implementation display names
export const IMPLEMENTATION_NAMES = {
  'nodejs': 'Node.js Native',
  'noble': '@noble/ciphers',
  'libsilver': 'LibSilver',
  'libsilver-aws': 'LibSilver (AWS-LC-RS)',
  'libsilver-rust': 'LibSilver (RustCrypto)'
};

// Report configuration
export const REPORT_CONFIG = {
  outputFile: 'performance_report.md',
  includeSystemInfo: true,
  includeMemoryAnalysis: true,
  includePerformanceAnalysis: true,
  includeThroughputAnalysis: true
};
