#!/usr/bin/env node

import Benchmark from 'benchmark';
import crypto from 'crypto';
import os from 'os';
import { gcm } from '@noble/ciphers/aes';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { SymmetricCrypto } from 'libsilver-nodejs';

// Test data sizes (in bytes)
const DATA_SIZES = [
  { name: '1KB', size: 1024 },
  { name: '4KB', size: 4096 },
  { name: '16KB', size: 16384 },
  { name: '64KB', size: 65536 },
  { name: '256KB', size: 262144 },
  { name: '1MB', size: 1048576 }
];

// Generate test data
function generateTestData(size) {
  return crypto.randomBytes(size);
}

// Generate AES-256 key
function generateAESKey() {
  return crypto.randomBytes(32);
}

// Generate ChaCha20 key
function generateChaChaKey() {
  return crypto.randomBytes(32);
}

// Node.js native crypto implementations
class NodeCrypto {
  static encryptAES(plaintext, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, encrypted, tag]);
  }

  static decryptAES(ciphertext, key) {
    const iv = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(-16);
    const encrypted = ciphertext.slice(12, -16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted);
    decipher.final();

    return decrypted;
  }

  static encryptChaCha20(plaintext, key) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce);

    let encrypted = cipher.update(plaintext);
    cipher.final();
    const tag = cipher.getAuthTag();

    return Buffer.concat([nonce, encrypted, tag]);
  }

  static decryptChaCha20(ciphertext, key) {
    const nonce = ciphertext.slice(0, 12);
    const tag = ciphertext.slice(-16);
    const encrypted = ciphertext.slice(12, -16);

    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted);
    decipher.final();

    return decrypted;
  }
}

// @noble/ciphers implementations
class NobleCrypto {
  static encryptAES(plaintext, key) {
    const nonce = crypto.randomBytes(12);
    const aes = gcm(key, nonce);
    const encrypted = aes.encrypt(plaintext);
    return Buffer.concat([nonce, encrypted]);
  }

  static decryptAES(ciphertext, key) {
    const nonce = ciphertext.slice(0, 12);
    const encrypted = ciphertext.slice(12);
    const aes = gcm(key, nonce);
    return Buffer.from(aes.decrypt(encrypted));
  }

  static encryptChaCha20(plaintext, key) {
    const nonce = crypto.randomBytes(12);
    const chacha = chacha20poly1305(key, nonce);
    const encrypted = chacha.encrypt(plaintext);
    return Buffer.concat([nonce, encrypted]);
  }

  static decryptChaCha20(ciphertext, key) {
    const nonce = ciphertext.slice(0, 12);
    const encrypted = ciphertext.slice(12);
    const chacha = chacha20poly1305(key, nonce);
    return Buffer.from(chacha.decrypt(encrypted));
  }
}

// LibSilver implementations
class LibSilverCrypto {
  static encryptAES(plaintext, key) {
    return SymmetricCrypto.encryptAes(plaintext, key);
  }

  static decryptAES(ciphertext, key) {
    return SymmetricCrypto.decryptAes(ciphertext, key);
  }

  static encryptChaCha20(plaintext, key) {
    return SymmetricCrypto.encryptChacha20(plaintext, key);
  }

  static decryptChaCha20(ciphertext, key) {
    return SymmetricCrypto.decryptChacha20(ciphertext, key);
  }
}

// Benchmark runner
function runBenchmarks() {
  console.log('🚀 LibSilver vs Node.js Crypto vs @noble/ciphers Performance Benchmark\n');
  console.log('Platform:', process.platform);
  console.log('Architecture:', process.arch);
  console.log('Node.js Version:', process.version);
  console.log('V8 Version:', process.versions.v8);
  console.log('CPU:', os.cpus()[0].model);
  console.log('Memory:', Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB');
  console.log('\n' + '='.repeat(80) + '\n');

  for (const dataSize of DATA_SIZES) {
    console.log(`📊 Benchmarking ${dataSize.name} (${dataSize.size.toLocaleString()} bytes)\n`);
    
    const plaintext = generateTestData(dataSize.size);
    const aesKey = generateAESKey();
    const chachaKey = generateChaChaKey();

    // Pre-encrypt data for decryption benchmarks
    const nodeAESCiphertext = NodeCrypto.encryptAES(plaintext, aesKey);
    const nobleAESCiphertext = NobleCrypto.encryptAES(plaintext, aesKey);
    const libsilverAESCiphertext = LibSilverCrypto.encryptAES(plaintext, aesKey);

    const nodeChaChatext = NodeCrypto.encryptChaCha20(plaintext, chachaKey);
    const nobleChaChatext = NobleCrypto.encryptChaCha20(plaintext, chachaKey);
    const libsilverChaChatext = LibSilverCrypto.encryptChaCha20(plaintext, chachaKey);

    const suite = new Benchmark.Suite();

    // AES-256-GCM Encryption Benchmarks
    suite
      .add(`Node.js AES-256-GCM Encrypt (${dataSize.name})`, function() {
        NodeCrypto.encryptAES(plaintext, aesKey);
      })
      .add(`@noble/ciphers AES-256-GCM Encrypt (${dataSize.name})`, function() {
        NobleCrypto.encryptAES(plaintext, aesKey);
      })
      .add(`LibSilver AES-256-GCM Encrypt (${dataSize.name})`, function() {
        LibSilverCrypto.encryptAES(plaintext, aesKey);
      })

      // AES-256-GCM Decryption Benchmarks
      .add(`Node.js AES-256-GCM Decrypt (${dataSize.name})`, function() {
        NodeCrypto.decryptAES(nodeAESCiphertext, aesKey);
      })
      .add(`@noble/ciphers AES-256-GCM Decrypt (${dataSize.name})`, function() {
        NobleCrypto.decryptAES(nobleAESCiphertext, aesKey);
      })
      .add(`LibSilver AES-256-GCM Decrypt (${dataSize.name})`, function() {
        LibSilverCrypto.decryptAES(libsilverAESCiphertext, aesKey);
      })

      // ChaCha20-Poly1305 Encryption Benchmarks
      .add(`Node.js ChaCha20-Poly1305 Encrypt (${dataSize.name})`, function() {
        NodeCrypto.encryptChaCha20(plaintext, chachaKey);
      })
      .add(`@noble/ciphers ChaCha20-Poly1305 Encrypt (${dataSize.name})`, function() {
        NobleCrypto.encryptChaCha20(plaintext, chachaKey);
      })
      .add(`LibSilver ChaCha20-Poly1305 Encrypt (${dataSize.name})`, function() {
        LibSilverCrypto.encryptChaCha20(plaintext, chachaKey);
      })

      // ChaCha20-Poly1305 Decryption Benchmarks
      .add(`Node.js ChaCha20-Poly1305 Decrypt (${dataSize.name})`, function() {
        NodeCrypto.decryptChaCha20(nodeChaChatext, chachaKey);
      })
      .add(`@noble/ciphers ChaCha20-Poly1305 Decrypt (${dataSize.name})`, function() {
        NobleCrypto.decryptChaCha20(nobleChaChatext, chachaKey);
      })
      .add(`LibSilver ChaCha20-Poly1305 Decrypt (${dataSize.name})`, function() {
        LibSilverCrypto.decryptChaCha20(libsilverChaChatext, chachaKey);
      })

      .on('cycle', function(event) {
        const benchmark = event.target;
        const opsPerSec = benchmark.hz.toFixed(2);
        const throughputMBps = ((dataSize.size * benchmark.hz) / (1024 * 1024)).toFixed(2);
        console.log(`  ${benchmark.name}: ${opsPerSec} ops/sec (${throughputMBps} MB/s)`);
      })
      .on('complete', function() {
        console.log('\n' + '-'.repeat(60) + '\n');
      })
      .run({ 'async': false });
  }

  console.log('✅ Benchmark completed!\n');
}

// Run benchmarks
runBenchmarks();
