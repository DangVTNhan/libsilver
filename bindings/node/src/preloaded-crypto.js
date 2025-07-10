/**
 * LibSilver Preloaded Crypto - High-performance wrapper with cipher preloading
 * 
 * This module provides preloading capabilities similar to Node.js native crypto
 * to reduce initialization overhead and improve performance.
 */

const { SymmetricCrypto } = require('./index.js');

/**
 * Preloaded cipher manager
 */
class PreloadedCrypto {
  constructor() {
    this.preloadedKeys = new Set();
    this.stats = {
      cacheHits: 0,
      cacheMisses: 0,
      preloadedCiphers: 0
    };
  }

  /**
   * Preload cipher instances for given keys
   * @param {Buffer[]} aesKeys - AES-256 keys to preload
   * @param {Buffer[]} chachaKeys - ChaCha20 keys to preload
   */
  async preloadCiphers(aesKeys = [], chachaKeys = []) {
    const promises = [];

    // Preload AES ciphers
    for (const key of aesKeys) {
      if (!this.preloadedKeys.has(key.toString('hex'))) {
        promises.push(
          SymmetricCrypto.preloadAesCipher(key).then(() => {
            this.preloadedKeys.add(key.toString('hex'));
            this.stats.preloadedCiphers++;
          })
        );
      }
    }

    // Preload ChaCha20 ciphers
    for (const key of chachaKeys) {
      if (!this.preloadedKeys.has(key.toString('hex'))) {
        promises.push(
          SymmetricCrypto.preloadChacha20Cipher(key).then(() => {
            this.preloadedKeys.add(key.toString('hex'));
            this.stats.preloadedCiphers++;
          })
        );
      }
    }

    await Promise.all(promises);
    console.log(`✅ Preloaded ${promises.length} cipher instances`);
  }

  /**
   * High-performance AES-256-GCM encryption with preloaded ciphers
   * @param {Buffer} plaintext - Data to encrypt
   * @param {Buffer} key - AES-256 key
   * @returns {Buffer} Encrypted data
   */
  encryptAES(plaintext, key) {
    const keyHex = key.toString('hex');
    
    if (this.preloadedKeys.has(keyHex)) {
      this.stats.cacheHits++;
      return SymmetricCrypto.encryptAesCached(plaintext, key);
    } else {
      this.stats.cacheMisses++;
      // Preload for future use
      SymmetricCrypto.preloadAesCipher(key);
      this.preloadedKeys.add(keyHex);
      return SymmetricCrypto.encryptAes(plaintext, key);
    }
  }

  /**
   * High-performance AES-256-GCM decryption with preloaded ciphers
   * @param {Buffer} ciphertext - Data to decrypt
   * @param {Buffer} key - AES-256 key
   * @returns {Buffer} Decrypted data
   */
  decryptAES(ciphertext, key) {
    const keyHex = key.toString('hex');
    
    if (this.preloadedKeys.has(keyHex)) {
      this.stats.cacheHits++;
      return SymmetricCrypto.decryptAesCached(ciphertext, key);
    } else {
      this.stats.cacheMisses++;
      // Preload for future use
      SymmetricCrypto.preloadAesCipher(key);
      this.preloadedKeys.add(keyHex);
      return SymmetricCrypto.decryptAes(ciphertext, key);
    }
  }

  /**
   * High-performance ChaCha20-Poly1305 encryption with preloaded ciphers
   * @param {Buffer} plaintext - Data to encrypt
   * @param {Buffer} key - ChaCha20 key
   * @returns {Buffer} Encrypted data
   */
  encryptChaCha20(plaintext, key) {
    const keyHex = key.toString('hex');
    
    if (this.preloadedKeys.has(keyHex)) {
      this.stats.cacheHits++;
      return SymmetricCrypto.encryptChacha20Cached(plaintext, key);
    } else {
      this.stats.cacheMisses++;
      // Preload for future use
      SymmetricCrypto.preloadChacha20Cipher(key);
      this.preloadedKeys.add(keyHex);
      return SymmetricCrypto.encryptChacha20(plaintext, key);
    }
  }

  /**
   * High-performance ChaCha20-Poly1305 decryption with preloaded ciphers
   * @param {Buffer} ciphertext - Data to decrypt
   * @param {Buffer} key - ChaCha20 key
   * @returns {Buffer} Decrypted data
   */
  decryptChaCha20(ciphertext, key) {
    const keyHex = key.toString('hex');
    
    if (this.preloadedKeys.has(keyHex)) {
      this.stats.cacheHits++;
      return SymmetricCrypto.decryptChacha20Cached(ciphertext, key);
    } else {
      this.stats.cacheMisses++;
      // Preload for future use
      SymmetricCrypto.preloadChacha20Cipher(key);
      this.preloadedKeys.add(keyHex);
      return SymmetricCrypto.decryptChacha20(ciphertext, key);
    }
  }

  /**
   * Batch encrypt multiple plaintexts with the same key (optimized)
   * @param {Buffer[]} plaintexts - Array of data to encrypt
   * @param {Buffer} key - Encryption key
   * @param {string} algorithm - 'aes' or 'chacha20'
   * @returns {Buffer[]} Array of encrypted data
   */
  encryptBatch(plaintexts, key, algorithm = 'aes') {
    // Ensure cipher is preloaded
    const keyHex = key.toString('hex');
    if (!this.preloadedKeys.has(keyHex)) {
      if (algorithm === 'aes') {
        SymmetricCrypto.preloadAesCipher(key);
      } else {
        SymmetricCrypto.preloadChacha20Cipher(key);
      }
      this.preloadedKeys.add(keyHex);
    }

    // Batch encrypt using cached ciphers
    return plaintexts.map(plaintext => {
      this.stats.cacheHits++;
      if (algorithm === 'aes') {
        return SymmetricCrypto.encryptAesCached(plaintext, key);
      } else {
        return SymmetricCrypto.encryptChacha20Cached(plaintext, key);
      }
    });
  }

  /**
   * Get performance statistics
   * @returns {Object} Performance stats
   */
  getStats() {
    const cacheStats = SymmetricCrypto.getCacheStats();
    return {
      ...this.stats,
      cacheHitRate: this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses) || 0,
      nativeCacheInfo: cacheStats
    };
  }

  /**
   * Clear all caches and reset stats
   */
  clearCache() {
    SymmetricCrypto.clearCipherCache();
    this.preloadedKeys.clear();
    this.stats = {
      cacheHits: 0,
      cacheMisses: 0,
      preloadedCiphers: 0
    };
  }

  /**
   * Warm up caches with common key sizes and algorithms
   * @param {number} numKeys - Number of keys to generate and preload
   */
  async warmupCache(numKeys = 10) {
    console.log(`🔥 Warming up cache with ${numKeys} cipher instances...`);
    
    const aesKeys = [];
    const chachaKeys = [];
    
    for (let i = 0; i < numKeys; i++) {
      aesKeys.push(SymmetricCrypto.generateAesKey());
      chachaKeys.push(SymmetricCrypto.generateChacha20Key());
    }
    
    await this.preloadCiphers(aesKeys, chachaKeys);
    console.log(`✅ Cache warmed up with ${numKeys * 2} cipher instances`);
  }
}

// Export singleton instance
const preloadedCrypto = new PreloadedCrypto();

module.exports = {
  PreloadedCrypto,
  preloadedCrypto,
  
  // Convenience exports
  encryptAES: (plaintext, key) => preloadedCrypto.encryptAES(plaintext, key),
  decryptAES: (ciphertext, key) => preloadedCrypto.decryptAES(ciphertext, key),
  encryptChaCha20: (plaintext, key) => preloadedCrypto.encryptChaCha20(plaintext, key),
  decryptChaCha20: (ciphertext, key) => preloadedCrypto.decryptChaCha20(ciphertext, key),
  encryptBatch: (plaintexts, key, algorithm) => preloadedCrypto.encryptBatch(plaintexts, key, algorithm),
  preloadCiphers: (aesKeys, chachaKeys) => preloadedCrypto.preloadCiphers(aesKeys, chachaKeys),
  getStats: () => preloadedCrypto.getStats(),
  clearCache: () => preloadedCrypto.clearCache(),
  warmupCache: (numKeys) => preloadedCrypto.warmupCache(numKeys)
};
