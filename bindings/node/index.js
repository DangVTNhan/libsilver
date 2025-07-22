const native = require("./native.js");
class Crypto {
  static generateEncryptionKey(algorithm = "aes-256-gcm") {
    if (algorithm === "aes-256-gcm") {
      return native.SymmetricCrypto.generateAesKey();
    } else if (algorithm === "chacha20-poly1305") {
      return native.SymmetricCrypto.generateChacha20Key();
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static encrypt(plaintext, key, aad = null, algorithm = "aes-256-gcm") {
    if (algorithm === "aes-256-gcm" && !aad) {
      return native.SymmetricCrypto.encryptAes(plaintext, key);
    } else if (algorithm === "aes-256-gcm" && aad) {
      return native.SymmetricCrypto.encryptAesWithAad(plaintext, key, aad);
    } else if (algorithm === "chacha20-poly1305") {
      return native.SymmetricCrypto.encryptChacha20(plaintext, key);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static encryptWithNonce(plaintext, key, nonce, aad = null , algorithm = "aes-256-gcm") {
    if (algorithm === "aes-256-gcm" && !aad) {
      return native.SymmetricCrypto.encryptAesWithNonce(plaintext, key, nonce);
    } else if (algorithm === "aes-256-gcm" && aad) {
      return native.SymmetricCrypto.encryptAesWithAadAndNonce(plaintext, key, nonce, aad);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static getNonceFromCiphertext(ciphertext) {
    return ciphertext.slice(0, 12);
  }

  static decrypt(ciphertext, key, aad = null, algorithm = "aes-256-gcm") {
    if (algorithm === "aes-256-gcm" && !aad) {
      return native.SymmetricCrypto.decryptAes(ciphertext, key);
    } else if (algorithm === "aes-256-gcm" && aad) {
      return native.SymmetricCrypto.decryptAesWithAad(ciphertext, key, aad);
    } else if (algorithm === "chacha20-poly1305") {
      return native.SymmetricCrypto.decryptChacha20(ciphertext, key);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static generateEncapsulationKey(algorithm = "ml-kem-1024") {
    if (algorithm === "ml-kem-512") {
      return native.MlKem512Crypto.generateKeypair();
    } else if (algorithm === "ml-kem-768") {
      return native.MlKem768Crypto.generateKeypair();
    } else if (algorithm === "ml-kem-1024") {
      return native.MlKem1024Crypto.generateKeypair();
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static encapsulate(publicKey, algorithm = "ml-kem-1024") {
    if (algorithm === "ml-kem-512") {
      return native.MlKem512Crypto.encapsulate(publicKey);
    } else if (algorithm === "ml-kem-768") {
      return native.MlKem768Crypto.encapsulate(publicKey);
    } else if (algorithm === "ml-kem-1024") {
      return native.MlKem1024Crypto.encapsulate(publicKey);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static decapsulate(ciphertext, privateKey, algorithm = "ml-kem-1024") {
    if (algorithm === "ml-kem-512") {
      return native.MlKem512Crypto.decapsulate(ciphertext, privateKey);
    } else if (algorithm === "ml-kem-768") {
      return native.MlKem768Crypto.decapsulate(ciphertext, privateKey);
    } else if (algorithm === "ml-kem-1024") {
      return native.MlKem1024Crypto.decapsulate(ciphertext, privateKey);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static generateSignatureKey(algorithm = "ml-dsa-87") {
    if (algorithm === "ml-dsa-44") {
      return native.MlDsa44Crypto.generateKeypair();
    } else if (algorithm === "ml-dsa-65") {
      return native.MlDsa65Crypto.generateKeypair();
    } else if (algorithm === "ml-dsa-87") {
      return native.MlDsa87Crypto.generateKeypair();
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static sign(message, privateKey, algorithm = "ml-dsa-87") {
    if (algorithm === "ml-dsa-44") {
      return native.MlDsa44Crypto.sign(message, privateKey);
    } else if (algorithm === "ml-dsa-65") {
      return native.MlDsa65Crypto.sign(message, privateKey);
    } else if (algorithm === "ml-dsa-87") {
      return native.MlDsa87Crypto.sign(message, privateKey);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static verify(message, signature, publicKey, algorithm = "ml-dsa-87") {
    if (algorithm === "ml-dsa-44") {
      return native.MlDsa44Crypto.verify(message, signature, publicKey);
    } else if (algorithm === "ml-dsa-65") {
      return native.MlDsa65Crypto.verify(message, signature, publicKey);
    } else if (algorithm === "ml-dsa-87") {
      return native.MlDsa87Crypto.verify(message, signature, publicKey);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static hash(data, algorithm = "sha-256") {
    if (algorithm === "sha-256") {
      return native.HashFunctions.sha256(data);
    } else if (algorithm === "sha-512") {
      return native.HashFunctions.sha512(data);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static hashHex(data, algorithm = "sha-256") {
    if (algorithm === "sha-256") {
      return native.HashFunctions.sha256Hex(data);
    } else if (algorithm === "sha-512") {
      return native.HashFunctions.sha512Hex(data);
    } else if (algorithm === "blake3") {
      return native.HashFunctions.blake3Hex(data);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static hmac(key, message, algorithm = "sha-256") {
    if (algorithm === "sha-256") {
      return native.HashFunctions.hmacSha256(key, message);
    } else if (algorithm === "sha-512") {
      return native.HashFunctions.hmacSha512(key, message);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static verifyHmac(key, message, expectedMac, algorithm = "sha-256") {
    if (algorithm === "sha-256") {
      return native.HashFunctions.verifyHmacSha256(key, message, expectedMac);
    } else if (algorithm === "sha-512") {
      return native.HashFunctions.verifyHmacSha512(key, message, expectedMac);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  // Argon2 default parameters:
  // Memory cost: 19456 KiB
  // Iterations: 2
  // Hash length: 32
  // Parallelism: 1
  static derivePassword(
    password,
    salt,
    digestLength = 32,
    algorithm = "argon2"
  ) {
    if (algorithm === "argon2") {
      // Convert password to Buffer if it's a string
      const passwordBuffer =
        typeof password === "string" ? Buffer.from(password, "utf8") : password;
      return native.KeyDerivation.argon2(passwordBuffer, salt, digestLength);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }
}

/**
 * StreamEncryption - Stateful AES-256-GCM stream cipher with automatic nonce management
 *
 * This class provides a high-level wrapper around the StreamCipherJs native implementation,
 * offering stateful encryption/decryption with automatic nonce management and thread safety.
 *
 * Features:
 * - Automatic nonce increment for each operation
 * - Thread-safe operations using Arc<Mutex<>> internally
 * - AWS-LC-RS backend for high performance
 * - Zero-copy operations with BufferRef support
 * - Stateful design for streaming data processing
 */
class StreamEncryption {
  /**
   * Create a new StreamEncryption instance
   * @param {Buffer} key - AES-256 key (must be exactly 32 bytes)
   */
  constructor(key) {
    this.cipher = new native.StreamCipherJs(key);
  }

  /**
   * Generate a new AES-256 key for stream cipher use
   * @returns {Buffer} 32-byte AES-256 key
   */
  static generateKey() {
    return native.StreamCipherJs.generateKey();
  }

  /**
   * Encrypt a chunk of data using the stream cipher
   *
   * This method automatically generates a unique nonce for each operation
   * by incrementing an internal counter. The returned ciphertext includes
   * the nonce prefix for decryption.
   *
   * @param {Buffer} plaintext - Data to encrypt
   * @returns {Buffer} Encrypted data with nonce prefix (nonce + ciphertext + tag)
   */
  encryptChunk(plaintext) {
    return this.cipher.encryptChunk(plaintext);
  }

  /**
   * Decrypt a chunk of data using the stream cipher
   *
   * The ciphertext must include the nonce prefix as returned by encryptChunk.
   *
   * @param {Buffer} ciphertext - Encrypted data with nonce prefix (nonce + ciphertext + tag)
   * @returns {Buffer} Decrypted plaintext data
   */
  decryptChunk(ciphertext) {
    return this.cipher.decryptChunk(ciphertext);
  }

  /**
   * Reset the stream cipher state
   *
   * This generates a new base nonce and resets the nonce counter to 0.
   * Use this method when the nonce counter approaches overflow or when
   * starting a new encryption session.
   */
  reset() {
    return this.cipher.reset();
  }

  /**
   * Get the current nonce counter value
   *
   * This can be used to monitor nonce usage and determine when to reset.
   * Consider resetting when the counter approaches the maximum value.
   *
   * @returns {number} Current nonce counter value
   */
  getNonceCounter() {
    return this.cipher.getNonceCounter();
  }

  /**
   * Encrypt a chunk of data with additional authenticated data (AAD)
   *
   * This method performs authenticated encryption where the AAD is authenticated
   * but not encrypted. The returned ciphertext includes the nonce prefix for
   * decryption, similar to the standard encryptChunk method.
   *
   * @param {Buffer} plaintext - Data to encrypt
   * @param {Buffer} aad - Additional authenticated data (not encrypted, but authenticated)
   * @returns {Buffer} Encrypted data with nonce prefix (nonce + ciphertext + tag)
   */
  encryptChunkWithAad(plaintext, aad) {
    return this.cipher.encryptChunkWithAad(plaintext, aad);
  }

  /**
   * Decrypt a chunk of data with additional authenticated data (AAD)
   *
   * This method performs authenticated decryption where the AAD is verified
   * along with the ciphertext. The ciphertext must include the nonce prefix
   * and authentication tag as returned by encryptChunkWithAad.
   *
   * @param {Buffer} ciphertext - Encrypted data with nonce prefix (nonce + ciphertext + tag)
   * @param {Buffer} aad - Additional authenticated data (same as used during encryption)
   * @returns {Buffer} Decrypted plaintext data
   */
  decryptChunkWithAad(ciphertext, aad) {
    return this.cipher.decryptChunkWithAad(ciphertext, aad);
  }
}

// Export for CommonJS
module.exports = { ...native, Crypto, StreamEncryption };

// Export for ES modules compatibility
module.exports.default = { ...native, Crypto, StreamEncryption };
module.exports.Crypto = Crypto;
module.exports.StreamEncryption = StreamEncryption;
