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

// Export for CommonJS
module.exports = { ...native, Crypto };

// Export for ES modules compatibility
module.exports.default = { ...native, Crypto };
module.exports.Crypto = Crypto;
