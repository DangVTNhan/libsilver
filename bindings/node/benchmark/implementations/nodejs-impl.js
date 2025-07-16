#!/usr/bin/env node

/**
 * Node.js Native Crypto Implementation Wrappers
 */

import crypto from 'crypto';

export class NodeJSSymmetricCrypto {
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

  static generateAESKey() {
    return crypto.randomBytes(32);
  }

  static generateChaCha20Key() {
    return crypto.randomBytes(32);
  }
}

export class NodeJSAsymmetricCrypto {
  static generateRSAKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKeyPem: publicKey, privateKeyPem: privateKey };
  }

  static encryptRSA(plaintext, publicKeyPem) {
    return crypto.publicEncrypt({
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, plaintext);
  }

  static decryptRSA(ciphertext, privateKeyPem) {
    return crypto.privateDecrypt({
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, ciphertext);
  }

  static generateEd25519Keypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    
    // Extract raw key bytes (Node.js returns DER format)
    const signingKeyBytes = privateKey.slice(-32);
    const verifyingKeyBytes = publicKey.slice(-32);
    
    return { signingKeyBytes, verifyingKeyBytes };
  }

  static signEd25519(message, signingKeyBytes) {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
        signingKeyBytes
      ]),
      format: 'der',
      type: 'pkcs8'
    });
    
    return crypto.sign(null, message, privateKey);
  }

  static verifyEd25519(message, signature, verifyingKeyBytes) {
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
        verifyingKeyBytes
      ]),
      format: 'der',
      type: 'spki'
    });
    
    return crypto.verify(null, message, publicKey, signature);
  }

  static generateECDSAKeypair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    
    // Extract raw key bytes
    const signingKeyBytes = privateKey.slice(-32);
    const verifyingKeyBytes = publicKey.slice(-65);
    
    return { signingKeyBytes, verifyingKeyBytes };
  }

  static signECDSA(message, signingKeyBytes) {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from([0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]),
        signingKeyBytes,
        Buffer.from([0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00])
      ]),
      format: 'der',
      type: 'pkcs8'
    });
    
    return crypto.sign('sha256', message, privateKey);
  }

  static verifyECDSA(message, signature, verifyingKeyBytes) {
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]),
        verifyingKeyBytes
      ]),
      format: 'der',
      type: 'spki'
    });
    
    return crypto.verify('sha256', message, publicKey, signature);
  }
}

export class NodeJSHashFunctions {
  static sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
  }

  static sha512(data) {
    return crypto.createHash('sha512').update(data).digest();
  }
}

export class NodeJSKeyDerivation {
  static pbkdf2SHA256(password, salt, iterations, keyLength) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
  }

  static hkdfSHA256(inputKey, salt, info, keyLength) {
    return crypto.hkdfSync('sha256', inputKey, salt, info, keyLength);
  }
}
