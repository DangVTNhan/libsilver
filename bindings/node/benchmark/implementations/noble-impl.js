#!/usr/bin/env node

/**
 * @noble/ciphers Implementation Wrappers
 */

import crypto from 'crypto';
import { gcm } from '@noble/ciphers/aes';
import { chacha20poly1305 } from '@noble/ciphers/chacha';

export class NobleSymmetricCrypto {
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

  static generateAESKey() {
    return crypto.randomBytes(32);
  }

  static generateChaCha20Key() {
    return crypto.randomBytes(32);
  }
}
