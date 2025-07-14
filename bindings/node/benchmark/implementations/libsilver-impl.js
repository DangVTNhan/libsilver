#!/usr/bin/env node

/**
 * LibSilver Implementation Wrappers
 */

import {
  SymmetricCrypto, AwsLcAesCrypto, RustCryptoAesCrypto, AsymmetricCrypto, 
  HashFunctions, KeyDerivation, RandomGenerator,
  MlKem512Crypto, MlKem768Crypto, MlKem1024Crypto,
  MlDsa44Crypto, MlDsa65Crypto, MlDsa87Crypto
} from 'libsilver-nodejs';

export class LibSilverSymmetricCrypto {
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

  static generateAESKey() {
    return SymmetricCrypto.generateAesKey();
  }

  static generateChaCha20Key() {
    return SymmetricCrypto.generateChacha20Key();
  }
}

export class LibSilverAWSSymmetricCrypto {
  static encryptAES(plaintext, key) {
    return AwsLcAesCrypto.encrypt(plaintext, key);
  }

  static decryptAES(ciphertext, key) {
    return AwsLcAesCrypto.decrypt(ciphertext, key);
  }

  static generateAESKey() {
    return AwsLcAesCrypto.generateKey();
  }
}

export class LibSilverRustSymmetricCrypto {
  static encryptAES(plaintext, key) {
    return RustCryptoAesCrypto.encrypt(plaintext, key);
  }

  static decryptAES(ciphertext, key) {
    return RustCryptoAesCrypto.decrypt(ciphertext, key);
  }

  static generateAESKey() {
    return RustCryptoAesCrypto.generateKey();
  }
}

export class LibSilverAsymmetricCrypto {
  static generateRSAKeypair() {
    return AsymmetricCrypto.generateRsaKeypair();
  }

  static encryptRSA(plaintext, publicKeyPem) {
    return AsymmetricCrypto.encryptRsa(plaintext, publicKeyPem);
  }

  static decryptRSA(ciphertext, privateKeyPem) {
    return AsymmetricCrypto.decryptRsa(ciphertext, privateKeyPem);
  }

  static generateEd25519Keypair() {
    return AsymmetricCrypto.generateEd25519Keypair();
  }

  static signEd25519(message, signingKeyBytes) {
    return AsymmetricCrypto.signEd25519(message, signingKeyBytes);
  }

  static verifyEd25519(message, signature, verifyingKeyBytes) {
    return AsymmetricCrypto.verifyEd25519(message, signature, verifyingKeyBytes);
  }

  static generateECDSAKeypair() {
    return AsymmetricCrypto.generateEcdsaKeypair();
  }

  static signECDSA(message, signingKeyBytes) {
    return AsymmetricCrypto.signEcdsa(message, signingKeyBytes);
  }

  static verifyECDSA(message, signature, verifyingKeyBytes) {
    return AsymmetricCrypto.verifyEcdsa(message, signature, verifyingKeyBytes);
  }
}

export class LibSilverHashFunctions {
  static sha256(data) {
    return HashFunctions.sha256(data);
  }

  static sha512(data) {
    return HashFunctions.sha512(data);
  }

  static blake3(data) {
    return HashFunctions.blake3(data);
  }
}

export class LibSilverKeyDerivation {
  static pbkdf2SHA256(password, salt, iterations, keyLength) {
    return KeyDerivation.pbkdf2Sha256(password, salt, iterations, keyLength);
  }

  static argon2(password, salt, keyLength) {
    return KeyDerivation.argon2(password, salt, keyLength);
  }

  static hkdfSHA256(inputKey, salt, info, keyLength) {
    return KeyDerivation.hkdfSha256(inputKey, salt, info, keyLength);
  }
}

export class LibSilverPostQuantum {
  // ML-KEM implementations
  static mlKem512GenerateKeypair() {
    return MlKem512Crypto.generateKeypair();
  }

  static mlKem512Encapsulate(publicKeyBytes) {
    return MlKem512Crypto.encapsulate(publicKeyBytes);
  }

  static mlKem512Decapsulate(ciphertext, privateKeyBytes) {
    return MlKem512Crypto.decapsulate(ciphertext, privateKeyBytes);
  }

  static mlKem768GenerateKeypair() {
    return MlKem768Crypto.generateKeypair();
  }

  static mlKem768Encapsulate(publicKeyBytes) {
    return MlKem768Crypto.encapsulate(publicKeyBytes);
  }

  static mlKem768Decapsulate(ciphertext, privateKeyBytes) {
    return MlKem768Crypto.decapsulate(ciphertext, privateKeyBytes);
  }

  static mlKem1024GenerateKeypair() {
    return MlKem1024Crypto.generateKeypair();
  }

  static mlKem1024Encapsulate(publicKeyBytes) {
    return MlKem1024Crypto.encapsulate(publicKeyBytes);
  }

  static mlKem1024Decapsulate(ciphertext, privateKeyBytes) {
    return MlKem1024Crypto.decapsulate(ciphertext, privateKeyBytes);
  }

  // ML-DSA implementations
  static mlDsa44GenerateKeypair() {
    return MlDsa44Crypto.generateKeypair();
  }

  static mlDsa44Sign(message, privateKeyBytes) {
    return MlDsa44Crypto.sign(message, privateKeyBytes);
  }

  static mlDsa44Verify(message, signature, publicKeyBytes) {
    return MlDsa44Crypto.verify(message, signature, publicKeyBytes);
  }

  static mlDsa65GenerateKeypair() {
    return MlDsa65Crypto.generateKeypair();
  }

  static mlDsa65Sign(message, privateKeyBytes) {
    return MlDsa65Crypto.sign(message, privateKeyBytes);
  }

  static mlDsa65Verify(message, signature, publicKeyBytes) {
    return MlDsa65Crypto.verify(message, signature, publicKeyBytes);
  }

  static mlDsa87GenerateKeypair() {
    return MlDsa87Crypto.generateKeypair();
  }

  static mlDsa87Sign(message, privateKeyBytes) {
    return MlDsa87Crypto.sign(message, privateKeyBytes);
  }

  static mlDsa87Verify(message, signature, publicKeyBytes) {
    return MlDsa87Crypto.verify(message, signature, publicKeyBytes);
  }
}
