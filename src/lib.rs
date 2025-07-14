//! # LibSilver - Cross-Platform Cryptography Library
//!
//! LibSilver is a comprehensive cryptography library that provides
//! secure cryptographic primitives for multiple platforms including Node.js, Swift, and Kotlin/Java.
//! It uses AWS-LC-RS as the default implementation for FIPS 140-2 validated cryptography.
//!
//! ## Features
//!
//! - **Symmetric Encryption**: AES-256-GCM (AWS-LC-RS default, RustCrypto available), ChaCha20-Poly1305
//! - **Asymmetric Encryption**: RSA-OAEP
//! - **Digital Signatures**: ECDSA P-256, Ed25519
//! - **Post-Quantum Cryptography**: ML-KEM (Key Encapsulation), ML-DSA (Digital Signatures)
//! - **Hashing**: SHA-256, SHA-512, BLAKE3, HMAC
//! - **Key Derivation**: Argon2, HKDF, PBKDF2
//! - **Secure Random Generation**: OS-backed random number generation
//! - **Memory Safety**: Automatic zeroization of sensitive data
//!
//! ## Quick Start
//!
//! ```rust
//! use libsilver::prelude::*;
//!
//! // Symmetric encryption (now uses AWS-LC-RS by default)
//! let key = AesGcm::generate_key()?;
//! let plaintext = b"Hello, World!";
//! let ciphertext = AesGcm::encrypt(plaintext, &key)?;
//! let decrypted = AesGcm::decrypt(&ciphertext, &key)?;
//! assert_eq!(plaintext, &decrypted[..]);
//!
//! // Digital signatures
//! let keypair = Ed25519Crypto::generate_keypair()?;
//! let message = b"Sign this message";
//! let signature = Ed25519Crypto::sign(message, keypair.signing_key())?;
//! let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key())?;
//! assert!(is_valid);
//!
//! // Hashing
//! let data = b"Hash this data";
//! let hash = Sha256Hash::hash(data)?;
//! let hex_hash = Sha256Hash::hash_hex(data)?;
//!
//! // Post-quantum cryptography
//! // ML-KEM-768 (Key Encapsulation Mechanism) - Recommended
//! let kem_keypair = MlKem768::generate_keypair()?;
//! let encapsulation = MlKem768::encapsulate(kem_keypair.public_key_bytes())?;
//! let shared_secret = MlKem768::decapsulate(
//!     &encapsulation.ciphertext,
//!     kem_keypair.private_key_bytes(),
//! )?;
//!
//! // ML-DSA-65 (Digital Signature Algorithm) - Recommended
//! let dsa_keypair = MlDsa65::generate_keypair()?;
//! let message = b"Post-quantum signature";
//! let signature = MlDsa65::sign(message, dsa_keypair.private_key_bytes())?;
//! let is_valid = MlDsa65::verify(message, &signature, dsa_keypair.public_key_bytes())?;
//! assert!(is_valid);
//!
//! # Ok::<(), libsilver::error::CryptoError>(())
//! ```

pub mod core;
pub mod error;

// Re-export for convenience
pub use error::{CryptoError, CryptoResult};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::core::*;
    pub use crate::error::{CryptoError, CryptoResult};
}

// High-level convenience functions
pub mod crypto {
    use crate::prelude::*;

    /// High-level symmetric encryption using AES-256-GCM (AWS-LC-RS - Default)
    #[inline]
    pub fn encrypt_aes(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::encrypt(plaintext, key)
    }

    /// High-level symmetric decryption using AES-256-GCM (AWS-LC-RS - Default)
    #[inline]
    pub fn decrypt_aes(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::decrypt(ciphertext, key)
    }

    /// High-level symmetric encryption using AWS-LC-RS AES-256-GCM
    #[inline]
    pub fn encrypt_aes_aws_lc(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AwsLcAesGcm::encrypt(plaintext, key)
    }

    /// High-level symmetric decryption using AWS-LC-RS AES-256-GCM
    #[inline]
    pub fn decrypt_aes_aws_lc(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AwsLcAesGcm::decrypt(ciphertext, key)
    }

    /// High-level symmetric encryption using RustCrypto AES-256-GCM
    #[inline]
    pub fn encrypt_aes_rustcrypto(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        RustCryptoAesGcm::encrypt(plaintext, key)
    }

    /// High-level symmetric decryption using RustCrypto AES-256-GCM
    #[inline]
    pub fn decrypt_aes_rustcrypto(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        RustCryptoAesGcm::decrypt(ciphertext, key)
    }

    /// High-level symmetric encryption using AES-256-GCM with additional authenticated data (AWS-LC-RS - Default)
    #[inline]
    pub fn encrypt_aes_with_aad(plaintext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::encrypt_with_aad(plaintext, key, aad)
    }

    /// High-level symmetric decryption using AES-256-GCM with additional authenticated data (AWS-LC-RS - Default)
    #[inline]
    pub fn decrypt_aes_with_aad(ciphertext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::decrypt_with_aad(ciphertext, key, aad)
    }

    /// High-level symmetric encryption using ChaCha20-Poly1305
    #[inline]
    pub fn encrypt_chacha20(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        ChaCha20Poly1305Cipher::encrypt(plaintext, key)
    }

    /// High-level symmetric decryption using ChaCha20-Poly1305
    #[inline]
    pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        ChaCha20Poly1305Cipher::decrypt(ciphertext, key)
    }

    /// Generate a secure random key of specified length
    #[inline]
    pub fn generate_key(length: usize) -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(length)
    }

    /// Hash data using SHA-256
    #[inline]
    pub fn hash_sha256(data: &[u8]) -> CryptoResult<Vec<u8>> {
        Sha256Hash::hash(data)
    }

    /// Hash data using BLAKE3
    #[inline]
    pub fn hash_blake3(data: &[u8]) -> CryptoResult<Vec<u8>> {
        Blake3Hash::hash(data)
    }

    /// Derive key from password using Argon2
    #[inline]
    pub fn derive_key_argon2(password: &[u8], salt: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        Argon2Kdf::derive_key(password, salt, length)
    }

    // ML-KEM convenience functions

    /// Generate ML-KEM-512 key pair (post-quantum key encapsulation)
    #[inline]
    pub fn generate_ml_kem_512_keypair() -> CryptoResult<MlKem512KeyPair> {
        MlKem512::generate_keypair()
    }

    /// Encapsulate shared secret using ML-KEM-512
    #[inline]
    pub fn ml_kem_512_encapsulate(public_key: &[u8]) -> CryptoResult<MlKem512Encapsulation> {
        MlKem512::encapsulate(public_key)
    }

    /// Decapsulate shared secret using ML-KEM-512
    #[inline]
    pub fn ml_kem_512_decapsulate(ciphertext: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlKem512::decapsulate(ciphertext, private_key)
    }

    /// Generate ML-KEM-768 key pair (post-quantum key encapsulation) - Recommended
    #[inline]
    pub fn generate_ml_kem_768_keypair() -> CryptoResult<MlKem768KeyPair> {
        MlKem768::generate_keypair()
    }

    /// Encapsulate shared secret using ML-KEM-768
    #[inline]
    pub fn ml_kem_768_encapsulate(public_key: &[u8]) -> CryptoResult<MlKem768Encapsulation> {
        MlKem768::encapsulate(public_key)
    }

    /// Decapsulate shared secret using ML-KEM-768
    #[inline]
    pub fn ml_kem_768_decapsulate(ciphertext: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlKem768::decapsulate(ciphertext, private_key)
    }

    /// Generate ML-KEM-1024 key pair (post-quantum key encapsulation)
    #[inline]
    pub fn generate_ml_kem_1024_keypair() -> CryptoResult<MlKem1024KeyPair> {
        MlKem1024::generate_keypair()
    }

    /// Encapsulate shared secret using ML-KEM-1024
    #[inline]
    pub fn ml_kem_1024_encapsulate(public_key: &[u8]) -> CryptoResult<MlKem1024Encapsulation> {
        MlKem1024::encapsulate(public_key)
    }

    /// Decapsulate shared secret using ML-KEM-1024
    #[inline]
    pub fn ml_kem_1024_decapsulate(ciphertext: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlKem1024::decapsulate(ciphertext, private_key)
    }

    // ML-DSA convenience functions

    /// Generate ML-DSA-44 key pair (post-quantum digital signatures)
    #[inline]
    pub fn generate_ml_dsa_44_keypair() -> CryptoResult<MlDsa44KeyPair> {
        MlDsa44::generate_keypair()
    }

    /// Sign data using ML-DSA-44
    #[inline]
    pub fn ml_dsa_44_sign(message: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlDsa44::sign(message, private_key)
    }

    /// Verify ML-DSA-44 signature
    #[inline]
    pub fn ml_dsa_44_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<bool> {
        MlDsa44::verify(message, signature, public_key)
    }

    /// Generate ML-DSA-65 key pair (post-quantum digital signatures) - Recommended
    #[inline]
    pub fn generate_ml_dsa_65_keypair() -> CryptoResult<MlDsa65KeyPair> {
        MlDsa65::generate_keypair()
    }

    /// Sign data using ML-DSA-65
    #[inline]
    pub fn ml_dsa_65_sign(message: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlDsa65::sign(message, private_key)
    }

    /// Verify ML-DSA-65 signature
    #[inline]
    pub fn ml_dsa_65_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<bool> {
        MlDsa65::verify(message, signature, public_key)
    }

    /// Generate ML-DSA-87 key pair (post-quantum digital signatures)
    #[inline]
    pub fn generate_ml_dsa_87_keypair() -> CryptoResult<MlDsa87KeyPair> {
        MlDsa87::generate_keypair()
    }

    /// Sign data using ML-DSA-87
    #[inline]
    pub fn ml_dsa_87_sign(message: &[u8], private_key: &[u8]) -> CryptoResult<Vec<u8>> {
        MlDsa87::sign(message, private_key)
    }

    /// Verify ML-DSA-87 signature
    #[inline]
    pub fn ml_dsa_87_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<bool> {
        MlDsa87::verify(message, signature, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_aes_encryption_integration() {
        // Test that AesGcm (now AWS-LC-RS by default) works
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Integration test message";

        let ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_aws_lc_aes_integration() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"AWS-LC-RS integration test message";

        let ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AwsLcAesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rustcrypto_aes_integration() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"RustCrypto integration test message";

        let ciphertext = RustCryptoAesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = RustCryptoAesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_high_level_aws_lc_functions() {
        use crate::crypto::{encrypt_aes_aws_lc, decrypt_aes_aws_lc};

        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"High-level AWS-LC-RS function test";

        let ciphertext = encrypt_aes_aws_lc(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_aws_lc(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ed25519_signature_integration() {
        let keypair = Ed25519Crypto::generate_keypair().unwrap();
        let message = b"Integration test signature";

        let signature = Ed25519Crypto::sign(message, keypair.signing_key()).unwrap();
        let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key()).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_hash_integration() {
        let data = b"Integration test hash";

        let sha256_hash = Sha256Hash::hash(data).unwrap();
        let blake3_hash = Blake3Hash::hash(data).unwrap();

        assert_eq!(sha256_hash.len(), 32);
        assert_eq!(blake3_hash.len(), 32);

        // Verify hashes
        assert!(Sha256Hash::verify(data, &sha256_hash).unwrap());
        assert!(Blake3Hash::verify(data, &blake3_hash).unwrap());
    }

    #[test]
    fn test_key_derivation_integration() {
        let password = b"test_password";
        let salt = SecureRandom::generate_salt().unwrap();

        let key = Argon2Kdf::derive_key(password, &salt, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Same inputs should produce same key
        let key2 = Argon2Kdf::derive_key(password, &salt, 32).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_convenience_functions() {
        use crate::crypto;

        let key = crypto::generate_key(32).unwrap();
        let plaintext = b"Convenience function test";

        let ciphertext = crypto::encrypt_aes(plaintext, &key).unwrap();
        let decrypted = crypto::decrypt_aes(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);

        let hash = crypto::hash_sha256(plaintext).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_ml_kem_768_integration() {
        let keypair = MlKem768::generate_keypair().unwrap();

        let encapsulation = MlKem768::encapsulate(keypair.public_key_bytes()).unwrap();

        let shared_secret = MlKem768::decapsulate(
            &encapsulation.ciphertext,
            keypair.private_key_bytes(),
        ).unwrap();

        assert_eq!(encapsulation.shared_secret, shared_secret);
    }

    #[test]
    fn test_ml_dsa_65_integration() {
        let keypair = MlDsa65::generate_keypair().unwrap();
        let message = b"Integration test for ML-DSA-65";

        let signature = MlDsa65::sign(message, keypair.private_key_bytes()).unwrap();

        let is_valid = MlDsa65::verify(message, &signature, keypair.public_key_bytes()).unwrap();

        assert!(is_valid);

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_valid = MlDsa65::verify(wrong_message, &signature, keypair.public_key_bytes()).unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_post_quantum_convenience_functions() {
        use crate::crypto;

        // Test ML-KEM-768 convenience functions
        let kem_keypair = crypto::generate_ml_kem_768_keypair().unwrap();
        let encapsulation = crypto::ml_kem_768_encapsulate(kem_keypair.public_key_bytes()).unwrap();
        let shared_secret = crypto::ml_kem_768_decapsulate(
            &encapsulation.ciphertext,
            kem_keypair.private_key_bytes(),
        ).unwrap();
        assert_eq!(encapsulation.shared_secret, shared_secret);

        // Test ML-DSA-65 convenience functions
        let dsa_keypair = crypto::generate_ml_dsa_65_keypair().unwrap();
        let message = b"Convenience function test for ML-DSA-65";
        let signature = crypto::ml_dsa_65_sign(message, dsa_keypair.private_key_bytes()).unwrap();
        let is_valid = crypto::ml_dsa_65_verify(message, &signature, dsa_keypair.public_key_bytes()).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_rustcrypto_convenience_functions() {
        use crate::crypto;

        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"RustCrypto convenience function test";

        let ciphertext = crypto::encrypt_aes_rustcrypto(plaintext, &key).unwrap();
        let decrypted = crypto::decrypt_aes_rustcrypto(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }
}
