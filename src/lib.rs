//! # LibSilver - Cross-Platform Cryptography Library
//!
//! LibSilver is a comprehensive cryptography library built with RustCrypto that provides
//! secure cryptographic primitives for multiple platforms including Node.js, Swift, and Kotlin/Java.
//!
//! ## Features
//!
//! - **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
//! - **Asymmetric Encryption**: RSA-OAEP
//! - **Digital Signatures**: ECDSA P-256, Ed25519
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
//! // Symmetric encryption
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

    /// High-level symmetric encryption using AES-256-GCM
    #[inline]
    pub fn encrypt_aes(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::encrypt(plaintext, key)
    }

    /// High-level symmetric decryption using AES-256-GCM
    #[inline]
    pub fn decrypt_aes(ciphertext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::decrypt(ciphertext, key)
    }

    /// High-level symmetric encryption using AES-256-GCM with additional authenticated data
    #[inline]
    pub fn encrypt_aes_with_aad(plaintext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        AesGcm::encrypt_with_aad(plaintext, key, aad)
    }

    /// High-level symmetric decryption using AES-256-GCM with additional authenticated data
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
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_aes_encryption_integration() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Integration test message";

        let ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
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
}
