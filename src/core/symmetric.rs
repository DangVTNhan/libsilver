use crate::error::{CryptoError, CryptoResult, INVALID_KEY_LENGTH_AES, INVALID_KEY_LENGTH_CHACHA, INVALID_NONCE_LENGTH, CIPHERTEXT_TOO_SHORT, AES_GCM_ENCRYPTION_FAILED, AES_GCM_DECRYPTION_FAILED, CHACHA20_ENCRYPTION_FAILED, CHACHA20_DECRYPTION_FAILED};
use crate::core::random::SecureRandom;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};


// Constants for AES-GCM
const AES_KEY_SIZE: usize = 32;  // 256 bits
const AES_NONCE_SIZE: usize = 12; // 96 bits
const AES_TAG_SIZE: usize = 16;   // 128 bits
const MIN_CIPHERTEXT_SIZE: usize = AES_NONCE_SIZE + AES_TAG_SIZE; // 28 bytes minimum

/// AES-256-GCM symmetric encryption
pub struct AesGcm;

impl AesGcm {
    /// Generate a new AES-256 key (32 bytes)
    #[inline]
    pub fn generate_key() -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(AES_KEY_SIZE)
    }

    /// Encrypt data using AES-256-GCM
    /// Returns: nonce (12 bytes) + ciphertext + tag
    #[inline]
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let nonce_bytes = SecureRandom::generate_nonce(AES_NONCE_SIZE)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED))?;

        // Prepend nonce to ciphertext - pre-allocate exact capacity
        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM
    /// Input format: nonce (12 bytes) + ciphertext + tag
    #[inline]
    pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_ciphertext_length(ciphertext_with_nonce)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext)
    }

    /// Encrypt with provided nonce (for testing purposes)
    #[inline]
    pub fn encrypt_with_nonce(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_nonce(nonce)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED))?;

        Ok(ciphertext)
    }

    /// Encrypt with associated data (AAD) for additional authentication
    #[inline]
    pub fn encrypt_with_aad(plaintext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let nonce_bytes = SecureRandom::generate_nonce(AES_NONCE_SIZE)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with AAD
        let ciphertext = cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt with associated data (AAD) for additional authentication
    #[inline]
    pub fn decrypt_with_aad(ciphertext_with_nonce: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_ciphertext_length(ciphertext_with_nonce)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt with AAD
        let plaintext = cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::DecryptionFailed(AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext)
    }

    // Private helper methods for validation
    #[inline]
    fn validate_key(key: &[u8]) -> CryptoResult<()> {
        if key.len() != AES_KEY_SIZE {
            return Err(CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES));
        }
        Ok(())
    }

    #[inline]
    fn validate_nonce(nonce: &[u8]) -> CryptoResult<()> {
        if nonce.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidInput(INVALID_NONCE_LENGTH));
        }
        Ok(())
    }

    #[inline]
    fn validate_ciphertext_length(ciphertext: &[u8]) -> CryptoResult<()> {
        if ciphertext.len() < MIN_CIPHERTEXT_SIZE {
            return Err(CryptoError::InvalidInput(CIPHERTEXT_TOO_SHORT));
        }
        Ok(())
    }
}

/// ChaCha20-Poly1305 symmetric encryption
pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
    /// Generate a new ChaCha20 key (32 bytes)
    #[inline]
    pub fn generate_key() -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(32)
    }

    /// Encrypt data using ChaCha20-Poly1305
    /// Returns: nonce (12 bytes) + ciphertext + tag
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey(INVALID_KEY_LENGTH_CHACHA));
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let nonce_bytes = SecureRandom::generate_nonce(12)?;
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed(CHACHA20_ENCRYPTION_FAILED))?;

        // Prepend nonce to ciphertext - pre-allocate exact capacity
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    /// Input format: nonce (12 bytes) + ciphertext + tag
    pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey(INVALID_KEY_LENGTH_CHACHA));
        }

        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::InvalidInput(CIPHERTEXT_TOO_SHORT));
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = ChaChaNonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(CHACHA20_DECRYPTION_FAILED))?;

        Ok(plaintext)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Hello, World! This is a test message.";

        let ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len()); // Should include nonce and tag

        let decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        let plaintext = b"test";

        let result = AesGcm::encrypt(plaintext, &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"";

        let ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = ChaCha20Poly1305Cipher::generate_key().unwrap();
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let ciphertext = ChaCha20Poly1305Cipher::encrypt(plaintext, &key).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = ChaCha20Poly1305Cipher::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        let plaintext = b"test";

        let result = ChaCha20Poly1305Cipher::encrypt(plaintext, &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Hello, World!";

        let mut ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(20) {
            *byte = byte.wrapping_add(1);
        }

        let result = AesGcm::decrypt(&ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_with_aad() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"additional authenticated data";

        let ciphertext = AesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let decrypted = AesGcm::decrypt_with_aad(&ciphertext, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_with_aad_wrong_aad() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"additional authenticated data";
        let wrong_aad = b"wrong additional data";

        let ciphertext = AesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let result = AesGcm::decrypt_with_aad(&ciphertext, &key, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_constants() {
        // Test that our constants are correct
        assert_eq!(AES_KEY_SIZE, 32);
        assert_eq!(AES_NONCE_SIZE, 12);
        assert_eq!(AES_TAG_SIZE, 16);
        assert_eq!(MIN_CIPHERTEXT_SIZE, 28);
    }

    #[test]
    fn test_aes_gcm_ciphertext_too_short() {
        let key = AesGcm::generate_key().unwrap();
        let short_ciphertext = vec![0u8; 20]; // Less than MIN_CIPHERTEXT_SIZE

        let result = AesGcm::decrypt(&short_ciphertext, &key);
        assert!(result.is_err());
    }
}