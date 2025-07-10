use crate::error::{CryptoError, CryptoResult};
use crate::core::random::SecureRandom;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};


/// AES-256-GCM symmetric encryption
pub struct AesGcm;

impl AesGcm {
    /// Generate a new AES-256 key (32 bytes)
    pub fn generate_key() -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(32)
    }

    /// Encrypt data using AES-256-GCM
    /// Returns: nonce (12 bytes) + ciphertext + tag
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 key must be 32 bytes".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Generate random nonce
        let nonce_bytes = SecureRandom::generate_nonce(12)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {:?}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using AES-256-GCM
    /// Input format: nonce (12 bytes) + ciphertext + tag
    pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 key must be 32 bytes".to_string()));
        }

        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::InvalidInput("Ciphertext too short".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("AES-GCM decryption failed: {:?}", e)))?;

        Ok(plaintext)
    }

    /// Encrypt with provided nonce (for testing purposes)
    pub fn encrypt_with_nonce(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey("AES-256 key must be 32 bytes".to_string()));
        }

        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput("Nonce must be 12 bytes".to_string()));
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES-GCM encryption failed: {:?}", e)))?;

        Ok(ciphertext)
    }
}

/// ChaCha20-Poly1305 symmetric encryption
pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
    /// Generate a new ChaCha20 key (32 bytes)
    pub fn generate_key() -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(32)
    }

    /// Encrypt data using ChaCha20-Poly1305
    /// Returns: nonce (12 bytes) + ciphertext + tag
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey("ChaCha20 key must be 32 bytes".to_string()));
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let nonce_bytes = SecureRandom::generate_nonce(12)?;
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {:?}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    /// Input format: nonce (12 bytes) + ciphertext + tag
    pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey("ChaCha20 key must be 32 bytes".to_string()));
        }

        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::InvalidInput("Ciphertext too short".to_string()));
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = ChaChaNonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("ChaCha20-Poly1305 decryption failed: {:?}", e)))?;

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


}