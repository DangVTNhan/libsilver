use crate::core::random::SecureRandom;
use crate::error::{
    CryptoError, CryptoResult, AES_GCM_DECRYPTION_FAILED, AES_GCM_ENCRYPTION_FAILED,
    AWS_LC_AES_GCM_DECRYPTION_FAILED, AWS_LC_AES_GCM_ENCRYPTION_FAILED, CHACHA20_DECRYPTION_FAILED,
    CHACHA20_ENCRYPTION_FAILED, CIPHERTEXT_TOO_SHORT, INVALID_KEY_LENGTH_AES,
    INVALID_KEY_LENGTH_CHACHA, INVALID_NONCE_LENGTH,
};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce as AwsNonce, RandomizedNonceKey, UnboundKey, AES_256_GCM,
};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};

// Constants for AES-GCM
const AES_KEY_SIZE: usize = 32; // 256 bits
const AES_NONCE_SIZE: usize = 12; // 96 bits
const AES_TAG_SIZE: usize = 16; // 128 bits
const MIN_CIPHERTEXT_SIZE: usize = AES_NONCE_SIZE + AES_TAG_SIZE; // 28 bytes minimum

/// AES-256-GCM symmetric encryption using RustCrypto
pub struct RustCryptoAesGcm;

impl RustCryptoAesGcm {
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
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
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
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
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

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
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
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt with associated data (AAD) for additional authentication
    #[inline]
    pub fn decrypt_with_aad(
        ciphertext_with_nonce: &[u8],
        key: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_ciphertext_length(ciphertext_with_nonce)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt with AAD
        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed(AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext)
    }

    /// Encrypt with associated data (AAD) and provided nonce for additional authentication
    /// This function combines the functionality of encrypt_with_aad and encrypt_with_nonce
    #[inline]
    pub fn encrypt_with_aad_and_nonce(
        plaintext: &[u8],
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_nonce(nonce)?;

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        // Encrypt with AAD and provided nonce
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED))?;

        Ok(ciphertext)
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

/// AWS-LC-RS AES-256-GCM symmetric encryption
pub struct AwsLcAesGcm;

impl AwsLcAesGcm {
    /// Generate a new AES-256 key (32 bytes)
    #[inline]
    pub fn generate_key() -> CryptoResult<Vec<u8>> {
        SecureRandom::generate_bytes(AES_KEY_SIZE)
    }

    /// Encrypt data using AWS-LC-RS AES-256-GCM
    /// Returns: nonce (12 bytes) + ciphertext + tag
    #[inline]
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;

        // Create RandomizedNonceKey (automatically handles secure nonce generation)
        let randomized_key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place - RandomizedNonceKey automatically generates secure nonce
        let (nonce, tag) = randomized_key
            .seal_in_place_separate_tag(Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Pre-allocate final result buffer with exact capacity
        let nonce_bytes = nonce.as_ref();
        let tag_bytes = tag.as_ref();
        let total_len = nonce_bytes.len() + in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(nonce_bytes);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        Ok(result)
    }

    /// Decrypt data using AWS-LC-RS AES-256-GCM
    /// Input format: nonce (12 bytes) + ciphertext + tag
    #[inline]
    pub fn decrypt(ciphertext_with_nonce: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_ciphertext_length(ciphertext_with_nonce)?;

        // Create RandomizedNonceKey
        let randomized_key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;

        // Extract nonce and ciphertext+tag
        let (nonce_bytes, ciphertext_and_tag) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce = AwsNonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(ciphertext_and_tag.len());
        in_out.extend_from_slice(ciphertext_and_tag);

        // Decrypt in place
        let plaintext = randomized_key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed(AWS_LC_AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt with provided nonce (for testing purposes)
    /// Note: Uses LessSafeKey since RandomizedNonceKey generates nonces automatically
    #[inline]
    pub fn encrypt_with_nonce(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_nonce(nonce)?;

        // Create unbound key and LessSafeKey for manual nonce control
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let aws_nonce = AwsNonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place and get separate tag
        let tag = less_safe_key
            .seal_in_place_separate_tag(aws_nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Pre-allocate final result buffer with exact capacity
        let tag_bytes = tag.as_ref();
        let total_len = in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        Ok(result)
    }

    /// Encrypt with associated data (AAD) for additional authentication
    #[inline]
    pub fn encrypt_with_aad(plaintext: &[u8], key: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;

        // Create RandomizedNonceKey (automatically handles secure nonce generation)
        let randomized_key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt with AAD - RandomizedNonceKey automatically generates secure nonce
        let (nonce, tag) = randomized_key
            .seal_in_place_separate_tag(Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Pre-allocate final result buffer with exact capacity
        let nonce_bytes = nonce.as_ref();
        let tag_bytes = tag.as_ref();
        let total_len = nonce_bytes.len() + in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(nonce_bytes);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        Ok(result)
    }

    /// Encrypt with associated data (AAD) and provided nonce for additional authentication
    /// This function combines the functionality of encrypt_with_aad and encrypt_with_nonce
    /// Note: Uses LessSafeKey since we need manual nonce control
    #[inline]
    pub fn encrypt_with_aad_and_nonce(
        plaintext: &[u8],
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_nonce(nonce)?;

        // Create unbound key and LessSafeKey for manual nonce control
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let aws_nonce = AwsNonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place with AAD and get separate tag
        let tag = less_safe_key
            .seal_in_place_separate_tag(aws_nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Pre-allocate final result buffer with exact capacity
        let tag_bytes = tag.as_ref();
        let total_len = in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        Ok(result)
    }
    
    /// Decrypt with associated data (AAD) for additional authentication
    #[inline]
    pub fn decrypt_with_aad(
        ciphertext_with_nonce: &[u8],
        key: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Self::validate_key(key)?;
        Self::validate_ciphertext_length(ciphertext_with_nonce)?;

        // Create RandomizedNonceKey
        let randomized_key = RandomizedNonceKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;

        // Extract nonce and ciphertext+tag
        let (nonce_bytes, ciphertext_and_tag) = ciphertext_with_nonce.split_at(AES_NONCE_SIZE);
        let nonce = AwsNonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer with exact capacity to avoid reallocation
        let mut in_out = Vec::with_capacity(ciphertext_and_tag.len());
        in_out.extend_from_slice(ciphertext_and_tag);

        // Decrypt with AAD
        let plaintext = randomized_key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed(AWS_LC_AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext.to_vec())
    }

    // Private helper methods for validation (reuse existing ones)
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
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
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
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(CHACHA20_DECRYPTION_FAILED))?;

        Ok(plaintext)
    }
}

// Type alias to make AWS-LC-RS AES-GCM the default implementation
/// Default AES-256-GCM implementation using AWS-LC-RS
///
/// This provides FIPS 140-2 validated cryptography with optimized performance.
/// For the RustCrypto implementation, use `RustCryptoAesGcm` directly.
pub type AesGcm = AwsLcAesGcm;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rustcrypto_aes_gcm_encrypt_decrypt() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Hello, World! This is a test message.";

        let ciphertext = RustCryptoAesGcm::encrypt(plaintext, &key).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len()); // Should include nonce and tag

        let decrypted = RustCryptoAesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rustcrypto_aes_gcm_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        let plaintext = b"test";

        let result = RustCryptoAesGcm::encrypt(plaintext, &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_rustcrypto_aes_gcm_empty_plaintext() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"";

        let ciphertext = RustCryptoAesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = RustCryptoAesGcm::decrypt(&ciphertext, &key).unwrap();
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
    fn test_rustcrypto_aes_gcm_tampered_ciphertext() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Hello, World!";

        let mut ciphertext = RustCryptoAesGcm::encrypt(plaintext, &key).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(20) {
            *byte = byte.wrapping_add(1);
        }

        let result = RustCryptoAesGcm::decrypt(&ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_rustcrypto_aes_gcm_with_aad() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"additional authenticated data";

        let ciphertext = RustCryptoAesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let decrypted = RustCryptoAesGcm::decrypt_with_aad(&ciphertext, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rustcrypto_aes_gcm_with_aad_wrong_aad() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"additional authenticated data";
        let wrong_aad = b"wrong additional data";

        let ciphertext = RustCryptoAesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let result = RustCryptoAesGcm::decrypt_with_aad(&ciphertext, &key, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_rustcrypto_aes_gcm_encrypt_with_aad_and_nonce() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message with AAD and nonce";
        let aad = b"additional authenticated data";
        let nonce = vec![1u8; AES_NONCE_SIZE]; // Fixed nonce for testing

        let ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Verify ciphertext is not the same as plaintext
        assert_ne!(ciphertext, plaintext);

        // Create full ciphertext with nonce for decryption
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&ciphertext);

        let decrypted = RustCryptoAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rustcrypto_aes_gcm_encrypt_with_aad_and_nonce_deterministic() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Test deterministic encryption";
        let aad = b"test aad";
        let nonce = vec![2u8; AES_NONCE_SIZE]; // Fixed nonce

        let ciphertext1 = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();
        let ciphertext2 = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // With same nonce, AAD, and key, ciphertext should be identical
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_rustcrypto_aes_gcm_encrypt_with_aad_and_nonce_wrong_aad() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";
        let nonce = vec![3u8; AES_NONCE_SIZE];

        let ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Create full ciphertext with nonce
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&ciphertext);

        let result = RustCryptoAesGcm::decrypt_with_aad(&full_ciphertext, &key, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_rustcrypto_aes_gcm_encrypt_with_aad_and_nonce_invalid_nonce() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"test";
        let aad = b"test aad";
        let invalid_nonce = vec![0u8; 8]; // Wrong nonce length

        let result = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &invalid_nonce);
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
    fn test_rustcrypto_aes_gcm_ciphertext_too_short() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let short_ciphertext = vec![0u8; 20]; // Less than MIN_CIPHERTEXT_SIZE

        let result = RustCryptoAesGcm::decrypt(&short_ciphertext, &key);
        assert!(result.is_err());
    }

    // AWS-LC-RS AES-GCM Tests
    #[test]
    fn test_aws_lc_aes_gcm_encrypt_decrypt() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Hello, AWS-LC-RS World! This is a test message.";

        let ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len()); // Should include nonce and tag

        let decrypted = AwsLcAesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aws_lc_aes_gcm_invalid_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        let plaintext = b"test";

        let result = AwsLcAesGcm::encrypt(plaintext, &short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_empty_plaintext() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"";

        let ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AwsLcAesGcm::decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aws_lc_aes_gcm_tampered_ciphertext() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Hello, AWS-LC-RS!";

        let mut ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(20) {
            *byte = byte.wrapping_add(1);
        }

        let result = AwsLcAesGcm::decrypt(&ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_with_aad() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message with AWS-LC-RS";
        let aad = b"additional authenticated data";

        let ciphertext = AwsLcAesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let decrypted = AwsLcAesGcm::decrypt_with_aad(&ciphertext, &key, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aws_lc_aes_gcm_with_aad_wrong_aad() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message with AWS-LC-RS";
        let aad = b"additional authenticated data";
        let wrong_aad = b"wrong additional data";

        let ciphertext = AwsLcAesGcm::encrypt_with_aad(plaintext, &key, aad).unwrap();
        let result = AwsLcAesGcm::decrypt_with_aad(&ciphertext, &key, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_ciphertext_too_short() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let short_ciphertext = vec![0u8; 20]; // Less than MIN_CIPHERTEXT_SIZE

        let result = AwsLcAesGcm::decrypt(&short_ciphertext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_nonce() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Test message";
        let nonce = vec![0u8; AES_NONCE_SIZE]; // Fixed nonce for testing

        let ciphertext1 = AwsLcAesGcm::encrypt_with_nonce(plaintext, &key, &nonce).unwrap();
        let ciphertext2 = AwsLcAesGcm::encrypt_with_nonce(plaintext, &key, &nonce).unwrap();

        // With same nonce, ciphertext should be identical
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_aad_and_nonce() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message with AAD and nonce";
        let aad = b"additional authenticated data";
        let nonce = vec![1u8; AES_NONCE_SIZE]; // Fixed nonce for testing

        let ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Verify ciphertext is not the same as plaintext
        assert_ne!(ciphertext, plaintext);

        // Create full ciphertext with nonce for decryption (AWS-LC format: nonce + ciphertext + tag)
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&ciphertext);

        let decrypted = AwsLcAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_aad_and_nonce_deterministic() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Test deterministic encryption";
        let aad = b"test aad";
        let nonce = vec![2u8; AES_NONCE_SIZE]; // Fixed nonce

        let ciphertext1 = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();
        let ciphertext2 = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // With same nonce, AAD, and key, ciphertext should be identical
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_aad_and_nonce_wrong_aad() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Secret message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";
        let nonce = vec![3u8; AES_NONCE_SIZE];

        let ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Create full ciphertext with nonce
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&ciphertext);

        let result = AwsLcAesGcm::decrypt_with_aad(&full_ciphertext, &key, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_aad_and_nonce_invalid_nonce() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"test";
        let aad = b"test aad";
        let invalid_nonce = vec![0u8; 8]; // Wrong nonce length

        let result = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &invalid_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_aws_lc_aes_gcm_encrypt_with_aad_and_nonce_invalid_key() {
        let invalid_key = vec![0u8; 16]; // Wrong key length
        let plaintext = b"test";
        let aad = b"test aad";
        let nonce = vec![0u8; AES_NONCE_SIZE];

        let result = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &invalid_key, aad, &nonce);
        assert!(result.is_err());
    }

    // Cross-implementation compatibility test

    #[test]
    fn test_aes_gcm_implementations_different_outputs() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Test message for comparison";

        // Both implementations should encrypt the same plaintext differently due to random nonces
        let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt(plaintext, &key).unwrap();
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();

        // Ciphertexts should be different (due to different random nonces)
        assert_ne!(rustcrypto_ciphertext, aws_lc_ciphertext);

        // But both should decrypt to the same plaintext
        let rustcrypto_decrypted = RustCryptoAesGcm::decrypt(&rustcrypto_ciphertext, &key).unwrap();
        let aws_lc_decrypted = AwsLcAesGcm::decrypt(&aws_lc_ciphertext, &key).unwrap();

        assert_eq!(rustcrypto_decrypted, plaintext);
        assert_eq!(aws_lc_decrypted, plaintext);
        assert_eq!(rustcrypto_decrypted, aws_lc_decrypted);
    }

    #[test]
    fn test_aws_lc_aes_gcm_randomized_nonce_key_generates_different_nonces() {
        let key = AwsLcAesGcm::generate_key().unwrap();
        let plaintext = b"Test message for nonce randomness";

        // Encrypt the same plaintext multiple times
        let ciphertext1 = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        let ciphertext2 = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        let ciphertext3 = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();

        // All ciphertexts should be different due to random nonces
        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(ciphertext2, ciphertext3);
        assert_ne!(ciphertext1, ciphertext3);

        // Extract nonces (first 12 bytes) and verify they're different
        let nonce1 = &ciphertext1[..AES_NONCE_SIZE];
        let nonce2 = &ciphertext2[..AES_NONCE_SIZE];
        let nonce3 = &ciphertext3[..AES_NONCE_SIZE];

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);

        // All should decrypt to the same plaintext
        let decrypted1 = AwsLcAesGcm::decrypt(&ciphertext1, &key).unwrap();
        let decrypted2 = AwsLcAesGcm::decrypt(&ciphertext2, &key).unwrap();
        let decrypted3 = AwsLcAesGcm::decrypt(&ciphertext3, &key).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        assert_eq!(decrypted3, plaintext);
    }

    // Cross-implementation compatibility tests for encrypt_with_aad_and_nonce
    #[test]
    fn test_encrypt_with_aad_and_nonce_cross_implementation_compatibility() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Cross-implementation test message";
        let aad = b"shared aad data";
        let nonce = vec![5u8; AES_NONCE_SIZE]; // Fixed nonce for both implementations

        // Encrypt with both implementations using same parameters
        let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Both should produce the same ciphertext (deterministic with same nonce)
        assert_eq!(rustcrypto_ciphertext, aws_lc_ciphertext);

        // Create full ciphertext format for decryption (nonce + ciphertext)
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + rustcrypto_ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&rustcrypto_ciphertext);

        // Both implementations should be able to decrypt each other's output
        let rustcrypto_decrypted = RustCryptoAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();
        let aws_lc_decrypted = AwsLcAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();

        assert_eq!(rustcrypto_decrypted, plaintext);
        assert_eq!(aws_lc_decrypted, plaintext);
        assert_eq!(rustcrypto_decrypted, aws_lc_decrypted);
    }

    #[test]
    fn test_encrypt_with_aad_and_nonce_empty_aad() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let plaintext = b"Test with empty AAD";
        let empty_aad = b"";
        let nonce = vec![6u8; AES_NONCE_SIZE];

        // Test both implementations with empty AAD
        let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, empty_aad, &nonce).unwrap();
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, empty_aad, &nonce).unwrap();

        // Should produce same result
        assert_eq!(rustcrypto_ciphertext, aws_lc_ciphertext);

        // Create full ciphertext for decryption
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + rustcrypto_ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&rustcrypto_ciphertext);

        // Both should decrypt successfully
        let rustcrypto_decrypted = RustCryptoAesGcm::decrypt_with_aad(&full_ciphertext, &key, empty_aad).unwrap();
        let aws_lc_decrypted = AwsLcAesGcm::decrypt_with_aad(&full_ciphertext, &key, empty_aad).unwrap();

        assert_eq!(rustcrypto_decrypted, plaintext);
        assert_eq!(aws_lc_decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_with_aad_and_nonce_empty_plaintext() {
        let key = RustCryptoAesGcm::generate_key().unwrap();
        let empty_plaintext = b"";
        let aad = b"test aad for empty plaintext";
        let nonce = vec![7u8; AES_NONCE_SIZE];

        // Test both implementations with empty plaintext
        let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(empty_plaintext, &key, aad, &nonce).unwrap();
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(empty_plaintext, &key, aad, &nonce).unwrap();

        // Should produce same result
        assert_eq!(rustcrypto_ciphertext, aws_lc_ciphertext);

        // Create full ciphertext for decryption
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + rustcrypto_ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&rustcrypto_ciphertext);

        // Both should decrypt successfully to empty plaintext
        let rustcrypto_decrypted = RustCryptoAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();
        let aws_lc_decrypted = AwsLcAesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();

        assert_eq!(rustcrypto_decrypted, empty_plaintext);
        assert_eq!(aws_lc_decrypted, empty_plaintext);
    }

    // Test that AesGcm type alias points to AwsLcAesGcm
    #[test]
    fn test_aes_gcm_type_alias_uses_aws_lc() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Test that AesGcm uses AWS-LC-RS by default";

        let ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        let decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();

        assert_eq!(decrypted, plaintext);

        // Verify that AesGcm and AwsLcAesGcm produce compatible results
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt(plaintext, &key).unwrap();
        let aws_lc_decrypted = AesGcm::decrypt(&aws_lc_ciphertext, &key).unwrap();
        assert_eq!(aws_lc_decrypted, plaintext);

        let aes_gcm_ciphertext = AesGcm::encrypt(plaintext, &key).unwrap();
        let aes_gcm_decrypted = AwsLcAesGcm::decrypt(&aes_gcm_ciphertext, &key).unwrap();
        assert_eq!(aes_gcm_decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_type_alias_encrypt_with_aad_and_nonce() {
        let key = AesGcm::generate_key().unwrap();
        let plaintext = b"Test AesGcm type alias with AAD and nonce";
        let aad = b"type alias test aad";
        let nonce = vec![8u8; AES_NONCE_SIZE];

        // Test that AesGcm type alias has the encrypt_with_aad_and_nonce function
        let ciphertext = AesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();

        // Create full ciphertext for decryption
        let mut full_ciphertext = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
        full_ciphertext.extend_from_slice(&nonce);
        full_ciphertext.extend_from_slice(&ciphertext);

        let decrypted = AesGcm::decrypt_with_aad(&full_ciphertext, &key, aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Verify compatibility with AwsLcAesGcm
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &nonce).unwrap();
        assert_eq!(ciphertext, aws_lc_ciphertext);
    }
}
