use crate::core::random::SecureRandom;
use crate::error::{
    CryptoError, CryptoResult, AWS_LC_AES_GCM_DECRYPTION_FAILED, AWS_LC_AES_GCM_ENCRYPTION_FAILED,
    INVALID_KEY_LENGTH_AES, INVALID_NONCE_LENGTH, CIPHERTEXT_TOO_SHORT,
    INVALID_AUTHENTICATION_TAG, AUTHENTICATION_TAG_VERIFICATION_FAILED,
};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce as AwsNonce, UnboundKey, AES_256_GCM,
};
use std::sync::{Arc, Mutex};

// Constants for AES-GCM streaming
pub const AES_KEY_SIZE: usize = 32; // 256 bits
pub const AES_NONCE_SIZE: usize = 12; // 96 bits
pub const AES_TAG_SIZE: usize = 16; // 128 bits
pub const MIN_CIPHERTEXT_SIZE: usize = AES_NONCE_SIZE + AES_TAG_SIZE; // 28 bytes minimum

// Error messages for stream cipher
pub const STREAM_CIPHER_INIT_FAILED: &str = "Stream cipher initialization failed";
pub const NONCE_OVERFLOW: &str = "Nonce counter overflow - reset required";
pub const STREAM_CIPHER_POISONED: &str = "Stream cipher mutex poisoned";

/// Result of authenticated encryption operation containing ciphertext and authentication tag
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatedCiphertext {
    /// The encrypted data (without nonce or tag)
    pub ciphertext: Vec<u8>,
    /// The authentication tag for integrity verification
    pub tag: Vec<u8>,
    /// The nonce used for this encryption operation
    pub nonce: Vec<u8>,
}

/// Thread-safe streaming AES-256-GCM cipher implementation using AWS-LC-RS
/// 
/// This implementation maintains internal state for nonce management and provides
/// streaming encryption/decryption capabilities. It automatically handles nonce
/// increment to prevent reuse within the same key context.
/// 
/// # Security Notes
/// - Nonces are automatically incremented for each operation
/// - The cipher must be reset when nonce counter approaches overflow
/// - Thread-safe operations using Arc<Mutex<>> for shared state
#[derive(Clone)]
pub struct StreamCipher {
    inner: Arc<Mutex<StreamCipherInner>>,
}

struct StreamCipherInner {
    key: LessSafeKey,
    nonce_counter: u64,
    base_nonce: [u8; AES_NONCE_SIZE],
}

impl StreamCipher {
    /// Create a new StreamCipher instance with the provided encryption key
    /// 
    /// # Arguments
    /// * `key` - AES-256 key (must be exactly 32 bytes)
    /// 
    /// # Returns
    /// * `Ok(StreamCipher)` - Successfully initialized stream cipher
    /// * `Err(CryptoError)` - If key validation fails or initialization fails
    pub fn new(key: &[u8]) -> CryptoResult<Self> {
        Self::validate_key(key)?;

        // Create AWS-LC-RS key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES))?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        // Generate a random base nonce
        let base_nonce_bytes = SecureRandom::generate_nonce(AES_NONCE_SIZE)?;
        let mut base_nonce = [0u8; AES_NONCE_SIZE];
        base_nonce.copy_from_slice(&base_nonce_bytes);

        let inner = StreamCipherInner {
            key: less_safe_key,
            nonce_counter: 0,
            base_nonce,
        };

        Ok(StreamCipher {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Encrypt a chunk of data using the stream cipher
    /// 
    /// This method automatically generates a unique nonce for each operation
    /// by incrementing an internal counter. The returned ciphertext includes
    /// the nonce prefix for decryption.
    /// 
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` - Encrypted data with nonce prefix (nonce + ciphertext + tag)
    /// * `Err(CryptoError)` - If encryption fails or nonce overflow occurs
    /// 
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn encrypt_chunk(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Generate unique nonce by combining base nonce with counter
        let current_nonce = inner.generate_nonce()?;
        let nonce_bytes: Vec<u8> = current_nonce.as_ref().to_vec();

        // Pre-allocate buffer for in-place encryption
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place and get separate tag
        let tag = inner.key
            .seal_in_place_separate_tag(current_nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Build result: nonce + ciphertext + tag
        let tag_bytes = tag.as_ref();
        let total_len = nonce_bytes.len() + in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        // Increment nonce counter for next operation
        inner.increment_nonce_counter()?;

        Ok(result)
    }

    /// Decrypt a chunk of data using the stream cipher
    /// 
    /// The ciphertext must include the nonce prefix as returned by encrypt_chunk.
    /// 
    /// # Arguments
    /// * `ciphertext` - Encrypted data with nonce prefix (nonce + ciphertext + tag)
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext data
    /// * `Err(CryptoError)` - If decryption fails or ciphertext format is invalid
    /// 
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn decrypt_chunk(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_ciphertext_length(ciphertext)?;

        let inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Extract nonce and ciphertext+tag
        let (nonce_bytes, ciphertext_and_tag) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = AwsNonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer for in-place decryption
        let mut in_out = Vec::with_capacity(ciphertext_and_tag.len());
        in_out.extend_from_slice(ciphertext_and_tag);

        // Decrypt in place
        let plaintext = inner.key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed(AWS_LC_AES_GCM_DECRYPTION_FAILED))?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt a chunk of data with additional authenticated data (AAD)
    ///
    /// This method performs authenticated encryption where the AAD is authenticated
    /// but not encrypted. The returned ciphertext includes the nonce prefix for
    /// decryption, similar to the standard encrypt_chunk method.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Encrypted data with nonce prefix (nonce + ciphertext + tag)
    /// * `Err(CryptoError)` - If encryption fails or nonce overflow occurs
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn encrypt_chunk_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Generate unique nonce by combining base nonce with counter
        let current_nonce = inner.generate_nonce()?;
        let nonce_bytes: Vec<u8> = current_nonce.as_ref().to_vec();

        // Pre-allocate buffer for in-place encryption
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place with AAD and get separate tag
        let aad_obj = Aad::from(aad);
        let tag = inner.key
            .seal_in_place_separate_tag(current_nonce, aad_obj, &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Build result: nonce + ciphertext + tag
        let tag_bytes = tag.as_ref();
        let total_len = nonce_bytes.len() + in_out.len() + tag_bytes.len();

        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag_bytes);

        // Increment nonce counter for next operation
        inner.increment_nonce_counter()?;

        Ok(result)
    }

    /// Decrypt a chunk of data with additional authenticated data (AAD)
    ///
    /// This method performs authenticated decryption where the AAD is verified
    /// along with the ciphertext. The ciphertext must include the nonce prefix
    /// and authentication tag as returned by encrypt_chunk_with_aad.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with nonce prefix (nonce + ciphertext + tag)
    /// * `aad` - Additional authenticated data (same as used during encryption)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext data
    /// * `Err(CryptoError)` - If decryption or authentication fails
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn decrypt_chunk_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_ciphertext_length(ciphertext)?;

        let inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Extract nonce and ciphertext+tag
        let (nonce_bytes, ciphertext_and_tag) = ciphertext.split_at(AES_NONCE_SIZE);
        let nonce = AwsNonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Pre-allocate buffer for in-place decryption
        let mut in_out = Vec::with_capacity(ciphertext_and_tag.len());
        in_out.extend_from_slice(ciphertext_and_tag);

        // Decrypt in place with AAD
        let aad_obj = Aad::from(aad);
        let plaintext = inner.key
            .open_in_place(nonce, aad_obj, &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed(AUTHENTICATION_TAG_VERIFICATION_FAILED))?;

        Ok(plaintext.to_vec())
    }

    /// Reset the stream cipher state
    /// 
    /// This generates a new base nonce and resets the nonce counter to 0.
    /// Use this method when the nonce counter approaches overflow or when
    /// starting a new encryption session.
    /// 
    /// # Thread Safety
    /// This method is thread-safe but will block other operations during reset.
    pub fn reset(&self) -> CryptoResult<()> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Generate new base nonce
        let base_nonce_bytes = SecureRandom::generate_nonce(AES_NONCE_SIZE)?;
        inner.base_nonce.copy_from_slice(&base_nonce_bytes);
        
        // Reset counter
        inner.nonce_counter = 0;

        Ok(())
    }

    /// Get the current nonce counter value
    /// 
    /// This can be used to monitor nonce usage and determine when to reset.
    /// Consider resetting when the counter approaches u64::MAX to prevent overflow.
    pub fn get_nonce_counter(&self) -> CryptoResult<u64> {
        let inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;
        Ok(inner.nonce_counter)
    }

    /// Encrypt a chunk of data and return separate ciphertext and authentication tag
    ///
    /// This method performs authenticated encryption and returns the components
    /// separately for flexible handling.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// * `Ok(AuthenticatedCiphertext)` - Encrypted data with separate tag and nonce
    /// * `Err(CryptoError)` - If encryption fails or nonce overflow occurs
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn encrypt_chunk_with_separate_components(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<AuthenticatedCiphertext> {
        let mut inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Generate unique nonce by combining base nonce with counter
        let current_nonce = inner.generate_nonce()?;
        let nonce_bytes: Vec<u8> = current_nonce.as_ref().to_vec();

        // Pre-allocate buffer for in-place encryption
        let mut in_out = Vec::with_capacity(plaintext.len());
        in_out.extend_from_slice(plaintext);

        // Encrypt in place with AAD and get separate tag
        let aad_obj = Aad::from(aad);
        let tag = inner.key
            .seal_in_place_separate_tag(current_nonce, aad_obj, &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed(AWS_LC_AES_GCM_ENCRYPTION_FAILED))?;

        // Increment nonce counter for next operation
        inner.increment_nonce_counter()?;

        Ok(AuthenticatedCiphertext {
            ciphertext: in_out,
            tag: tag.as_ref().to_vec(),
            nonce: nonce_bytes,
        })
    }

    /// Encrypt a chunk of data and return separate ciphertext and authentication tag
    ///
    /// This is a convenience method that performs authenticated encryption without AAD
    /// and returns the components separately for flexible handling.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// * `Ok(AuthenticatedCiphertext)` - Encrypted data with separate tag and nonce
    /// * `Err(CryptoError)` - If encryption fails or nonce overflow occurs
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn encrypt_chunk_with_tag(&self, plaintext: &[u8]) -> CryptoResult<AuthenticatedCiphertext> {
        self.encrypt_chunk_with_separate_components(plaintext, &[])
    }

    /// Decrypt a chunk of data using separate ciphertext and authentication tag
    ///
    /// This method performs authenticated decryption using separately provided
    /// ciphertext, tag, and nonce components.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data (without nonce or tag)
    /// * `tag` - Authentication tag for integrity verification
    /// * `nonce` - Nonce used during encryption
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext data
    /// * `Err(CryptoError)` - If decryption or authentication fails
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn decrypt_chunk_with_tag(&self, ciphertext: &[u8], tag: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        self.decrypt_chunk_with_separate_components(ciphertext, tag, nonce, &[])
    }

    /// Decrypt a chunk of data using separate components with AAD
    ///
    /// This method performs authenticated decryption with AAD using separately
    /// provided ciphertext, tag, nonce, and AAD components.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data (without nonce or tag)
    /// * `tag` - Authentication tag for integrity verification
    /// * `nonce` - Nonce used during encryption
    /// * `aad` - Additional authenticated data (same as used during encryption)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext data
    /// * `Err(CryptoError)` - If decryption or authentication fails
    ///
    /// # Thread Safety
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn decrypt_chunk_with_separate_components(&self, ciphertext: &[u8], tag: &[u8], nonce: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::validate_tag_length(tag)?;
        Self::validate_nonce_length(nonce)?;

        let inner = self.inner.lock()
            .map_err(|_| CryptoError::InternalError(STREAM_CIPHER_POISONED))?;

        // Create nonce object
        let nonce_obj = AwsNonce::try_assume_unique_for_key(nonce)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))?;

        // Prepare buffer with ciphertext + tag for in-place decryption
        let mut in_out = Vec::with_capacity(ciphertext.len() + tag.len());
        in_out.extend_from_slice(ciphertext);
        in_out.extend_from_slice(tag);

        // Decrypt in place with AAD
        let aad_obj = Aad::from(aad);
        let plaintext = inner.key
            .open_in_place(nonce_obj, aad_obj, &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed(AUTHENTICATION_TAG_VERIFICATION_FAILED))?;

        Ok(plaintext.to_vec())
    }

    // Validation helper methods
    #[inline]
    fn validate_key(key: &[u8]) -> CryptoResult<()> {
        if key.len() != AES_KEY_SIZE {
            return Err(CryptoError::InvalidKey(INVALID_KEY_LENGTH_AES));
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

    #[inline]
    fn validate_tag_length(tag: &[u8]) -> CryptoResult<()> {
        if tag.len() != AES_TAG_SIZE {
            return Err(CryptoError::InvalidInput(INVALID_AUTHENTICATION_TAG));
        }
        Ok(())
    }

    #[inline]
    fn validate_nonce_length(nonce: &[u8]) -> CryptoResult<()> {
        if nonce.len() != AES_NONCE_SIZE {
            return Err(CryptoError::InvalidInput(INVALID_NONCE_LENGTH));
        }
        Ok(())
    }
}

impl StreamCipherInner {
    /// Generate a unique nonce by combining base nonce with counter
    fn generate_nonce(&self) -> CryptoResult<AwsNonce> {
        let mut nonce_bytes = self.base_nonce;
        
        // Combine counter with base nonce (XOR the last 8 bytes with counter)
        let counter_bytes = self.nonce_counter.to_le_bytes();
        for (i, &byte) in counter_bytes.iter().enumerate() {
            nonce_bytes[AES_NONCE_SIZE - 8 + i] ^= byte;
        }

        AwsNonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::InvalidInput(INVALID_NONCE_LENGTH))
    }

    /// Increment the nonce counter with overflow protection
    fn increment_nonce_counter(&mut self) -> CryptoResult<()> {
        self.nonce_counter = self.nonce_counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::InternalError(NONCE_OVERFLOW))?;
        Ok(())
    }
}

// Implement Send and Sync for thread safety
unsafe impl Send for StreamCipher {}
unsafe impl Sync for StreamCipher {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_cipher_new() {
        let key = vec![0u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_stream_cipher_invalid_key() {
        let key = vec![0u8; 16]; // Wrong size
        let cipher = StreamCipher::new(&key);
        assert!(cipher.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let key = vec![1u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Hello, streaming world!";

        let ciphertext = cipher.encrypt_chunk(plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = cipher.decrypt_chunk(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_multiple_chunks() {
        let key = vec![2u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        
        let chunk1 = b"First chunk";
        let chunk2 = b"Second chunk";
        
        let ciphertext1 = cipher.encrypt_chunk(chunk1).unwrap();
        let ciphertext2 = cipher.encrypt_chunk(chunk2).unwrap();
        
        // Ciphertexts should be different (different nonces)
        assert_ne!(ciphertext1, ciphertext2);
        
        let decrypted1 = cipher.decrypt_chunk(&ciphertext1).unwrap();
        let decrypted2 = cipher.decrypt_chunk(&ciphertext2).unwrap();
        
        assert_eq!(decrypted1, chunk1);
        assert_eq!(decrypted2, chunk2);
    }

    #[test]
    fn test_nonce_counter_increment() {
        let key = vec![3u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        
        let initial_counter = cipher.get_nonce_counter().unwrap();
        assert_eq!(initial_counter, 0);
        
        cipher.encrypt_chunk(b"test").unwrap();
        let after_encrypt = cipher.get_nonce_counter().unwrap();
        assert_eq!(after_encrypt, 1);
    }

    #[test]
    fn test_reset() {
        let key = vec![4u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        
        // Encrypt some chunks
        cipher.encrypt_chunk(b"chunk1").unwrap();
        cipher.encrypt_chunk(b"chunk2").unwrap();
        
        let counter_before_reset = cipher.get_nonce_counter().unwrap();
        assert_eq!(counter_before_reset, 2);
        
        // Reset
        cipher.reset().unwrap();
        let counter_after_reset = cipher.get_nonce_counter().unwrap();
        assert_eq!(counter_after_reset, 0);
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;
        
        let key = vec![5u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let cipher_clone = cipher.clone();
        
        let handle = thread::spawn(move || {
            cipher_clone.encrypt_chunk(b"thread test").unwrap()
        });
        
        let main_result = cipher.encrypt_chunk(b"main thread").unwrap();
        let thread_result = handle.join().unwrap();
        
        // Both should succeed
        assert!(main_result.len() > 0);
        assert!(thread_result.len() > 0);
        
        // Results should be different (different nonces)
        assert_ne!(main_result, thread_result);
    }

    #[test]
    fn test_ciphertext_too_short() {
        let key = vec![6u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();

        let short_ciphertext = vec![0u8; 20]; // Less than MIN_CIPHERTEXT_SIZE
        let result = cipher.decrypt_chunk(&short_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = vec![7u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Hello, authenticated world!";
        let aad = b"additional data";

        let ciphertext = cipher.encrypt_chunk_with_aad(plaintext, aad).unwrap();

        // Verify structure (nonce + ciphertext + tag)
        assert!(ciphertext.len() >= MIN_CIPHERTEXT_SIZE);
        assert_eq!(ciphertext.len(), AES_NONCE_SIZE + plaintext.len() + AES_TAG_SIZE);

        // Decrypt with correct AAD
        let decrypted = cipher.decrypt_chunk_with_aad(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_tag() {
        let key = vec![8u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Hello, tagged world!";

        let auth_ciphertext = cipher.encrypt_chunk_with_tag(plaintext).unwrap();

        // Verify structure
        assert_eq!(auth_ciphertext.nonce.len(), AES_NONCE_SIZE);
        assert_eq!(auth_ciphertext.tag.len(), AES_TAG_SIZE);
        assert_eq!(auth_ciphertext.ciphertext.len(), plaintext.len());

        // Decrypt with tag
        let decrypted = cipher.decrypt_chunk_with_tag(
            &auth_ciphertext.ciphertext,
            &auth_ciphertext.tag,
            &auth_ciphertext.nonce
        ).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aad_authentication_failure() {
        let key = vec![9u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Test message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = cipher.encrypt_chunk_with_aad(plaintext, aad).unwrap();

        // Try to decrypt with wrong AAD - should fail
        let result = cipher.decrypt_chunk_with_aad(&ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_tampering_detection() {
        let key = vec![10u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Test message";

        let auth_ciphertext = cipher.encrypt_chunk_with_tag(plaintext).unwrap();

        // Tamper with the tag
        let mut tampered_tag = auth_ciphertext.tag.clone();
        tampered_tag[0] ^= 0x01; // Flip one bit

        // Try to decrypt with tampered tag - should fail
        let result = cipher.decrypt_chunk_with_tag(
            &auth_ciphertext.ciphertext,
            &tampered_tag,
            &auth_ciphertext.nonce
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_tampering_detection() {
        let key = vec![11u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"Test message";

        let auth_ciphertext = cipher.encrypt_chunk_with_tag(plaintext).unwrap();

        // Tamper with the ciphertext
        let mut tampered_ciphertext = auth_ciphertext.ciphertext.clone();
        tampered_ciphertext[0] ^= 0x01; // Flip one bit

        // Try to decrypt with tampered ciphertext - should fail
        let result = cipher.decrypt_chunk_with_tag(
            &tampered_ciphertext,
            &auth_ciphertext.tag,
            &auth_ciphertext.nonce
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tag_length() {
        let key = vec![12u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let ciphertext = vec![0u8; 32];
        let nonce = vec![0u8; AES_NONCE_SIZE];
        let invalid_tag = vec![0u8; 8]; // Wrong size

        let result = cipher.decrypt_chunk_with_tag(&ciphertext, &invalid_tag, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = vec![13u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let ciphertext = vec![0u8; 32];
        let tag = vec![0u8; AES_TAG_SIZE];
        let invalid_nonce = vec![0u8; 8]; // Wrong size

        let result = cipher.decrypt_chunk_with_tag(&ciphertext, &tag, &invalid_nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_chunks_with_aad() {
        let key = vec![14u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();

        let chunk1 = b"First chunk";
        let chunk2 = b"Second chunk";
        let aad1 = b"aad for chunk 1";
        let aad2 = b"aad for chunk 2";

        let ciphertext1 = cipher.encrypt_chunk_with_aad(chunk1, aad1).unwrap();
        let ciphertext2 = cipher.encrypt_chunk_with_aad(chunk2, aad2).unwrap();

        // Ciphertexts should be different (different nonces)
        assert_ne!(ciphertext1, ciphertext2);

        // Decrypt both chunks
        let decrypted1 = cipher.decrypt_chunk_with_aad(&ciphertext1, aad1).unwrap();
        let decrypted2 = cipher.decrypt_chunk_with_aad(&ciphertext2, aad2).unwrap();

        assert_eq!(decrypted1, chunk1);
        assert_eq!(decrypted2, chunk2);
    }

    #[test]
    fn test_empty_plaintext_with_aad() {
        let key = vec![15u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"";
        let aad = b"some aad";

        let ciphertext = cipher.encrypt_chunk_with_aad(plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), AES_NONCE_SIZE + AES_TAG_SIZE); // Only nonce + tag for empty plaintext

        let decrypted = cipher.decrypt_chunk_with_aad(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_aad() {
        let key = vec![16u8; AES_KEY_SIZE];
        let cipher = StreamCipher::new(&key).unwrap();
        let plaintext = b"test with empty aad";
        let aad = b"";

        let ciphertext = cipher.encrypt_chunk_with_aad(plaintext, aad).unwrap();

        let decrypted = cipher.decrypt_chunk_with_aad(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
