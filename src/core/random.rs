use crate::error::{CryptoError, CryptoResult};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

/// Secure random number generator
pub struct SecureRandom;

impl SecureRandom {
    /// Generate random bytes using the OS random number generator
    pub fn generate_bytes(length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput("Length cannot be zero".to_string()));
        }

        let mut bytes = vec![0u8; length];
        OsRng.try_fill_bytes(&mut bytes)
            .map_err(|e| CryptoError::RandomGenerationFailed(format!("Failed to generate random bytes: {}", e)))?;

        Ok(bytes)
    }

    /// Generate a random u32
    pub fn generate_u32() -> CryptoResult<u32> {
        Ok(OsRng.next_u32())
    }

    /// Generate a random u64
    pub fn generate_u64() -> CryptoResult<u64> {
        Ok(OsRng.next_u64())
    }

    /// Generate a cryptographically secure random key of specified length
    pub fn generate_key(length: usize) -> CryptoResult<SecureKey> {
        let bytes = Self::generate_bytes(length)?;
        Ok(SecureKey::new(bytes))
    }

    /// Generate a random nonce/IV of specified length
    pub fn generate_nonce(length: usize) -> CryptoResult<Vec<u8>> {
        Self::generate_bytes(length)
    }

    /// Generate a random salt for password hashing
    pub fn generate_salt() -> CryptoResult<Vec<u8>> {
        Self::generate_bytes(32) // 256-bit salt
    }
}

/// A secure key that automatically zeros its memory when dropped
#[derive(Clone)]
pub struct SecureKey {
    data: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the key data as a slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to Vec<u8> (consumes the SecureKey)
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Zeroize for SecureKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureKey")
            .field("len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bytes() {
        let bytes = SecureRandom::generate_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // Generate another set and ensure they're different
        let bytes2 = SecureRandom::generate_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_generate_bytes_zero_length() {
        let result = SecureRandom::generate_bytes(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_u32() {
        let num1 = SecureRandom::generate_u32().unwrap();
        let num2 = SecureRandom::generate_u32().unwrap();
        // Very unlikely to be equal
        assert_ne!(num1, num2);
    }

    #[test]
    fn test_generate_key() {
        let key = SecureRandom::generate_key(32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_secure_key_drop() {
        // Test that the key is properly created and can be used
        let data = vec![1, 2, 3, 4];
        let key = SecureKey::new(data);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(key.len(), 4);
        assert!(!key.is_empty());
        // Drop happens automatically at end of scope
    }

    #[test]
    fn test_secure_key_into_bytes() {
        let key = SecureKey::new(vec![1, 2, 3, 4]);
        let bytes = key.into_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_generate_salt() {
        let salt = SecureRandom::generate_salt().unwrap();
        assert_eq!(salt.len(), 32);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = SecureRandom::generate_nonce(12).unwrap();
        assert_eq!(nonce.len(), 12);
    }
}