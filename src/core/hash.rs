use crate::error::{CryptoError, CryptoResult, HASH_LENGTH_ZERO, INVALID_HMAC_KEY};
use sha2::{Sha256, Sha512, Digest};
use blake3::Hasher as Blake3Hasher;

/// SHA-256 hashing
pub struct Sha256Hash;

impl Sha256Hash {
    /// Compute SHA-256 hash of input data
    #[inline]
    pub fn hash(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Compute SHA-256 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify data against a SHA-256 hash
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        let computed_hash = Self::hash(data)?;
        Ok(computed_hash == expected_hash)
    }
}

/// SHA-512 hashing
pub struct Sha512Hash;

impl Sha512Hash {
    /// Compute SHA-512 hash of input data
    #[inline]
    pub fn hash(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    /// Compute SHA-512 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verify data against a SHA-512 hash
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        let computed_hash = Self::hash(data)?;
        Ok(computed_hash == expected_hash)
    }
}

/// BLAKE3 hashing
pub struct Blake3Hash;

impl Blake3Hash {
    /// Compute BLAKE3 hash of input data
    #[inline]
    pub fn hash(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let hash = blake3::hash(data);
        Ok(hash.as_bytes().to_vec())
    }

    /// Compute BLAKE3 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let hash = blake3::hash(data);
        Ok(hex::encode(hash.as_bytes()))
    }

    /// Verify data against a BLAKE3 hash
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        let computed_hash = Self::hash(data)?;
        Ok(computed_hash == expected_hash)
    }

    /// Compute BLAKE3 hash with custom output length
    #[inline]
    pub fn hash_with_length(data: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput(HASH_LENGTH_ZERO));
        }

        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let mut output = vec![0u8; length];
        hasher.finalize_xof().fill(&mut output);
        Ok(output)
    }
}

/// HMAC (Hash-based Message Authentication Code)
pub struct Hmac;

impl Hmac {
    /// Compute HMAC-SHA256
    #[inline]
    pub fn sha256(key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        use sha2::Sha256;
        use hmac::{Hmac as HmacImpl, Mac};

        type HmacSha256 = HmacImpl<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_HMAC_KEY))?;

        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Compute HMAC-SHA512
    #[inline]
    pub fn sha512(key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        use sha2::Sha512;
        use hmac::{Hmac as HmacImpl, Mac};

        type HmacSha512 = HmacImpl<Sha512>;

        let mut mac = HmacSha512::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_HMAC_KEY))?;

        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verify HMAC-SHA256
    #[inline]
    pub fn verify_sha256(key: &[u8], message: &[u8], expected_mac: &[u8]) -> CryptoResult<bool> {
        let computed_mac = Self::sha256(key, message)?;
        Ok(computed_mac == expected_mac)
    }

    /// Verify HMAC-SHA512
    #[inline]
    pub fn verify_sha512(key: &[u8], message: &[u8], expected_mac: &[u8]) -> CryptoResult<bool> {
        let computed_mac = Self::sha512(key, message)?;
        Ok(computed_mac == expected_mac)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello, World!";
        let hash = Sha256Hash::hash(data).unwrap();

        // SHA-256 hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Test known hash value
        let expected = hex::decode("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f").unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_hash_hex() {
        let data = b"Hello, World!";
        let hash_hex = Sha256Hash::hash_hex(data).unwrap();

        assert_eq!(hash_hex, "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    }

    #[test]
    fn test_sha256_verify() {
        let data = b"Hello, World!";
        let hash = Sha256Hash::hash(data).unwrap();

        assert!(Sha256Hash::verify(data, &hash).unwrap());
        assert!(!Sha256Hash::verify(b"Different data", &hash).unwrap());
    }

    #[test]
    fn test_sha512_hash() {
        let data = b"Hello, World!";
        let hash = Sha512Hash::hash(data).unwrap();

        // SHA-512 hash should be 64 bytes
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake3_hash() {
        let data = b"Hello, World!";
        let hash = Blake3Hash::hash(data).unwrap();

        // BLAKE3 hash should be 32 bytes by default
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_hash_with_length() {
        let data = b"Hello, World!";
        let hash = Blake3Hash::hash_with_length(data, 64).unwrap();

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake3_hash_zero_length() {
        let data = b"Hello, World!";
        let result = Blake3Hash::hash_with_length(data, 0);

        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let message = b"Hello, World!";

        let mac = Hmac::sha256(key, message).unwrap();
        assert_eq!(mac.len(), 32); // SHA-256 output length

        // Verify HMAC
        assert!(Hmac::verify_sha256(key, message, &mac).unwrap());
        assert!(!Hmac::verify_sha256(b"wrong_key", message, &mac).unwrap());
    }

    #[test]
    fn test_hmac_sha512() {
        let key = b"secret_key";
        let message = b"Hello, World!";

        let mac = Hmac::sha512(key, message).unwrap();
        assert_eq!(mac.len(), 64); // SHA-512 output length

        // Verify HMAC
        assert!(Hmac::verify_sha512(key, message, &mac).unwrap());
        assert!(!Hmac::verify_sha512(b"wrong_key", message, &mac).unwrap());
    }



    #[test]
    fn test_empty_data_hash() {
        let data = b"";

        let sha256_hash = Sha256Hash::hash(data).unwrap();
        let sha512_hash = Sha512Hash::hash(data).unwrap();
        let blake3_hash = Blake3Hash::hash(data).unwrap();

        assert_eq!(sha256_hash.len(), 32);
        assert_eq!(sha512_hash.len(), 64);
        assert_eq!(blake3_hash.len(), 32);
    }
}