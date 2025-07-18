use crate::error::{CryptoError, CryptoResult, HASH_LENGTH_ZERO, INVALID_HMAC_KEY};
use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256, Sha512};

/// Streaming hash context for processing large data efficiently
pub enum StreamingHasher {
    Sha256(Sha256),
    Sha512(Sha512),
    Blake3(Blake3Hasher),
}

impl StreamingHasher {
    /// Create a new SHA-256 streaming hasher
    pub fn new_sha256() -> Self {
        Self::Sha256(Sha256::new())
    }

    /// Create a new SHA-512 streaming hasher
    pub fn new_sha512() -> Self {
        Self::Sha512(Sha512::new())
    }

    /// Create a new BLAKE3 streaming hasher
    pub fn new_blake3() -> Self {
        Self::Blake3(Blake3Hasher::new())
    }

    /// Update the hasher with new data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hasher) => {
                hasher.update(data);
            }
            Self::Sha512(hasher) => {
                hasher.update(data);
            }
            Self::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }

    /// Finalize the hash and return the result
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
            Self::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
        }
    }

    /// Finalize the hash into a provided buffer (zero-allocation)
    pub fn finalize_into(self, output: &mut [u8]) -> CryptoResult<()> {
        match self {
            Self::Sha256(hasher) => {
                if output.len() != 32 {
                    return Err(CryptoError::InvalidInput(
                        "SHA-256 requires 32-byte output buffer",
                    ));
                }
                let hash = hasher.finalize();
                output.copy_from_slice(&hash);
                Ok(())
            }
            Self::Sha512(hasher) => {
                if output.len() != 64 {
                    return Err(CryptoError::InvalidInput(
                        "SHA-512 requires 64-byte output buffer",
                    ));
                }
                let hash = hasher.finalize();
                output.copy_from_slice(&hash);
                Ok(())
            }
            Self::Blake3(hasher) => {
                if output.is_empty() {
                    return Err(CryptoError::InvalidInput(HASH_LENGTH_ZERO));
                }
                hasher.finalize_xof().fill(output);
                Ok(())
            }
        }
    }
}

/// SHA-256 hashing
pub struct Sha256Hash;

impl Sha256Hash {
    /// Compute SHA-256 hash of input data
    #[inline]
    pub fn hash(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let hash = Sha256::digest(data);
        Ok(hash.to_vec())
    }

    /// Compute SHA-256 hash into provided buffer (zero-allocation)
    #[inline]
    pub fn hash_into(data: &[u8], output: &mut [u8; 32]) -> CryptoResult<()> {
        let hash = Sha256::digest(data);
        output.copy_from_slice(&hash);
        Ok(())
    }

    /// Compute SHA-256 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let hash = Sha256::digest(data);
        Ok(hex::encode(hash))
    }

    /// Verify data against a SHA-256 hash (constant-time comparison)
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        use subtle::ConstantTimeEq;
        let computed_hash = Sha256::digest(data);
        Ok(computed_hash.as_slice().ct_eq(expected_hash).into())
    }
}

/// SHA-512 hashing
pub struct Sha512Hash;

impl Sha512Hash {
    /// Compute SHA-512 hash of input data
    #[inline]
    pub fn hash(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let hash = Sha512::digest(data);
        Ok(hash.to_vec())
    }

    /// Compute SHA-512 hash into provided buffer (zero-allocation)
    #[inline]
    pub fn hash_into(data: &[u8], output: &mut [u8; 64]) -> CryptoResult<()> {
        let hash = Sha512::digest(data);
        output.copy_from_slice(&hash);
        Ok(())
    }

    /// Compute SHA-512 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let hash = Sha512::digest(data);
        Ok(hex::encode(hash))
    }

    /// Verify data against a SHA-512 hash (constant-time comparison)
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        use subtle::ConstantTimeEq;
        let hash = Sha512::digest(data);
        Ok(hash.as_slice().ct_eq(expected_hash).into())
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

    /// Compute BLAKE3 hash into provided buffer (zero-allocation)
    #[inline]
    pub fn hash_into(data: &[u8], output: &mut [u8; 32]) -> CryptoResult<()> {
        let hash = blake3::hash(data);
        output.copy_from_slice(hash.as_bytes());
        Ok(())
    }

    /// Compute BLAKE3 hash and return as hex string
    #[inline]
    pub fn hash_hex(data: &[u8]) -> CryptoResult<String> {
        let hash = blake3::hash(data);
        Ok(hex::encode(hash.as_bytes()))
    }

    /// Verify data against a BLAKE3 hash (constant-time comparison)
    #[inline]
    pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        use subtle::ConstantTimeEq;
        let hash = blake3::hash(data);
        Ok(hash.as_bytes().ct_eq(expected_hash).into())
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

    /// Compute BLAKE3 hash with custom output length into provided buffer
    #[inline]
    pub fn hash_with_length_into(data: &[u8], output: &mut [u8]) -> CryptoResult<()> {
        if output.is_empty() {
            return Err(CryptoError::InvalidInput(HASH_LENGTH_ZERO));
        }

        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        hasher.finalize_xof().fill(output);
        Ok(())
    }
}

/// HMAC (Hash-based Message Authentication Code)
pub struct Hmac;

impl Hmac {
    /// Compute HMAC-SHA256
    #[inline]
    pub fn sha256(key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        use hmac::{Hmac as HmacImpl, Mac};
        use sha2::Sha256;

        type HmacSha256 = HmacImpl<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| CryptoError::InvalidKey(INVALID_HMAC_KEY))?;

        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Compute HMAC-SHA512
    #[inline]
    pub fn sha512(key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
        use hmac::{Hmac as HmacImpl, Mac};
        use sha2::Sha512;

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
        let expected =
            hex::decode("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
                .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_hash_hex() {
        let data = b"Hello, World!";
        let hash_hex = Sha256Hash::hash_hex(data).unwrap();

        assert_eq!(
            hash_hex,
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
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

    #[test]
    fn test_hash_into_methods() {
        let data = b"Hello, World!";

        // Test SHA-256 hash_into
        let mut sha256_output = [0u8; 32];
        Sha256Hash::hash_into(data, &mut sha256_output).unwrap();
        let sha256_vec = Sha256Hash::hash(data).unwrap();
        assert_eq!(sha256_output.as_slice(), sha256_vec.as_slice());

        // Test SHA-512 hash_into
        let mut sha512_output = [0u8; 64];
        Sha512Hash::hash_into(data, &mut sha512_output).unwrap();
        let sha512_vec = Sha512Hash::hash(data).unwrap();
        assert_eq!(sha512_output.as_slice(), sha512_vec.as_slice());

        // Test BLAKE3 hash_into
        let mut blake3_output = [0u8; 32];
        Blake3Hash::hash_into(data, &mut blake3_output).unwrap();
        let blake3_vec = Blake3Hash::hash(data).unwrap();
        assert_eq!(blake3_output.as_slice(), blake3_vec.as_slice());
    }

    #[test]
    fn test_streaming_hasher() {
        let data = b"Hello, World!";

        // Test SHA-256 streaming
        let mut sha256_stream = StreamingHasher::new_sha256();
        sha256_stream.update(data);
        let sha256_stream_result = sha256_stream.finalize();
        let sha256_direct = Sha256Hash::hash(data).unwrap();
        assert_eq!(sha256_stream_result, sha256_direct);

        // Test SHA-512 streaming
        let mut sha512_stream = StreamingHasher::new_sha512();
        sha512_stream.update(data);
        let sha512_stream_result = sha512_stream.finalize();
        let sha512_direct = Sha512Hash::hash(data).unwrap();
        assert_eq!(sha512_stream_result, sha512_direct);

        // Test BLAKE3 streaming
        let mut blake3_stream = StreamingHasher::new_blake3();
        blake3_stream.update(data);
        let blake3_stream_result = blake3_stream.finalize();
        let blake3_direct = Blake3Hash::hash(data).unwrap();
        assert_eq!(blake3_stream_result, blake3_direct);
    }

    #[test]
    fn test_streaming_hasher_chunked() {
        let data = b"Hello, World! This is a longer message for testing chunked processing.";
        let chunk_size = 8;

        // Test SHA-256 chunked streaming
        let mut sha256_stream = StreamingHasher::new_sha256();
        for chunk in data.chunks(chunk_size) {
            sha256_stream.update(chunk);
        }
        let sha256_stream_result = sha256_stream.finalize();
        let sha256_direct = Sha256Hash::hash(data).unwrap();
        assert_eq!(sha256_stream_result, sha256_direct);

        // Test BLAKE3 chunked streaming
        let mut blake3_stream = StreamingHasher::new_blake3();
        for chunk in data.chunks(chunk_size) {
            blake3_stream.update(chunk);
        }
        let blake3_stream_result = blake3_stream.finalize();
        let blake3_direct = Blake3Hash::hash(data).unwrap();
        assert_eq!(blake3_stream_result, blake3_direct);
    }
}
