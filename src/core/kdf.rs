use crate::error::{CryptoError, CryptoResult};
use crate::core::random::SecureRandom;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};


/// Argon2 password hashing and verification
pub struct Argon2Kdf;

impl Argon2Kdf {
    /// Hash a password using Argon2id with default parameters
    pub fn hash_password(password: &[u8]) -> CryptoResult<String> {
        let salt = SecureRandom::generate_salt()?;
        Self::hash_password_with_salt(password, &salt)
    }

    /// Hash a password using Argon2id with provided salt
    pub fn hash_password_with_salt(password: &[u8], salt: &[u8]) -> CryptoResult<String> {
        use argon2::password_hash::{SaltString, PasswordHasher};

        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("Salt encoding failed: {}", e)))?;

        let password_hash = argon2.hash_password(password, &salt_string)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("Argon2 hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against an Argon2 hash
    pub fn verify_password(password: &[u8], hash: &str) -> CryptoResult<bool> {
        let argon2 = Argon2::default();

        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid hash format: {}", e)))?;

        match argon2.verify_password(password, &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Derive a key from password using Argon2
    pub fn derive_key(password: &[u8], salt: &[u8], output_length: usize) -> CryptoResult<Vec<u8>> {
        if output_length == 0 {
            return Err(CryptoError::InvalidInput("Output length cannot be zero".to_string()));
        }

        let mut output = vec![0u8; output_length];

        argon2::Argon2::default()
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("Argon2 key derivation failed: {}", e)))?;

        Ok(output)
    }
}

/// HKDF (HMAC-based Key Derivation Function)
pub struct HkdfKdf;

impl HkdfKdf {
    /// Derive key using HKDF-SHA256
    pub fn derive_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput("Output length cannot be zero".to_string()));
        }

        let hk = Hkdf::<Sha256>::new(salt, ikm);
        let mut okm = vec![0u8; length];

        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("HKDF-SHA256 failed: {:?}", e)))?;

        Ok(okm)
    }

    /// Derive key using HKDF-SHA512
    pub fn derive_sha512(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput("Output length cannot be zero".to_string()));
        }

        let hk = Hkdf::<Sha512>::new(salt, ikm);
        let mut okm = vec![0u8; length];

        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("HKDF-SHA512 failed: {:?}", e)))?;

        Ok(okm)
    }
}

/// PBKDF2 (Password-Based Key Derivation Function 2)
pub struct Pbkdf2Kdf;

impl Pbkdf2Kdf {
    /// Derive key using PBKDF2-HMAC-SHA256
    pub fn derive_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput("Output length cannot be zero".to_string()));
        }

        if iterations == 0 {
            return Err(CryptoError::InvalidInput("Iterations cannot be zero".to_string()));
        }

        let mut output = vec![0u8; length];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

        Ok(output)
    }

    /// Derive key using PBKDF2-HMAC-SHA512
    pub fn derive_sha512(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInput("Output length cannot be zero".to_string()));
        }

        if iterations == 0 {
            return Err(CryptoError::InvalidInput("Iterations cannot be zero".to_string()));
        }

        let mut output = vec![0u8; length];
        pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output);

        Ok(output)
    }
}



/// Secure key derivation with automatic salt generation
pub struct SecureKeyDerivation;

impl SecureKeyDerivation {
    /// Derive a key using Argon2 with random salt
    pub fn derive_argon2(password: &[u8], output_length: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let salt = SecureRandom::generate_salt()?;
        let key = Argon2Kdf::derive_key(password, &salt, output_length)?;
        Ok((key, salt))
    }

    /// Derive a key using PBKDF2-SHA256 with random salt and recommended iterations
    pub fn derive_pbkdf2_sha256(password: &[u8], output_length: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let salt = SecureRandom::generate_salt()?;
        let iterations = 100_000; // OWASP recommended minimum
        let key = Pbkdf2Kdf::derive_sha256(password, &salt, iterations, output_length)?;
        Ok((key, salt))
    }

    /// Derive a key using HKDF-SHA256 with random salt
    pub fn derive_hkdf_sha256(ikm: &[u8], info: &[u8], output_length: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        let salt = SecureRandom::generate_salt()?;
        let key = HkdfKdf::derive_sha256(ikm, Some(&salt), info, output_length)?;
        Ok((key, salt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_hash_password() {
        let password = b"test_password";
        let hash = Argon2Kdf::hash_password(password).unwrap();

        // Argon2 hash should start with $argon2id$
        assert!(hash.starts_with("$argon2id$"));

        // Verify the password
        assert!(Argon2Kdf::verify_password(password, &hash).unwrap());
        assert!(!Argon2Kdf::verify_password(b"wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_argon2_derive_key() {
        let password = b"test_password";
        let salt = b"test_salt_32_bytes_long_for_test";
        let key_length = 32;

        let key = Argon2Kdf::derive_key(password, salt, key_length).unwrap();
        assert_eq!(key.len(), key_length);

        // Same inputs should produce same key
        let key2 = Argon2Kdf::derive_key(password, salt, key_length).unwrap();
        assert_eq!(key, key2);

        // Different password should produce different key
        let key3 = Argon2Kdf::derive_key(b"different_password", salt, key_length).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_argon2_zero_length() {
        let password = b"test_password";
        let salt = b"test_salt_32_bytes_long_for_test";

        let result = Argon2Kdf::derive_key(password, salt, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        let info = b"application_info";
        let length = 32;

        let key = HkdfKdf::derive_sha256(ikm, Some(salt), info, length).unwrap();
        assert_eq!(key.len(), length);

        // Same inputs should produce same key
        let key2 = HkdfKdf::derive_sha256(ikm, Some(salt), info, length).unwrap();
        assert_eq!(key, key2);

        // Different info should produce different key
        let key3 = HkdfKdf::derive_sha256(ikm, Some(salt), b"different_info", length).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_hkdf_sha256_no_salt() {
        let ikm = b"input_key_material";
        let info = b"application_info";
        let length = 32;

        let key = HkdfKdf::derive_sha256(ikm, None, info, length).unwrap();
        assert_eq!(key.len(), length);
    }

    #[test]
    fn test_hkdf_sha512() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        let info = b"application_info";
        let length = 64;

        let key = HkdfKdf::derive_sha512(ikm, Some(salt), info, length).unwrap();
        assert_eq!(key.len(), length);
    }

    #[test]
    fn test_pbkdf2_sha256() {
        let password = b"test_password";
        let salt = b"test_salt";
        let iterations = 1000;
        let length = 32;

        let key = Pbkdf2Kdf::derive_sha256(password, salt, iterations, length).unwrap();
        assert_eq!(key.len(), length);

        // Same inputs should produce same key
        let key2 = Pbkdf2Kdf::derive_sha256(password, salt, iterations, length).unwrap();
        assert_eq!(key, key2);

        // Different iterations should produce different key
        let key3 = Pbkdf2Kdf::derive_sha256(password, salt, iterations + 1, length).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_pbkdf2_sha512() {
        let password = b"test_password";
        let salt = b"test_salt";
        let iterations = 1000;
        let length = 64;

        let key = Pbkdf2Kdf::derive_sha512(password, salt, iterations, length).unwrap();
        assert_eq!(key.len(), length);
    }

    #[test]
    fn test_pbkdf2_zero_iterations() {
        let password = b"test_password";
        let salt = b"test_salt";
        let length = 32;

        let result = Pbkdf2Kdf::derive_sha256(password, salt, 0, length);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_key_derivation_argon2() {
        let password = b"test_password";
        let length = 32;

        let (key, salt) = SecureKeyDerivation::derive_argon2(password, length).unwrap();
        assert_eq!(key.len(), length);
        assert_eq!(salt.len(), 32); // Default salt length

        // Different calls should produce different salts and keys
        let (key2, salt2) = SecureKeyDerivation::derive_argon2(password, length).unwrap();
        assert_ne!(salt, salt2);
        assert_ne!(key, key2);
    }

    #[test]
    fn test_secure_key_derivation_pbkdf2() {
        let password = b"test_password";
        let length = 32;

        let (key, salt) = SecureKeyDerivation::derive_pbkdf2_sha256(password, length).unwrap();
        assert_eq!(key.len(), length);
        assert_eq!(salt.len(), 32);
    }

    #[test]
    fn test_secure_key_derivation_hkdf() {
        let ikm = b"input_key_material";
        let info = b"application_info";
        let length = 32;

        let (key, salt) = SecureKeyDerivation::derive_hkdf_sha256(ikm, info, length).unwrap();
        assert_eq!(key.len(), length);
        assert_eq!(salt.len(), 32);
    }
}