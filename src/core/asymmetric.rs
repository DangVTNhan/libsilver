use crate::error::{CryptoError, CryptoResult, RSA_KEY_SIZE_TOO_SMALL, RSA_KEY_GENERATION_FAILED, RSA_ENCRYPTION_FAILED, RSA_DECRYPTION_FAILED, PRIVATE_KEY_ENCODING_FAILED, PUBLIC_KEY_ENCODING_FAILED, PRIVATE_KEY_DECODING_FAILED, PUBLIC_KEY_DECODING_FAILED, INVALID_ECDSA_PRIVATE_KEY, INVALID_ECDSA_PUBLIC_KEY, INVALID_SIGNATURE_FORMAT, ED25519_PRIVATE_KEY_INVALID_SIZE, ED25519_PUBLIC_KEY_INVALID_SIZE, ED25519_SIGNATURE_INVALID_SIZE, INVALID_ED25519_PUBLIC_KEY};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey}};
use rsa::sha2::Sha256;
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};

use rand::rngs::OsRng;

/// RSA key pair
#[derive(Clone)]
pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair with specified bit size
    pub fn generate(bits: usize) -> CryptoResult<Self> {
        if bits < 2048 {
            return Err(CryptoError::InvalidInput(RSA_KEY_SIZE_TOO_SMALL));
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|_| CryptoError::KeyGenerationFailed(RSA_KEY_GENERATION_FAILED))?;

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the public key
    #[inline]
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    /// Get the private key
    #[inline]
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Export private key as PEM
    pub fn private_key_pem(&self) -> CryptoResult<String> {
        self.private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| CryptoError::EncodingFailed(PRIVATE_KEY_ENCODING_FAILED))
            .map(|pem| pem.to_string())
    }

    /// Export public key as PEM
    pub fn public_key_pem(&self) -> CryptoResult<String> {
        self.public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|_| CryptoError::EncodingFailed(PUBLIC_KEY_ENCODING_FAILED))
    }

    /// Import private key from PEM
    pub fn from_private_key_pem(pem: &str) -> CryptoResult<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|_| CryptoError::InvalidKey(PRIVATE_KEY_DECODING_FAILED))?;

        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Import public key from PEM
    pub fn from_public_key_pem(pem: &str) -> CryptoResult<RsaPublicKey> {
        RsaPublicKey::from_public_key_pem(pem)
            .map_err(|_| CryptoError::InvalidKey(PUBLIC_KEY_DECODING_FAILED))
    }
}

/// RSA encryption and decryption
pub struct RsaCrypto;

impl RsaCrypto {
    /// Generate a new RSA-2048 key pair
    #[inline]
    pub fn generate_keypair() -> CryptoResult<RsaKeyPair> {
        RsaKeyPair::generate(2048)
    }

    /// Generate a new RSA key pair with custom bit size
    #[inline]
    pub fn generate_keypair_with_size(bits: usize) -> CryptoResult<RsaKeyPair> {
        RsaKeyPair::generate(bits)
    }

    /// Encrypt data using RSA-OAEP
    pub fn encrypt(plaintext: &[u8], public_key: &RsaPublicKey) -> CryptoResult<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();

        public_key.encrypt(&mut OsRng, padding, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed(RSA_ENCRYPTION_FAILED))
    }

    /// Decrypt data using RSA-OAEP
    pub fn decrypt(ciphertext: &[u8], private_key: &RsaPrivateKey) -> CryptoResult<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();

        private_key.decrypt(padding, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed(RSA_DECRYPTION_FAILED))
    }
}

/// ECDSA P-256 key pair
#[derive(Clone)]
pub struct EcdsaKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl EcdsaKeyPair {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate() -> CryptoResult<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the verifying key (public key)
    #[inline]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the signing key (private key)
    #[inline]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Export private key bytes
    #[inline]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Export public key bytes
    #[inline]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Import from private key bytes
    pub fn from_private_key_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidKey(INVALID_ECDSA_PRIVATE_KEY))?;

        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Import verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> CryptoResult<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKey(INVALID_ECDSA_PUBLIC_KEY))
    }
}

/// ECDSA P-256 digital signatures
pub struct EcdsaCrypto;

impl EcdsaCrypto {
    /// Generate a new ECDSA P-256 key pair
    #[inline]
    pub fn generate_keypair() -> CryptoResult<EcdsaKeyPair> {
        EcdsaKeyPair::generate()
    }

    /// Sign data using ECDSA P-256
    pub fn sign(message: &[u8], signing_key: &SigningKey) -> CryptoResult<Vec<u8>> {
        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify ECDSA P-256 signature
    pub fn verify(message: &[u8], signature: &[u8], verifying_key: &VerifyingKey) -> CryptoResult<bool> {
        let signature = Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidInput(INVALID_SIGNATURE_FORMAT))?;

        match verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Ed25519 key pair
#[derive(Clone)]
pub struct Ed25519KeyPair {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> CryptoResult<Self> {
        use rand::RngCore;
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);

        let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the verifying key (public key)
    #[inline]
    pub fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    /// Get the signing key (private key)
    #[inline]
    pub fn signing_key(&self) -> &Ed25519SigningKey {
        &self.signing_key
    }

    /// Export private key bytes
    #[inline]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Export public key bytes
    #[inline]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Import from private key bytes
    pub fn from_private_key_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(ED25519_PRIVATE_KEY_INVALID_SIZE));
        }

        let signing_key = Ed25519SigningKey::from_bytes(bytes.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Import verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> CryptoResult<Ed25519VerifyingKey> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(ED25519_PUBLIC_KEY_INVALID_SIZE));
        }

        Ed25519VerifyingKey::from_bytes(bytes.try_into().unwrap())
            .map_err(|_| CryptoError::InvalidKey(INVALID_ED25519_PUBLIC_KEY))
    }
}

/// Ed25519 digital signatures
pub struct Ed25519Crypto;

impl Ed25519Crypto {
    /// Generate a new Ed25519 key pair
    #[inline]
    pub fn generate_keypair() -> CryptoResult<Ed25519KeyPair> {
        Ed25519KeyPair::generate()
    }

    /// Sign data using Ed25519
    pub fn sign(message: &[u8], signing_key: &Ed25519SigningKey) -> CryptoResult<Vec<u8>> {
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify Ed25519 signature
    pub fn verify(message: &[u8], signature: &[u8], verifying_key: &Ed25519VerifyingKey) -> CryptoResult<bool> {
        if signature.len() != 64 {
            return Err(CryptoError::InvalidInput(ED25519_SIGNATURE_INVALID_SIZE));
        }

        let signature = Ed25519Signature::from_bytes(signature.try_into().unwrap());

        match verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}





#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_rsa_key_generation() {
        let keypair = RsaCrypto::generate_keypair().unwrap();

        // Test key export/import
        let private_pem = keypair.private_key_pem().unwrap();
        let public_pem = keypair.public_key_pem().unwrap();

        assert!(private_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(public_pem.contains("-----BEGIN PUBLIC KEY-----"));

        // Test import
        let imported_keypair = RsaKeyPair::from_private_key_pem(&private_pem).unwrap();
        let imported_public = RsaKeyPair::from_public_key_pem(&public_pem).unwrap();

        // Keys should be equivalent
        assert_eq!(keypair.public_key().n(), imported_keypair.public_key().n());
        assert_eq!(keypair.public_key().n(), imported_public.n());
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let keypair = RsaCrypto::generate_keypair().unwrap();
        let plaintext = b"Hello, RSA encryption!";

        let ciphertext = RsaCrypto::encrypt(plaintext, keypair.public_key()).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = RsaCrypto::decrypt(&ciphertext, keypair.private_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_invalid_key_size() {
        let result = RsaKeyPair::generate(1024); // Too small
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_key_generation() {
        let keypair = EcdsaCrypto::generate_keypair().unwrap();

        let private_bytes = keypair.private_key_bytes();
        let public_bytes = keypair.public_key_bytes();

        assert_eq!(private_bytes.len(), 32); // P-256 private key is 32 bytes
        assert_eq!(public_bytes.len(), 65); // Uncompressed public key is 65 bytes

        // Test import
        let imported_keypair = EcdsaKeyPair::from_private_key_bytes(&private_bytes).unwrap();
        let imported_public = EcdsaKeyPair::verifying_key_from_bytes(&public_bytes).unwrap();

        assert_eq!(keypair.public_key_bytes(), imported_keypair.public_key_bytes());
        assert_eq!(keypair.verifying_key().to_encoded_point(false), imported_public.to_encoded_point(false));
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let keypair = EcdsaCrypto::generate_keypair().unwrap();
        let message = b"Hello, ECDSA signatures!";

        let signature = EcdsaCrypto::sign(message, keypair.signing_key()).unwrap();
        assert_eq!(signature.len(), 64); // ECDSA signature is 64 bytes

        let is_valid = EcdsaCrypto::verify(message, &signature, keypair.verifying_key()).unwrap();
        assert!(is_valid);

        // Test with wrong message
        let is_valid = EcdsaCrypto::verify(b"Wrong message", &signature, keypair.verifying_key()).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_ed25519_key_generation() {
        let keypair = Ed25519Crypto::generate_keypair().unwrap();

        let private_bytes = keypair.private_key_bytes();
        let public_bytes = keypair.public_key_bytes();

        assert_eq!(private_bytes.len(), 32); // Ed25519 private key is 32 bytes
        assert_eq!(public_bytes.len(), 32); // Ed25519 public key is 32 bytes

        // Test import
        let imported_keypair = Ed25519KeyPair::from_private_key_bytes(&private_bytes).unwrap();
        let imported_public = Ed25519KeyPair::verifying_key_from_bytes(&public_bytes).unwrap();

        assert_eq!(keypair.public_key_bytes(), imported_keypair.public_key_bytes());
        assert_eq!(keypair.verifying_key().to_bytes(), imported_public.to_bytes());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let keypair = Ed25519Crypto::generate_keypair().unwrap();
        let message = b"Hello, Ed25519 signatures!";

        let signature = Ed25519Crypto::sign(message, keypair.signing_key()).unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

        let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key()).unwrap();
        assert!(is_valid);

        // Test with wrong message
        let is_valid = Ed25519Crypto::verify(b"Wrong message", &signature, keypair.verifying_key()).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_ed25519_invalid_key_size() {
        let short_key = vec![0u8; 16]; // Too short
        let result = Ed25519KeyPair::from_private_key_bytes(&short_key);
        assert!(result.is_err());

        let result = Ed25519KeyPair::verifying_key_from_bytes(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_invalid_signature_size() {
        let keypair = Ed25519Crypto::generate_keypair().unwrap();
        let message = b"Hello, Ed25519!";
        let short_signature = vec![0u8; 32]; // Too short

        let result = Ed25519Crypto::verify(message, &short_signature, keypair.verifying_key());
        assert!(result.is_err());
    }


}