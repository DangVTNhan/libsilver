use thiserror::Error;

// Static error messages to avoid allocations
pub const INVALID_KEY_LENGTH_AES: &str = "AES-256 key must be 32 bytes";
pub const INVALID_KEY_LENGTH_CHACHA: &str = "ChaCha20 key must be 32 bytes";
pub const INVALID_NONCE_LENGTH: &str = "Nonce must be 12 bytes";
pub const CIPHERTEXT_TOO_SHORT: &str = "Ciphertext too short";
pub const ZERO_LENGTH_INPUT: &str = "Length cannot be zero";
pub const ZERO_OUTPUT_LENGTH: &str = "Output length cannot be zero";
pub const ZERO_ITERATIONS: &str = "Iterations cannot be zero";
pub const HASH_LENGTH_ZERO: &str = "Hash length cannot be zero";
pub const AES_GCM_ENCRYPTION_FAILED: &str = "AES-GCM encryption failed";
pub const AES_GCM_DECRYPTION_FAILED: &str = "AES-GCM decryption failed";
pub const CHACHA20_ENCRYPTION_FAILED: &str = "ChaCha20-Poly1305 encryption failed";
pub const CHACHA20_DECRYPTION_FAILED: &str = "ChaCha20-Poly1305 decryption failed";
pub const INVALID_HMAC_KEY: &str = "Invalid HMAC key";
pub const ARGON2_DERIVATION_FAILED: &str = "Argon2 key derivation failed";
pub const HKDF_SHA256_FAILED: &str = "HKDF-SHA256 failed";
pub const HKDF_SHA512_FAILED: &str = "HKDF-SHA512 failed";
pub const RANDOM_GENERATION_FAILED: &str = "Failed to generate random bytes";
pub const RSA_KEY_SIZE_TOO_SMALL: &str = "RSA key size must be at least 2048 bits";
pub const RSA_KEY_GENERATION_FAILED: &str = "RSA key generation failed";
pub const RSA_ENCRYPTION_FAILED: &str = "RSA encryption failed";
pub const RSA_DECRYPTION_FAILED: &str = "RSA decryption failed";
pub const PRIVATE_KEY_ENCODING_FAILED: &str = "Failed to encode private key";
pub const PUBLIC_KEY_ENCODING_FAILED: &str = "Failed to encode public key";
pub const PRIVATE_KEY_DECODING_FAILED: &str = "Failed to decode private key";
pub const PUBLIC_KEY_DECODING_FAILED: &str = "Failed to decode public key";
pub const INVALID_ECDSA_PRIVATE_KEY: &str = "Invalid ECDSA private key";
pub const INVALID_ECDSA_PUBLIC_KEY: &str = "Invalid ECDSA public key";
pub const INVALID_SIGNATURE_FORMAT: &str = "Invalid signature format";
pub const ED25519_PRIVATE_KEY_INVALID_SIZE: &str = "Ed25519 private key must be 32 bytes";
pub const ED25519_PUBLIC_KEY_INVALID_SIZE: &str = "Ed25519 public key must be 32 bytes";
pub const ED25519_SIGNATURE_INVALID_SIZE: &str = "Ed25519 signature must be 64 bytes";
pub const INVALID_ED25519_PUBLIC_KEY: &str = "Invalid Ed25519 public key";
pub const SALT_ENCODING_FAILED: &str = "Salt encoding failed";
pub const ARGON2_HASHING_FAILED: &str = "Argon2 hashing failed";
pub const INVALID_HASH_FORMAT: &str = "Invalid hash format";

/// Unified error type for all cryptographic operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("Invalid key: {0}")]
    InvalidKey(&'static str),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(&'static str),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(&'static str),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(&'static str),

    #[error("Signature generation failed: {0}")]
    SignatureFailed(&'static str),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(&'static str),

    #[error("Hash operation failed: {0}")]
    HashFailed(&'static str),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(&'static str),

    #[error("Random number generation failed: {0}")]
    RandomGenerationFailed(&'static str),

    #[error("Encoding/Decoding failed: {0}")]
    EncodingFailed(&'static str),

    #[error("Internal error: {0}")]
    InternalError(&'static str),
}

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

impl From<aes_gcm::Error> for CryptoError {
    fn from(_err: aes_gcm::Error) -> Self {
        CryptoError::EncryptionFailed(AES_GCM_ENCRYPTION_FAILED)
    }
}

impl From<rsa::Error> for CryptoError {
    fn from(_err: rsa::Error) -> Self {
        CryptoError::EncryptionFailed(RSA_ENCRYPTION_FAILED)
    }
}

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(_err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::SignatureFailed("Ed25519 signature failed")
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(_err: argon2::Error) -> Self {
        CryptoError::KeyDerivationFailed(ARGON2_DERIVATION_FAILED)
    }
}

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(_err: hkdf::InvalidLength) -> Self {
        CryptoError::KeyDerivationFailed(HKDF_SHA256_FAILED)
    }
}

// Note: PBKDF2 doesn't expose InvalidLength in current version, so we handle errors manually

impl From<getrandom::Error> for CryptoError {
    fn from(_err: getrandom::Error) -> Self {
        CryptoError::RandomGenerationFailed(RANDOM_GENERATION_FAILED)
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(_err: hex::FromHexError) -> Self {
        CryptoError::EncodingFailed("Hex decoding error")
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(_err: base64::DecodeError) -> Self {
        CryptoError::EncodingFailed("Base64 decoding error")
    }
}
