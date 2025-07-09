use thiserror::Error;

/// Unified error type for all cryptographic operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),
    
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Hash operation failed: {0}")]
    HashFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Random number generation failed: {0}")]
    RandomGenerationFailed(String),
    
    #[error("Encoding/Decoding failed: {0}")]
    EncodingFailed(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

impl From<aes_gcm::Error> for CryptoError {
    fn from(err: aes_gcm::Error) -> Self {
        CryptoError::EncryptionFailed(format!("AES-GCM error: {:?}", err))
    }
}

impl From<rsa::Error> for CryptoError {
    fn from(err: rsa::Error) -> Self {
        CryptoError::EncryptionFailed(format!("RSA error: {:?}", err))
    }
}

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::SignatureFailed(format!("Ed25519 error: {:?}", err))
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        CryptoError::KeyDerivationFailed(format!("Argon2 error: {:?}", err))
    }
}

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(err: hkdf::InvalidLength) -> Self {
        CryptoError::KeyDerivationFailed(format!("HKDF error: {:?}", err))
    }
}

// Note: PBKDF2 doesn't expose InvalidLength in current version, so we handle errors manually

impl From<getrandom::Error> for CryptoError {
    fn from(err: getrandom::Error) -> Self {
        CryptoError::RandomGenerationFailed(format!("Random generation error: {:?}", err))
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(err: hex::FromHexError) -> Self {
        CryptoError::EncodingFailed(format!("Hex decoding error: {:?}", err))
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::EncodingFailed(format!("Base64 decoding error: {:?}", err))
    }
}
