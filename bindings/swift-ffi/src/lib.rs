use libsilver::prelude::*;

// UniFFI setup
uniffi::setup_scaffolding!();

// Error type for UniFFI
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CryptoError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    #[error("Cryptographic error: {message}")]
    CryptographicError { message: String },
    #[error("Key generation error: {message}")]
    KeyGenerationError { message: String },
    #[error("Encryption error: {message}")]
    EncryptionError { message: String },
    #[error("Decryption error: {message}")]
    DecryptionError { message: String },
    #[error("Signature error: {message}")]
    SignatureError { message: String },
    #[error("Verification error: {message}")]
    VerificationError { message: String },
    #[error("Hash error: {message}")]
    HashError { message: String },
    #[error("KDF error: {message}")]
    KdfError { message: String },
    #[error("Random error: {message}")]
    RandomError { message: String },
}

impl From<libsilver::error::CryptoError> for CryptoError {
    fn from(err: libsilver::error::CryptoError) -> Self {
        match err {
            libsilver::error::CryptoError::InvalidInput(msg) => CryptoError::InvalidInput {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::InvalidKey(msg) => CryptoError::InvalidInput {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::EncryptionFailed(msg) => CryptoError::EncryptionError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::DecryptionFailed(msg) => CryptoError::DecryptionError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::KeyGenerationFailed(msg) => {
                CryptoError::KeyGenerationError {
                    message: msg.to_string(),
                }
            }
            libsilver::error::CryptoError::SignatureFailed(msg) => CryptoError::SignatureError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::VerificationFailed(msg) => {
                CryptoError::VerificationError {
                    message: msg.to_string(),
                }
            }
            libsilver::error::CryptoError::HashFailed(msg) => CryptoError::HashError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::KeyDerivationFailed(msg) => CryptoError::KdfError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::RandomGenerationFailed(msg) => {
                CryptoError::RandomError {
                    message: msg.to_string(),
                }
            }
            libsilver::error::CryptoError::EncodingFailed(msg) => CryptoError::CryptographicError {
                message: msg.to_string(),
            },
            libsilver::error::CryptoError::InternalError(msg) => CryptoError::CryptographicError {
                message: msg.to_string(),
            },
        }
    }
}

// Data structures for UniFFI
#[derive(Debug, uniffi::Record)]
pub struct AesKey {
    pub key: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct Ed25519KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

// Library functions
#[uniffi::export]
pub fn initialize() {
    // Initialize any global state if needed
}

#[uniffi::export]
pub fn get_version() -> String {
    "0.1.0".to_string()
}

// Symmetric encryption functions
#[uniffi::export]
pub fn generate_aes_key() -> Result<AesKey, CryptoError> {
    let key = AwsLcAesGcm::generate_key().map_err(CryptoError::from)?;
    Ok(AesKey { key })
}

#[uniffi::export]
pub fn encrypt_aes(plaintext: Vec<u8>, key: AesKey) -> Result<EncryptionResult, CryptoError> {
    let result = AwsLcAesGcm::encrypt(&plaintext, &key.key).map_err(CryptoError::from)?;
    // Extract nonce and ciphertext from the result
    let nonce = result[..12].to_vec(); // First 12 bytes are nonce for AES-GCM
    let ciphertext = result[12..].to_vec(); // Rest is ciphertext + tag
    Ok(EncryptionResult { ciphertext, nonce })
}

#[uniffi::export]
pub fn decrypt_aes(
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key: AesKey,
) -> Result<Vec<u8>, CryptoError> {
    // Reconstruct the format expected by your library
    let mut combined = nonce;
    combined.extend_from_slice(&ciphertext);
    let plaintext = AwsLcAesGcm::decrypt(&combined, &key.key).map_err(CryptoError::from)?;
    Ok(plaintext)
}

// Ed25519 functions
#[uniffi::export]
pub fn generate_ed25519_keypair() -> Result<Ed25519KeyPair, CryptoError> {
    let keypair = Ed25519Crypto::generate_keypair().map_err(CryptoError::from)?;
    Ok(Ed25519KeyPair {
        public_key: keypair.public_key_bytes(),
        private_key: keypair.private_key_bytes(),
    })
}

#[uniffi::export]
pub fn sign_ed25519(message: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let keypair = libsilver::core::asymmetric::Ed25519KeyPair::from_private_key_bytes(&private_key)
        .map_err(CryptoError::from)?;
    let signature =
        Ed25519Crypto::sign(&message, keypair.signing_key()).map_err(CryptoError::from)?;
    Ok(signature)
}

#[uniffi::export]
pub fn verify_ed25519(
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<bool, CryptoError> {
    let verifying_key =
        libsilver::core::asymmetric::Ed25519KeyPair::verifying_key_from_bytes(&public_key)
            .map_err(CryptoError::from)?;
    let is_valid =
        Ed25519Crypto::verify(&message, &signature, &verifying_key).map_err(CryptoError::from)?;
    Ok(is_valid)
}

// Hash functions
#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let hash = Sha256Hash::hash(&data).map_err(CryptoError::from)?;
    Ok(hash)
}

#[uniffi::export]
pub fn sha256_hex(data: Vec<u8>) -> Result<String, CryptoError> {
    let hash_hex = Sha256Hash::hash_hex(&data).map_err(CryptoError::from)?;
    Ok(hash_hex)
}

// Random generation
#[uniffi::export]
pub fn generate_random_bytes(length: u32) -> Result<Vec<u8>, CryptoError> {
    let bytes = SecureRandom::generate_bytes(length as usize).map_err(CryptoError::from)?;
    Ok(bytes)
}
