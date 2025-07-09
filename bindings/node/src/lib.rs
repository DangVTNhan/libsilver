use napi::bindgen_prelude::*;
use napi_derive::napi;
use libsilver::core::*;
use libsilver::error::CryptoError;

/// Convert CryptoError to napi::Error
fn crypto_error_to_napi(err: CryptoError) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, err.to_string())
}

/// Helper macro to convert Result<T, CryptoError> to napi::Result<T>
macro_rules! to_napi_result {
    ($expr:expr) => {
        $expr.map_err(crypto_error_to_napi)
    };
}

/// Symmetric Encryption Module
#[napi]
pub struct SymmetricCrypto;

#[napi]
impl SymmetricCrypto {
    /// Generate AES-256 key
    #[napi]
    pub fn generate_aes_key() -> napi::Result<Buffer> {
        let key = to_napi_result!(AesGcm::generate_key())?;
        Ok(Buffer::from(key))
    }

    /// Encrypt data using AES-256-GCM
    #[napi]
    pub fn encrypt_aes(plaintext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AesGcm::encrypt(&plaintext, &key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using AES-256-GCM
    #[napi]
    pub fn decrypt_aes(ciphertext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(AesGcm::decrypt(&ciphertext, &key))?;
        Ok(Buffer::from(plaintext))
    }

    /// Generate ChaCha20-Poly1305 key
    #[napi]
    pub fn generate_chacha20_key() -> napi::Result<Buffer> {
        let key = to_napi_result!(ChaCha20Poly1305Cipher::generate_key())?;
        Ok(Buffer::from(key))
    }

    /// Encrypt data using ChaCha20-Poly1305
    #[napi]
    pub fn encrypt_chacha20(plaintext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(ChaCha20Poly1305Cipher::encrypt(&plaintext, &key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using ChaCha20-Poly1305
    #[napi]
    pub fn decrypt_chacha20(ciphertext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(ChaCha20Poly1305Cipher::decrypt(&ciphertext, &key))?;
        Ok(Buffer::from(plaintext))
    }
}

/// Asymmetric Encryption Module
#[napi]
pub struct AsymmetricCrypto;

#[napi]
impl AsymmetricCrypto {
    /// Generate RSA-2048 key pair
    #[napi]
    pub fn generate_rsa_keypair() -> napi::Result<RsaKeyPairJs> {
        let keypair = to_napi_result!(RsaCrypto::generate_keypair())?;
        Ok(RsaKeyPairJs::from(keypair))
    }

    /// Generate RSA key pair with custom bit size
    #[napi]
    pub fn generate_rsa_keypair_with_size(bits: u32) -> napi::Result<RsaKeyPairJs> {
        let keypair = to_napi_result!(RsaCrypto::generate_keypair_with_size(bits as usize))?;
        Ok(RsaKeyPairJs::from(keypair))
    }

    /// Encrypt data using RSA-OAEP
    #[napi]
    pub fn encrypt_rsa(plaintext: Buffer, public_key_pem: String) -> napi::Result<Buffer> {
        let public_key = to_napi_result!(RsaKeyPair::from_public_key_pem(&public_key_pem))?;
        let ciphertext = to_napi_result!(RsaCrypto::encrypt(&plaintext, &public_key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using RSA-OAEP
    #[napi]
    pub fn decrypt_rsa(ciphertext: Buffer, private_key_pem: String) -> napi::Result<Buffer> {
        let keypair = to_napi_result!(RsaKeyPair::from_private_key_pem(&private_key_pem))?;
        let plaintext = to_napi_result!(RsaCrypto::decrypt(&ciphertext, keypair.private_key()))?;
        Ok(Buffer::from(plaintext))
    }

    /// Generate Ed25519 key pair
    #[napi]
    pub fn generate_ed25519_keypair() -> napi::Result<Ed25519KeyPairJs> {
        let keypair = to_napi_result!(Ed25519Crypto::generate_keypair())?;
        Ok(Ed25519KeyPairJs::from(keypair))
    }

    /// Sign data using Ed25519
    #[napi]
    pub fn sign_ed25519(message: Buffer, signing_key_bytes: Buffer) -> napi::Result<Buffer> {
        let keypair = to_napi_result!(Ed25519KeyPair::from_private_key_bytes(&signing_key_bytes))?;
        let signature = to_napi_result!(Ed25519Crypto::sign(&message, keypair.signing_key()))?;
        Ok(Buffer::from(signature))
    }

    /// Verify Ed25519 signature
    #[napi]
    pub fn verify_ed25519(message: Buffer, signature: Buffer, verifying_key_bytes: Buffer) -> napi::Result<bool> {
        let verifying_key = to_napi_result!(Ed25519KeyPair::verifying_key_from_bytes(&verifying_key_bytes))?;
        let is_valid = to_napi_result!(Ed25519Crypto::verify(&message, &signature, &verifying_key))?;
        Ok(is_valid)
    }

    /// Generate ECDSA P-256 key pair
    #[napi]
    pub fn generate_ecdsa_keypair() -> napi::Result<EcdsaKeyPairJs> {
        let keypair = to_napi_result!(EcdsaCrypto::generate_keypair())?;
        Ok(EcdsaKeyPairJs::from(keypair))
    }

    /// Sign data using ECDSA P-256
    #[napi]
    pub fn sign_ecdsa(message: Buffer, signing_key_bytes: Buffer) -> napi::Result<Buffer> {
        let keypair = to_napi_result!(EcdsaKeyPair::from_private_key_bytes(&signing_key_bytes))?;
        let signature = to_napi_result!(EcdsaCrypto::sign(&message, keypair.signing_key()))?;
        Ok(Buffer::from(signature))
    }

    /// Verify ECDSA P-256 signature
    #[napi]
    pub fn verify_ecdsa(message: Buffer, signature: Buffer, verifying_key_bytes: Buffer) -> napi::Result<bool> {
        let verifying_key = to_napi_result!(EcdsaKeyPair::verifying_key_from_bytes(&verifying_key_bytes))?;
        let is_valid = to_napi_result!(EcdsaCrypto::verify(&message, &signature, &verifying_key))?;
        Ok(is_valid)
    }
}

/// Hash Functions Module
#[napi]
pub struct HashFunctions;

#[napi]
impl HashFunctions {
    /// Compute SHA-256 hash
    #[napi]
    pub fn sha256(data: Buffer) -> napi::Result<Buffer> {
        let hash = to_napi_result!(Sha256Hash::hash(&data))?;
        Ok(Buffer::from(hash))
    }

    /// Compute SHA-256 hash and return as hex string
    #[napi]
    pub fn sha256_hex(data: Buffer) -> napi::Result<String> {
        let hex = to_napi_result!(Sha256Hash::hash_hex(&data))?;
        Ok(hex)
    }

    /// Compute SHA-512 hash
    #[napi]
    pub fn sha512(data: Buffer) -> napi::Result<Buffer> {
        let hash = to_napi_result!(Sha512Hash::hash(&data))?;
        Ok(Buffer::from(hash))
    }

    /// Compute SHA-512 hash and return as hex string
    #[napi]
    pub fn sha512_hex(data: Buffer) -> napi::Result<String> {
        let hex = to_napi_result!(Sha512Hash::hash_hex(&data))?;
        Ok(hex)
    }

    /// Compute BLAKE3 hash
    #[napi]
    pub fn blake3(data: Buffer) -> napi::Result<Buffer> {
        let hash = to_napi_result!(Blake3Hash::hash(&data))?;
        Ok(Buffer::from(hash))
    }

    /// Compute BLAKE3 hash and return as hex string
    #[napi]
    pub fn blake3_hex(data: Buffer) -> napi::Result<String> {
        let hex = to_napi_result!(Blake3Hash::hash_hex(&data))?;
        Ok(hex)
    }

    /// Compute BLAKE3 hash with custom length
    #[napi]
    pub fn blake3_with_length(data: Buffer, length: u32) -> napi::Result<Buffer> {
        let hash = to_napi_result!(Blake3Hash::hash_with_length(&data, length as usize))?;
        Ok(Buffer::from(hash))
    }

    /// Compute HMAC-SHA256
    #[napi]
    pub fn hmac_sha256(key: Buffer, message: Buffer) -> napi::Result<Buffer> {
        let mac = to_napi_result!(Hmac::sha256(&key, &message))?;
        Ok(Buffer::from(mac))
    }

    /// Verify HMAC-SHA256
    #[napi]
    pub fn verify_hmac_sha256(key: Buffer, message: Buffer, expected_mac: Buffer) -> napi::Result<bool> {
        let is_valid = to_napi_result!(Hmac::verify_sha256(&key, &message, &expected_mac))?;
        Ok(is_valid)
    }

    /// Compute HMAC-SHA512
    #[napi]
    pub fn hmac_sha512(key: Buffer, message: Buffer) -> napi::Result<Buffer> {
        let mac = to_napi_result!(Hmac::sha512(&key, &message))?;
        Ok(Buffer::from(mac))
    }

    /// Verify HMAC-SHA512
    #[napi]
    pub fn verify_hmac_sha512(key: Buffer, message: Buffer, expected_mac: Buffer) -> napi::Result<bool> {
        let is_valid = to_napi_result!(Hmac::verify_sha512(&key, &message, &expected_mac))?;
        Ok(is_valid)
    }
}

/// Key Derivation Functions Module
#[napi]
pub struct KeyDerivation;

#[napi]
impl KeyDerivation {
    /// Derive key using Argon2
    #[napi]
    pub fn argon2(password: Buffer, salt: Buffer, length: u32) -> napi::Result<Buffer> {
        let key = to_napi_result!(Argon2Kdf::derive_key(&password, &salt, length as usize))?;
        Ok(Buffer::from(key))
    }

    /// Derive key using PBKDF2-SHA256
    #[napi]
    pub fn pbkdf2_sha256(password: Buffer, salt: Buffer, iterations: u32, length: u32) -> napi::Result<Buffer> {
        let key = to_napi_result!(Pbkdf2Kdf::derive_sha256(&password, &salt, iterations, length as usize))?;
        Ok(Buffer::from(key))
    }

    /// Derive key using PBKDF2-SHA512
    #[napi]
    pub fn pbkdf2_sha512(password: Buffer, salt: Buffer, iterations: u32, length: u32) -> napi::Result<Buffer> {
        let key = to_napi_result!(Pbkdf2Kdf::derive_sha512(&password, &salt, iterations, length as usize))?;
        Ok(Buffer::from(key))
    }

    /// Derive key using HKDF-SHA256
    #[napi]
    pub fn hkdf_sha256(input_key: Buffer, salt: Option<Buffer>, info: Option<Buffer>, length: u32) -> napi::Result<Buffer> {
        let salt_ref = salt.as_ref().map(|s| s.as_ref());
        let info_bytes = info.as_ref().map(|i| i.as_ref()).unwrap_or(&[]);
        let key = to_napi_result!(HkdfKdf::derive_sha256(&input_key, salt_ref, info_bytes, length as usize))?;
        Ok(Buffer::from(key))
    }

    /// Derive key using HKDF-SHA512
    #[napi]
    pub fn hkdf_sha512(input_key: Buffer, salt: Option<Buffer>, info: Option<Buffer>, length: u32) -> napi::Result<Buffer> {
        let salt_ref = salt.as_ref().map(|s| s.as_ref());
        let info_bytes = info.as_ref().map(|i| i.as_ref()).unwrap_or(&[]);
        let key = to_napi_result!(HkdfKdf::derive_sha512(&input_key, salt_ref, info_bytes, length as usize))?;
        Ok(Buffer::from(key))
    }
}

/// Random Generation Module
#[napi]
pub struct RandomGenerator;

#[napi]
impl RandomGenerator {
    /// Generate secure random bytes
    #[napi]
    pub fn generate_bytes(length: u32) -> napi::Result<Buffer> {
        let bytes = to_napi_result!(SecureRandom::generate_bytes(length as usize))?;
        Ok(Buffer::from(bytes))
    }

    /// Generate secure random key
    #[napi]
    pub fn generate_key(length: u32) -> napi::Result<Buffer> {
        let key = to_napi_result!(SecureRandom::generate_key(length as usize))?;
        Ok(Buffer::from(key.as_bytes().to_vec()))
    }

    /// Generate nonce
    #[napi]
    pub fn generate_nonce(length: u32) -> napi::Result<Buffer> {
        let nonce = to_napi_result!(SecureRandom::generate_nonce(length as usize))?;
        Ok(Buffer::from(nonce))
    }

    /// Generate salt
    #[napi]
    pub fn generate_salt() -> napi::Result<Buffer> {
        let salt = to_napi_result!(SecureRandom::generate_salt())?;
        Ok(Buffer::from(salt))
    }
}

/// RSA Key Pair for JavaScript
#[napi(object)]
pub struct RsaKeyPairJs {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

impl From<RsaKeyPair> for RsaKeyPairJs {
    fn from(keypair: RsaKeyPair) -> Self {
        Self {
            public_key_pem: keypair.public_key_pem().unwrap_or_default(),
            private_key_pem: keypair.private_key_pem().unwrap_or_default(),
        }
    }
}

/// Ed25519 Key Pair for JavaScript
#[napi(object)]
pub struct Ed25519KeyPairJs {
    pub signing_key_bytes: Buffer,
    pub verifying_key_bytes: Buffer,
}

impl From<Ed25519KeyPair> for Ed25519KeyPairJs {
    fn from(keypair: Ed25519KeyPair) -> Self {
        Self {
            signing_key_bytes: Buffer::from(keypair.private_key_bytes()),
            verifying_key_bytes: Buffer::from(keypair.public_key_bytes()),
        }
    }
}

/// ECDSA Key Pair for JavaScript
#[napi(object)]
pub struct EcdsaKeyPairJs {
    pub signing_key_bytes: Buffer,
    pub verifying_key_bytes: Buffer,
}

impl From<EcdsaKeyPair> for EcdsaKeyPairJs {
    fn from(keypair: EcdsaKeyPair) -> Self {
        Self {
            signing_key_bytes: Buffer::from(keypair.private_key_bytes()),
            verifying_key_bytes: Buffer::from(keypair.public_key_bytes()),
        }
    }
}
