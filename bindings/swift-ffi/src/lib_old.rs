use libsilver::prelude::*;
use std::sync::Arc;

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
            libsilver::error::CryptoError::InvalidInput(msg) => {
                CryptoError::InvalidInput { message: msg }
            }
            libsilver::error::CryptoError::EncryptionError(msg) => {
                CryptoError::EncryptionError { message: msg }
            }
            libsilver::error::CryptoError::DecryptionError(msg) => {
                CryptoError::DecryptionError { message: msg }
            }
            libsilver::error::CryptoError::KeyGenerationError(msg) => {
                CryptoError::KeyGenerationError { message: msg }
            }
            libsilver::error::CryptoError::SignatureError(msg) => {
                CryptoError::SignatureError { message: msg }
            }
            libsilver::error::CryptoError::VerificationError(msg) => {
                CryptoError::VerificationError { message: msg }
            }
            libsilver::error::CryptoError::HashError(msg) => {
                CryptoError::HashError { message: msg }
            }
            libsilver::error::CryptoError::KdfError(msg) => CryptoError::KdfError { message: msg },
            libsilver::error::CryptoError::RandomError(msg) => {
                CryptoError::RandomError { message: msg }
            }
            _ => CryptoError::CryptographicError {
                message: err.to_string(),
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
pub struct ChaChaKey {
    pub key: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct RsaKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct EcdsaKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct Ed25519KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct MlKemKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub level: u32,
}

#[derive(Debug, uniffi::Record)]
pub struct MlKemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

#[derive(Debug, uniffi::Record)]
pub struct MlDsaKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub level: u32,
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

// Symmetric encryption module
pub mod symmetric {
    use super::*;

    #[uniffi::export]
    pub fn generate_aes_key() -> Result<AesKey, CryptoError> {
        let key = AwsLcAesGcm::generate_key().map_err(CryptoError::from)?;
        Ok(AesKey { key })
    }

    #[uniffi::export]
    pub fn encrypt_aes(plaintext: Vec<u8>, key: AesKey) -> Result<EncryptionResult, CryptoError> {
        let result = AwsLcAesGcm::encrypt(&plaintext, &key.key).map_err(CryptoError::from)?;
        // Extract nonce and ciphertext from the result
        // Note: This assumes the result format from your library
        let nonce = result[..12].to_vec(); // First 12 bytes are nonce for AES-GCM
        let ciphertext = result[12..].to_vec(); // Rest is ciphertext + tag
        Ok(EncryptionResult { ciphertext, nonce })
    }

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

    pub fn generate_chacha_key() -> Result<ChaChaKey, CryptoError> {
        let key = ChaCha20Poly1305Cipher::generate_key().map_err(CryptoError::from)?;
        Ok(ChaChaKey { key })
    }

    pub fn encrypt_chacha(
        plaintext: Vec<u8>,
        key: ChaChaKey,
    ) -> Result<EncryptionResult, CryptoError> {
        let result =
            ChaCha20Poly1305Cipher::encrypt(&plaintext, &key.key).map_err(CryptoError::from)?;
        // Extract nonce and ciphertext from the result
        let nonce = result[..12].to_vec(); // First 12 bytes are nonce
        let ciphertext = result[12..].to_vec(); // Rest is ciphertext + tag
        Ok(EncryptionResult { ciphertext, nonce })
    }

    pub fn decrypt_chacha(
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key: ChaChaKey,
    ) -> Result<Vec<u8>, CryptoError> {
        // Reconstruct the format expected by your library
        let mut combined = nonce;
        combined.extend_from_slice(&ciphertext);
        let plaintext =
            ChaCha20Poly1305Cipher::decrypt(&combined, &key.key).map_err(CryptoError::from)?;
        Ok(plaintext)
    }
}

// Asymmetric encryption module
pub mod asymmetric {
    use super::*;

    pub fn generate_rsa_keypair() -> Result<RsaKeyPair, CryptoError> {
        let keypair = RsaCrypto::generate_keypair().map_err(CryptoError::from)?;
        Ok(RsaKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
        })
    }

    pub fn encrypt_rsa(plaintext: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        // Convert bytes to PEM format and then to RsaPublicKey
        let pem = String::from_utf8(public_key).map_err(|_| CryptoError::InvalidInput {
            message: "Invalid public key format".to_string(),
        })?;
        let public_key = RsaKeyPair::from_public_key_pem(&pem).map_err(CryptoError::from)?;
        let ciphertext = RsaCrypto::encrypt(&plaintext, &public_key).map_err(CryptoError::from)?;
        Ok(ciphertext)
    }

    pub fn decrypt_rsa(ciphertext: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        // Convert bytes to PEM format and then to RsaKeyPair
        let pem = String::from_utf8(private_key).map_err(|_| CryptoError::InvalidInput {
            message: "Invalid private key format".to_string(),
        })?;
        let keypair = RsaKeyPair::from_private_key_pem(&pem).map_err(CryptoError::from)?;
        let plaintext =
            RsaCrypto::decrypt(&ciphertext, keypair.private_key()).map_err(CryptoError::from)?;
        Ok(plaintext)
    }

    pub fn generate_ecdsa_keypair() -> Result<EcdsaKeyPair, CryptoError> {
        let keypair = EcdsaCrypto::generate_keypair().map_err(CryptoError::from)?;
        Ok(EcdsaKeyPair {
            public_key: keypair.verifying_key_bytes(),
            private_key: keypair.signing_key_bytes(),
        })
    }

    pub fn sign_ecdsa(message: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let keypair =
            EcdsaKeyPair::from_private_key_bytes(&private_key).map_err(CryptoError::from)?;
        let signature =
            EcdsaCrypto::sign(&message, keypair.signing_key()).map_err(CryptoError::from)?;
        Ok(signature)
    }

    pub fn verify_ecdsa(
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<bool, CryptoError> {
        let verifying_key =
            EcdsaKeyPair::verifying_key_from_bytes(&public_key).map_err(CryptoError::from)?;
        let is_valid =
            EcdsaCrypto::verify(&message, &signature, &verifying_key).map_err(CryptoError::from)?;
        Ok(is_valid)
    }

    pub fn generate_ed25519_keypair() -> Result<Ed25519KeyPair, CryptoError> {
        let keypair = Ed25519Crypto::generate_keypair().map_err(CryptoError::from)?;
        Ok(Ed25519KeyPair {
            public_key: keypair.verifying_key_bytes(),
            private_key: keypair.signing_key_bytes(),
        })
    }

    pub fn sign_ed25519(message: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let keypair =
            Ed25519KeyPair::from_private_key_bytes(&private_key).map_err(CryptoError::from)?;
        let signature =
            Ed25519Crypto::sign(&message, keypair.signing_key()).map_err(CryptoError::from)?;
        Ok(signature)
    }

    pub fn verify_ed25519(
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<bool, CryptoError> {
        let verifying_key =
            Ed25519KeyPair::verifying_key_from_bytes(&public_key).map_err(CryptoError::from)?;
        let is_valid = Ed25519Crypto::verify(&message, &signature, &verifying_key)
            .map_err(CryptoError::from)?;
        Ok(is_valid)
    }
}

// Post-quantum cryptography module
pub mod post_quantum {
    use super::*;

    pub fn generate_ml_kem_512_keypair() -> Result<MlKemKeyPair, CryptoError> {
        let keypair = MlKem512::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlKemKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 512,
        })
    }

    pub fn generate_ml_kem_768_keypair() -> Result<MlKemKeyPair, CryptoError> {
        let keypair = MlKem768::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlKemKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 768,
        })
    }

    pub fn generate_ml_kem_1024_keypair() -> Result<MlKemKeyPair, CryptoError> {
        let keypair = MlKem1024::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlKemKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 1024,
        })
    }

    pub fn encapsulate_ml_kem(
        public_key: Vec<u8>,
        level: u32,
    ) -> Result<MlKemEncapsulation, CryptoError> {
        let encapsulation = match level {
            512 => {
                let enc = MlKem512::encapsulate(&public_key).map_err(CryptoError::from)?;
                MlKemEncapsulation {
                    ciphertext: enc.ciphertext().to_vec(),
                    shared_secret: enc.shared_secret().to_vec(),
                }
            }
            768 => {
                let enc = MlKem768::encapsulate(&public_key).map_err(CryptoError::from)?;
                MlKemEncapsulation {
                    ciphertext: enc.ciphertext().to_vec(),
                    shared_secret: enc.shared_secret().to_vec(),
                }
            }
            1024 => {
                let enc = MlKem1024::encapsulate(&public_key).map_err(CryptoError::from)?;
                MlKemEncapsulation {
                    ciphertext: enc.ciphertext().to_vec(),
                    shared_secret: enc.shared_secret().to_vec(),
                }
            }
            _ => {
                return Err(CryptoError::InvalidInput {
                    message: "Invalid ML-KEM level".to_string(),
                })
            }
        };
        Ok(encapsulation)
    }

    pub fn decapsulate_ml_kem(
        ciphertext: Vec<u8>,
        private_key: Vec<u8>,
        level: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let shared_secret = match level {
            512 => MlKem512::decapsulate(&ciphertext, &private_key).map_err(CryptoError::from)?,
            768 => MlKem768::decapsulate(&ciphertext, &private_key).map_err(CryptoError::from)?,
            1024 => MlKem1024::decapsulate(&ciphertext, &private_key).map_err(CryptoError::from)?,
            _ => {
                return Err(CryptoError::InvalidInput {
                    message: "Invalid ML-KEM level".to_string(),
                })
            }
        };
        Ok(shared_secret)
    }

    pub fn generate_ml_dsa_44_keypair() -> Result<MlDsaKeyPair, CryptoError> {
        let keypair = MlDsa44::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlDsaKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 44,
        })
    }

    pub fn generate_ml_dsa_65_keypair() -> Result<MlDsaKeyPair, CryptoError> {
        let keypair = MlDsa65::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlDsaKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 65,
        })
    }

    pub fn generate_ml_dsa_87_keypair() -> Result<MlDsaKeyPair, CryptoError> {
        let keypair = MlDsa87::generate_keypair().map_err(CryptoError::from)?;
        Ok(MlDsaKeyPair {
            public_key: keypair.public_key_bytes(),
            private_key: keypair.private_key_bytes(),
            level: 87,
        })
    }

    pub fn sign_ml_dsa(
        message: Vec<u8>,
        private_key: Vec<u8>,
        level: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let signature = match level {
            44 => MlDsa44::sign(&message, &private_key).map_err(CryptoError::from)?,
            65 => MlDsa65::sign(&message, &private_key).map_err(CryptoError::from)?,
            87 => MlDsa87::sign(&message, &private_key).map_err(CryptoError::from)?,
            _ => {
                return Err(CryptoError::InvalidInput {
                    message: "Invalid ML-DSA level".to_string(),
                })
            }
        };
        Ok(signature)
    }

    pub fn verify_ml_dsa(
        message: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
        level: u32,
    ) -> Result<bool, CryptoError> {
        let is_valid = match level {
            44 => MlDsa44::verify(&message, &signature, &public_key).map_err(CryptoError::from)?,
            65 => MlDsa65::verify(&message, &signature, &public_key).map_err(CryptoError::from)?,
            87 => MlDsa87::verify(&message, &signature, &public_key).map_err(CryptoError::from)?,
            _ => {
                return Err(CryptoError::InvalidInput {
                    message: "Invalid ML-DSA level".to_string(),
                })
            }
        };
        Ok(is_valid)
    }
}

// Cryptographic hashing module
pub mod hash {
    use super::*;

    pub fn sha256(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let hash = Sha256Hash::hash(&data).map_err(CryptoError::from)?;
        Ok(hash)
    }

    pub fn sha256_hex(data: Vec<u8>) -> Result<String, CryptoError> {
        let hash_hex = Sha256Hash::hash_hex(&data).map_err(CryptoError::from)?;
        Ok(hash_hex)
    }

    pub fn sha512(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let hash = Sha512Hash::hash(&data).map_err(CryptoError::from)?;
        Ok(hash)
    }

    pub fn sha512_hex(data: Vec<u8>) -> Result<String, CryptoError> {
        let hash_hex = Sha512Hash::hash_hex(&data).map_err(CryptoError::from)?;
        Ok(hash_hex)
    }

    pub fn blake3(data: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let hash = Blake3Hash::hash(&data).map_err(CryptoError::from)?;
        Ok(hash)
    }

    pub fn blake3_with_length(data: Vec<u8>, length: u32) -> Result<Vec<u8>, CryptoError> {
        let hash =
            Blake3Hash::hash_with_length(&data, length as usize).map_err(CryptoError::from)?;
        Ok(hash)
    }

    pub fn blake3_hex(data: Vec<u8>) -> Result<String, CryptoError> {
        let hash_hex = Blake3Hash::hash_hex(&data).map_err(CryptoError::from)?;
        Ok(hash_hex)
    }

    pub fn hmac_sha256(key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let mac = Hmac::sha256(&key, &message).map_err(CryptoError::from)?;
        Ok(mac)
    }

    pub fn verify_hmac_sha256(
        key: Vec<u8>,
        message: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<bool, CryptoError> {
        let is_valid = Hmac::verify_sha256(&key, &message, &mac).map_err(CryptoError::from)?;
        Ok(is_valid)
    }

    pub fn hmac_sha512(key: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let mac = Hmac::sha512(&key, &message).map_err(CryptoError::from)?;
        Ok(mac)
    }

    pub fn verify_hmac_sha512(
        key: Vec<u8>,
        message: Vec<u8>,
        mac: Vec<u8>,
    ) -> Result<bool, CryptoError> {
        let is_valid = Hmac::verify_sha512(&key, &message, &mac).map_err(CryptoError::from)?;
        Ok(is_valid)
    }
}

// Key derivation functions module
pub mod kdf {
    use super::*;

    pub fn argon2(password: Vec<u8>, salt: Vec<u8>, length: u32) -> Result<Vec<u8>, CryptoError> {
        let key =
            Argon2Kdf::derive_key(&password, &salt, length as usize).map_err(CryptoError::from)?;
        Ok(key)
    }

    pub fn pbkdf2_sha256(
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        length: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Pbkdf2Kdf::derive_sha256(&password, &salt, iterations, length as usize)
            .map_err(CryptoError::from)?;
        Ok(key)
    }

    pub fn pbkdf2_sha512(
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        length: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Pbkdf2Kdf::derive_sha512(&password, &salt, iterations, length as usize)
            .map_err(CryptoError::from)?;
        Ok(key)
    }

    pub fn hkdf_sha256(
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
        length: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = HkdfKdf::derive_sha256(&ikm, &salt, &info, length as usize)
            .map_err(CryptoError::from)?;
        Ok(key)
    }

    pub fn hkdf_sha512(
        ikm: Vec<u8>,
        salt: Vec<u8>,
        info: Vec<u8>,
        length: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = HkdfKdf::derive_sha512(&ikm, &salt, &info, length as usize)
            .map_err(CryptoError::from)?;
        Ok(key)
    }
}

// Secure random generation module
pub mod random {
    use super::*;

    pub fn generate_bytes(length: u32) -> Result<Vec<u8>, CryptoError> {
        let bytes = SecureRandom::generate_bytes(length as usize).map_err(CryptoError::from)?;
        Ok(bytes)
    }

    pub fn generate_salt() -> Result<Vec<u8>, CryptoError> {
        let salt = SecureRandom::generate_salt().map_err(CryptoError::from)?;
        Ok(salt)
    }

    pub fn generate_u32() -> Result<u32, CryptoError> {
        let value = SecureRandom::generate_u32().map_err(CryptoError::from)?;
        Ok(value)
    }

    pub fn generate_u64() -> Result<u64, CryptoError> {
        let value = SecureRandom::generate_u64().map_err(CryptoError::from)?;
        Ok(value)
    }
}
