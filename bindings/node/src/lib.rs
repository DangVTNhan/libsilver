use napi::bindgen_prelude::*;
use napi_derive::napi;
use libsilver::core::*;
use libsilver::core::symmetric::RustCryptoAesGcm;
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

/// Symmetric Encryption Module (Default: AWS-LC-RS AES-256-GCM)
#[napi]
pub struct SymmetricCrypto;

#[napi]
impl SymmetricCrypto {
    /// Generate AES-256 key (uses AWS-LC-RS by default)
    #[napi]
    pub fn generate_aes_key() -> napi::Result<Buffer> {
        let key = to_napi_result!(AesGcm::generate_key())?;
        Ok(Buffer::from(key))
    }

    /// Encrypt data using AES-256-GCM (uses AWS-LC-RS by default)
    #[napi]
    pub fn encrypt_aes(plaintext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AesGcm::encrypt(&plaintext, &key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using AES-256-GCM (uses AWS-LC-RS by default)
    #[napi]
    pub fn decrypt_aes(ciphertext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(AesGcm::decrypt(&ciphertext, &key))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with Additional Authenticated Data (AAD) using AES-256-GCM (uses AWS-LC-RS by default)
    #[napi]
    pub fn encrypt_aes_with_aad(plaintext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AesGcm::encrypt_with_aad(&plaintext, &key, &aad))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data with Additional Authenticated Data (AAD) using AES-256-GCM (uses AWS-LC-RS by default)
    #[napi]
    pub fn decrypt_aes_with_aad(ciphertext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(AesGcm::decrypt_with_aad(&ciphertext, &key, &aad))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with provided nonce using AES-256-GCM (uses AWS-LC-RS by default, for testing purposes)
    #[napi]
    pub fn encrypt_aes_with_nonce(plaintext: Buffer, key: Buffer, nonce: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AesGcm::encrypt_with_nonce(&plaintext, &key, &nonce))?;
        Ok(Buffer::from(ciphertext))
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

/// AWS-LC-RS AES Symmetric Encryption Module
#[napi]
pub struct AwsLcAesCrypto;

#[napi]
impl AwsLcAesCrypto {
    /// Generate AES-256 key using AWS-LC-RS
    #[napi]
    pub fn generate_key() -> napi::Result<Buffer> {
        let key = to_napi_result!(AwsLcAesGcm::generate_key())?;
        Ok(Buffer::from(key))
    }

    /// Encrypt data using AWS-LC-RS AES-256-GCM
    #[napi]
    pub fn encrypt(plaintext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AwsLcAesGcm::encrypt(&plaintext, &key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using AWS-LC-RS AES-256-GCM
    #[napi]
    pub fn decrypt(ciphertext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(AwsLcAesGcm::decrypt(&ciphertext, &key))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with Additional Authenticated Data (AAD) using AWS-LC-RS AES-256-GCM
    #[napi]
    pub fn encrypt_with_aad(plaintext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AwsLcAesGcm::encrypt_with_aad(&plaintext, &key, &aad))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data with Additional Authenticated Data (AAD) using AWS-LC-RS AES-256-GCM
    #[napi]
    pub fn decrypt_with_aad(ciphertext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(AwsLcAesGcm::decrypt_with_aad(&ciphertext, &key, &aad))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with provided nonce using AWS-LC-RS AES-256-GCM (for testing purposes)
    #[napi]
    pub fn encrypt_with_nonce(plaintext: Buffer, key: Buffer, nonce: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(AwsLcAesGcm::encrypt_with_nonce(&plaintext, &key, &nonce))?;
        Ok(Buffer::from(ciphertext))
    }
}

/// RustCrypto AES Symmetric Encryption Module
#[napi]
pub struct RustCryptoAesCrypto;

#[napi]
impl RustCryptoAesCrypto {
    /// Generate AES-256 key using RustCrypto
    #[napi]
    pub fn generate_key() -> napi::Result<Buffer> {
        let key = to_napi_result!(RustCryptoAesGcm::generate_key())?;
        Ok(Buffer::from(key))
    }

    /// Encrypt data using RustCrypto AES-256-GCM
    #[napi]
    pub fn encrypt(plaintext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(RustCryptoAesGcm::encrypt(&plaintext, &key))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data using RustCrypto AES-256-GCM
    #[napi]
    pub fn decrypt(ciphertext: Buffer, key: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(RustCryptoAesGcm::decrypt(&ciphertext, &key))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with Additional Authenticated Data (AAD) using RustCrypto AES-256-GCM
    #[napi]
    pub fn encrypt_with_aad(plaintext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(RustCryptoAesGcm::encrypt_with_aad(&plaintext, &key, &aad))?;
        Ok(Buffer::from(ciphertext))
    }

    /// Decrypt data with Additional Authenticated Data (AAD) using RustCrypto AES-256-GCM
    #[napi]
    pub fn decrypt_with_aad(ciphertext: Buffer, key: Buffer, aad: Buffer) -> napi::Result<Buffer> {
        let plaintext = to_napi_result!(RustCryptoAesGcm::decrypt_with_aad(&ciphertext, &key, &aad))?;
        Ok(Buffer::from(plaintext))
    }

    /// Encrypt data with provided nonce using RustCrypto AES-256-GCM (for testing purposes)
    #[napi]
    pub fn encrypt_with_nonce(plaintext: Buffer, key: Buffer, nonce: Buffer) -> napi::Result<Buffer> {
        let ciphertext = to_napi_result!(RustCryptoAesGcm::encrypt_with_nonce(&plaintext, &key, &nonce))?;
        Ok(Buffer::from(ciphertext))
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

/// ML-KEM-512 Key Pair for JavaScript
#[napi(object)]
pub struct MlKem512KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlKem512KeyPair> for MlKem512KeyPairJs {
    fn from(keypair: MlKem512KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-KEM-768 Key Pair for JavaScript
#[napi(object)]
pub struct MlKem768KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlKem768KeyPair> for MlKem768KeyPairJs {
    fn from(keypair: MlKem768KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-KEM-1024 Key Pair for JavaScript
#[napi(object)]
pub struct MlKem1024KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlKem1024KeyPair> for MlKem1024KeyPairJs {
    fn from(keypair: MlKem1024KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-DSA-44 Key Pair for JavaScript
#[napi(object)]
pub struct MlDsa44KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlDsa44KeyPair> for MlDsa44KeyPairJs {
    fn from(keypair: MlDsa44KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-DSA-65 Key Pair for JavaScript
#[napi(object)]
pub struct MlDsa65KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlDsa65KeyPair> for MlDsa65KeyPairJs {
    fn from(keypair: MlDsa65KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-DSA-87 Key Pair for JavaScript
#[napi(object)]
pub struct MlDsa87KeyPairJs {
    pub public_key_bytes: Buffer,
    pub private_key_bytes: Buffer,
}

impl From<MlDsa87KeyPair> for MlDsa87KeyPairJs {
    fn from(keypair: MlDsa87KeyPair) -> Self {
        Self {
            public_key_bytes: Buffer::from(keypair.public_key_bytes().to_vec()),
            private_key_bytes: Buffer::from(keypair.private_key_bytes().to_vec()),
        }
    }
}

/// ML-KEM-512 Encapsulation result for JavaScript
#[napi(object)]
pub struct MlKem512EncapsulationJs {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

impl From<MlKem512Encapsulation> for MlKem512EncapsulationJs {
    fn from(encapsulation: MlKem512Encapsulation) -> Self {
        Self {
            ciphertext: Buffer::from(encapsulation.ciphertext.clone()),
            shared_secret: Buffer::from(encapsulation.shared_secret.clone()),
        }
    }
}

/// ML-KEM-768 Encapsulation result for JavaScript
#[napi(object)]
pub struct MlKem768EncapsulationJs {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

impl From<MlKem768Encapsulation> for MlKem768EncapsulationJs {
    fn from(encapsulation: MlKem768Encapsulation) -> Self {
        Self {
            ciphertext: Buffer::from(encapsulation.ciphertext.clone()),
            shared_secret: Buffer::from(encapsulation.shared_secret.clone()),
        }
    }
}

/// ML-KEM-1024 Encapsulation result for JavaScript
#[napi(object)]
pub struct MlKem1024EncapsulationJs {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

impl From<MlKem1024Encapsulation> for MlKem1024EncapsulationJs {
    fn from(encapsulation: MlKem1024Encapsulation) -> Self {
        Self {
            ciphertext: Buffer::from(encapsulation.ciphertext.clone()),
            shared_secret: Buffer::from(encapsulation.shared_secret.clone()),
        }
    }
}

/// ML-KEM-512 Post-Quantum Cryptography Module
#[napi]
pub struct MlKem512Crypto;

#[napi]
impl MlKem512Crypto {
    /// Generate ML-KEM-512 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlKem512KeyPairJs> {
        let keypair = to_napi_result!(MlKem512::generate_keypair())?;
        Ok(MlKem512KeyPairJs::from(keypair))
    }

    /// Encapsulate shared secret using ML-KEM-512
    #[napi]
    pub fn encapsulate(public_key_bytes: Buffer) -> napi::Result<MlKem512EncapsulationJs> {
        let encapsulation = to_napi_result!(MlKem512::encapsulate(&public_key_bytes))?;
        Ok(MlKem512EncapsulationJs::from(encapsulation))
    }

    /// Decapsulate shared secret using ML-KEM-512
    #[napi]
    pub fn decapsulate(ciphertext: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let shared_secret = to_napi_result!(MlKem512::decapsulate(&ciphertext, &private_key_bytes))?;
        Ok(Buffer::from(shared_secret))
    }

    /// Get ML-KEM-512 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlKemSizesJs> {
        Ok(MlKemSizesJs {
            public_key_size: MlKem512::public_key_size() as u32,
            private_key_size: MlKem512::private_key_size() as u32,
            ciphertext_size: MlKem512::ciphertext_size() as u32,
            shared_secret_size: MlKem512::shared_secret_size() as u32,
        })
    }
}

/// ML-KEM-768 Post-Quantum Cryptography Module
#[napi]
pub struct MlKem768Crypto;

#[napi]
impl MlKem768Crypto {
    /// Generate ML-KEM-768 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlKem768KeyPairJs> {
        let keypair = to_napi_result!(MlKem768::generate_keypair())?;
        Ok(MlKem768KeyPairJs::from(keypair))
    }

    /// Encapsulate shared secret using ML-KEM-768
    #[napi]
    pub fn encapsulate(public_key_bytes: Buffer) -> napi::Result<MlKem768EncapsulationJs> {
        let encapsulation = to_napi_result!(MlKem768::encapsulate(&public_key_bytes))?;
        Ok(MlKem768EncapsulationJs::from(encapsulation))
    }

    /// Decapsulate shared secret using ML-KEM-768
    #[napi]
    pub fn decapsulate(ciphertext: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let shared_secret = to_napi_result!(MlKem768::decapsulate(&ciphertext, &private_key_bytes))?;
        Ok(Buffer::from(shared_secret))
    }

    /// Get ML-KEM-768 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlKemSizesJs> {
        Ok(MlKemSizesJs {
            public_key_size: MlKem768::public_key_size() as u32,
            private_key_size: MlKem768::private_key_size() as u32,
            ciphertext_size: MlKem768::ciphertext_size() as u32,
            shared_secret_size: MlKem768::shared_secret_size() as u32,
        })
    }
}

/// ML-KEM-1024 Post-Quantum Cryptography Module
#[napi]
pub struct MlKem1024Crypto;

#[napi]
impl MlKem1024Crypto {
    /// Generate ML-KEM-1024 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlKem1024KeyPairJs> {
        let keypair = to_napi_result!(MlKem1024::generate_keypair())?;
        Ok(MlKem1024KeyPairJs::from(keypair))
    }

    /// Encapsulate shared secret using ML-KEM-1024
    #[napi]
    pub fn encapsulate(public_key_bytes: Buffer) -> napi::Result<MlKem1024EncapsulationJs> {
        let encapsulation = to_napi_result!(MlKem1024::encapsulate(&public_key_bytes))?;
        Ok(MlKem1024EncapsulationJs::from(encapsulation))
    }

    /// Decapsulate shared secret using ML-KEM-1024
    #[napi]
    pub fn decapsulate(ciphertext: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let shared_secret = to_napi_result!(MlKem1024::decapsulate(&ciphertext, &private_key_bytes))?;
        Ok(Buffer::from(shared_secret))
    }

    /// Get ML-KEM-1024 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlKemSizesJs> {
        Ok(MlKemSizesJs {
            public_key_size: MlKem1024::public_key_size() as u32,
            private_key_size: MlKem1024::private_key_size() as u32,
            ciphertext_size: MlKem1024::ciphertext_size() as u32,
            shared_secret_size: MlKem1024::shared_secret_size() as u32,
        })
    }
}

/// ML-DSA-44 Post-Quantum Digital Signature Module
#[napi]
pub struct MlDsa44Crypto;

#[napi]
impl MlDsa44Crypto {
    /// Generate ML-DSA-44 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlDsa44KeyPairJs> {
        let keypair = to_napi_result!(MlDsa44::generate_keypair())?;
        Ok(MlDsa44KeyPairJs::from(keypair))
    }

    /// Sign message using ML-DSA-44
    #[napi]
    pub fn sign(message: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let signature = to_napi_result!(MlDsa44::sign(&message, &private_key_bytes))?;
        Ok(Buffer::from(signature))
    }

    /// Verify ML-DSA-44 signature
    #[napi]
    pub fn verify(message: Buffer, signature: Buffer, public_key_bytes: Buffer) -> napi::Result<bool> {
        let is_valid = to_napi_result!(MlDsa44::verify(&message, &signature, &public_key_bytes))?;
        Ok(is_valid)
    }

    /// Get ML-DSA-44 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlDsaSizesJs> {
        Ok(MlDsaSizesJs {
            public_key_size: MlDsa44::public_key_size() as u32,
            private_key_size: MlDsa44::private_key_size() as u32,
            max_signature_size: MlDsa44::max_signature_size() as u32,
        })
    }
}

/// ML-DSA-65 Post-Quantum Digital Signature Module
#[napi]
pub struct MlDsa65Crypto;

#[napi]
impl MlDsa65Crypto {
    /// Generate ML-DSA-65 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlDsa65KeyPairJs> {
        let keypair = to_napi_result!(MlDsa65::generate_keypair())?;
        Ok(MlDsa65KeyPairJs::from(keypair))
    }

    /// Sign message using ML-DSA-65
    #[napi]
    pub fn sign(message: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let signature = to_napi_result!(MlDsa65::sign(&message, &private_key_bytes))?;
        Ok(Buffer::from(signature))
    }

    /// Verify ML-DSA-65 signature
    #[napi]
    pub fn verify(message: Buffer, signature: Buffer, public_key_bytes: Buffer) -> napi::Result<bool> {
        let is_valid = to_napi_result!(MlDsa65::verify(&message, &signature, &public_key_bytes))?;
        Ok(is_valid)
    }

    /// Get ML-DSA-65 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlDsaSizesJs> {
        Ok(MlDsaSizesJs {
            public_key_size: MlDsa65::public_key_size() as u32,
            private_key_size: MlDsa65::private_key_size() as u32,
            max_signature_size: MlDsa65::max_signature_size() as u32,
        })
    }
}

/// ML-DSA-87 Post-Quantum Digital Signature Module
#[napi]
pub struct MlDsa87Crypto;

#[napi]
impl MlDsa87Crypto {
    /// Generate ML-DSA-87 key pair
    #[napi]
    pub fn generate_keypair() -> napi::Result<MlDsa87KeyPairJs> {
        let keypair = to_napi_result!(MlDsa87::generate_keypair())?;
        Ok(MlDsa87KeyPairJs::from(keypair))
    }

    /// Sign message using ML-DSA-87
    #[napi]
    pub fn sign(message: Buffer, private_key_bytes: Buffer) -> napi::Result<Buffer> {
        let signature = to_napi_result!(MlDsa87::sign(&message, &private_key_bytes))?;
        Ok(Buffer::from(signature))
    }

    /// Verify ML-DSA-87 signature
    #[napi]
    pub fn verify(message: Buffer, signature: Buffer, public_key_bytes: Buffer) -> napi::Result<bool> {
        let is_valid = to_napi_result!(MlDsa87::verify(&message, &signature, &public_key_bytes))?;
        Ok(is_valid)
    }

    /// Get ML-DSA-87 size constants
    #[napi]
    pub fn get_sizes() -> napi::Result<MlDsaSizesJs> {
        Ok(MlDsaSizesJs {
            public_key_size: MlDsa87::public_key_size() as u32,
            private_key_size: MlDsa87::private_key_size() as u32,
            max_signature_size: MlDsa87::max_signature_size() as u32,
        })
    }
}

/// ML-KEM Size Constants for JavaScript
#[napi(object)]
pub struct MlKemSizesJs {
    pub public_key_size: u32,
    pub private_key_size: u32,
    pub ciphertext_size: u32,
    pub shared_secret_size: u32,
}

/// ML-DSA Size Constants for JavaScript
#[napi(object)]
pub struct MlDsaSizesJs {
    pub public_key_size: u32,
    pub private_key_size: u32,
    pub max_signature_size: u32,
}
