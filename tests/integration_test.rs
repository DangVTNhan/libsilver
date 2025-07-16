use libsilver::prelude::*;

#[test]
fn test_full_encryption_workflow() {
    // Test a complete encryption workflow with key derivation
    let password = b"user_password_123";
    let salt = SecureRandom::generate_salt().unwrap();
    
    // Derive encryption key from password
    let encryption_key = Argon2Kdf::derive_key(password, &salt, 32).unwrap();
    
    // Original data
    let original_data = b"This is sensitive data that needs to be encrypted and authenticated.";
    
    // Encrypt with AES-256-GCM
    let ciphertext = AesGcm::encrypt(original_data, &encryption_key).unwrap();
    
    // Decrypt
    let decrypted_data = AesGcm::decrypt(&ciphertext, &encryption_key).unwrap();
    
    // Verify
    assert_eq!(original_data, &decrypted_data[..]);
    
    // Test that wrong password fails
    let wrong_key = Argon2Kdf::derive_key(b"wrong_password", &salt, 32).unwrap();
    let wrong_decrypt_result = AesGcm::decrypt(&ciphertext, &wrong_key);
    assert!(wrong_decrypt_result.is_err());
}

#[test]
fn test_digital_signature_workflow() {
    // Test complete digital signature workflow
    let message = b"Important message that needs to be signed";
    
    // Generate Ed25519 keypair
    let keypair = Ed25519Crypto::generate_keypair().unwrap();
    
    // Sign the message
    let signature = Ed25519Crypto::sign(message, keypair.signing_key()).unwrap();
    
    // Verify signature
    let is_valid = Ed25519Crypto::verify(message, &signature, keypair.verifying_key()).unwrap();
    assert!(is_valid);
    
    // Test that tampered message fails verification
    let tampered_message = b"Important message that needs to be signed!"; // Added exclamation
    let tampered_valid = Ed25519Crypto::verify(tampered_message, &signature, keypair.verifying_key()).unwrap();
    assert!(!tampered_valid);
    
    // Test that wrong signature fails
    let wrong_signature = vec![0u8; 64];
    let wrong_valid = Ed25519Crypto::verify(message, &wrong_signature, keypair.verifying_key()).unwrap();
    assert!(!wrong_valid);
}

#[test]
fn test_hybrid_encryption_workflow() {
    // Test hybrid encryption: RSA for key exchange + AES for data
    let large_data = vec![42u8; 1024 * 1024]; // 1MB of data
    
    // Generate RSA keypair for key exchange
    let rsa_keypair = RsaCrypto::generate_keypair().unwrap();
    
    // Generate symmetric key for data encryption
    let symmetric_key = AesGcm::generate_key().unwrap();
    
    // Encrypt the symmetric key with RSA
    let encrypted_key = RsaCrypto::encrypt(&symmetric_key, rsa_keypair.public_key()).unwrap();
    
    // Encrypt the large data with AES
    let encrypted_data = AesGcm::encrypt(&large_data, &symmetric_key).unwrap();
    
    // Decryption process
    // 1. Decrypt the symmetric key with RSA
    let decrypted_key = RsaCrypto::decrypt(&encrypted_key, rsa_keypair.private_key()).unwrap();
    assert_eq!(symmetric_key, decrypted_key);
    
    // 2. Decrypt the data with the symmetric key
    let decrypted_data = AesGcm::decrypt(&encrypted_data, &decrypted_key).unwrap();
    assert_eq!(large_data, decrypted_data);
}

#[test]
fn test_authenticated_encryption_with_associated_data() {
    // Test that different algorithms produce different results but all work correctly
    let plaintext = b"Test message for authenticated encryption";
    
    // Test AES-256-GCM
    let aes_key = AesGcm::generate_key().unwrap();
    let aes_ciphertext = AesGcm::encrypt(plaintext, &aes_key).unwrap();
    let aes_decrypted = AesGcm::decrypt(&aes_ciphertext, &aes_key).unwrap();
    assert_eq!(plaintext, &aes_decrypted[..]);
    
    // Test ChaCha20-Poly1305
    let chacha_key = ChaCha20Poly1305Cipher::generate_key().unwrap();
    let chacha_ciphertext = ChaCha20Poly1305Cipher::encrypt(plaintext, &chacha_key).unwrap();
    let chacha_decrypted = ChaCha20Poly1305Cipher::decrypt(&chacha_ciphertext, &chacha_key).unwrap();
    assert_eq!(plaintext, &chacha_decrypted[..]);
    
    // Verify that different algorithms produce different ciphertexts
    assert_ne!(aes_ciphertext, chacha_ciphertext);
}

#[test]
fn test_key_derivation_consistency() {
    // Test that key derivation functions are deterministic
    let password = b"test_password";
    let salt = b"test_salt_32_bytes_long_for_test";
    
    // Argon2 should be deterministic with same inputs
    let key1 = Argon2Kdf::derive_key(password, salt, 32).unwrap();
    let key2 = Argon2Kdf::derive_key(password, salt, 32).unwrap();
    assert_eq!(key1, key2);
    
    // PBKDF2 should be deterministic
    let pbkdf2_key1 = Pbkdf2Kdf::derive_sha256(password, salt, 10000, 32).unwrap();
    let pbkdf2_key2 = Pbkdf2Kdf::derive_sha256(password, salt, 10000, 32).unwrap();
    assert_eq!(pbkdf2_key1, pbkdf2_key2);
    
    // HKDF should be deterministic
    let hkdf_key1 = HkdfKdf::derive_sha256(password, Some(salt), b"context", 32).unwrap();
    let hkdf_key2 = HkdfKdf::derive_sha256(password, Some(salt), b"context", 32).unwrap();
    assert_eq!(hkdf_key1, hkdf_key2);
    
    // Different algorithms should produce different keys
    assert_ne!(key1, pbkdf2_key1);
    assert_ne!(key1, hkdf_key1);
    assert_ne!(pbkdf2_key1, hkdf_key1);
}

#[test]
fn test_hash_consistency_and_verification() {
    let data = b"Data to hash for consistency testing";
    
    // Test that hashes are consistent
    let sha256_1 = Sha256Hash::hash(data).unwrap();
    let sha256_2 = Sha256Hash::hash(data).unwrap();
    assert_eq!(sha256_1, sha256_2);
    
    let blake3_1 = Blake3Hash::hash(data).unwrap();
    let blake3_2 = Blake3Hash::hash(data).unwrap();
    assert_eq!(blake3_1, blake3_2);
    
    // Test verification
    assert!(Sha256Hash::verify(data, &sha256_1).unwrap());
    assert!(Blake3Hash::verify(data, &blake3_1).unwrap());
    
    // Test that different data produces different hashes
    let different_data = b"Different data to hash";
    let sha256_different = Sha256Hash::hash(different_data).unwrap();
    assert_ne!(sha256_1, sha256_different);
    
    // Test HMAC consistency
    let key = b"hmac_key";
    let hmac1 = Hmac::sha256(key, data).unwrap();
    let hmac2 = Hmac::sha256(key, data).unwrap();
    assert_eq!(hmac1, hmac2);
    
    assert!(Hmac::verify_sha256(key, data, &hmac1).unwrap());
    assert!(!Hmac::verify_sha256(b"wrong_key", data, &hmac1).unwrap());
}

#[test]
fn test_secure_random_properties() {
    // Test that random generation produces different values
    let bytes1 = SecureRandom::generate_bytes(32).unwrap();
    let bytes2 = SecureRandom::generate_bytes(32).unwrap();
    assert_ne!(bytes1, bytes2);
    
    let key1 = SecureRandom::generate_key(32).unwrap();
    let key2 = SecureRandom::generate_key(32).unwrap();
    assert_ne!(key1.as_bytes(), key2.as_bytes());
    
    // Test that generated values have correct lengths
    assert_eq!(bytes1.len(), 32);
    assert_eq!(key1.len(), 32);
    
    let nonce = SecureRandom::generate_nonce(12).unwrap();
    assert_eq!(nonce.len(), 12);
    
    let salt = SecureRandom::generate_salt().unwrap();
    assert_eq!(salt.len(), 32);
}

#[test]
fn test_error_handling() {
    // Test various error conditions
    
    // Invalid key lengths
    let short_key = vec![0u8; 16];
    let plaintext = b"test";
    
    assert!(AesGcm::encrypt(plaintext, &short_key).is_err());
    assert!(ChaCha20Poly1305Cipher::encrypt(plaintext, &short_key).is_err());
    
    // Invalid ciphertext (too short)
    let valid_key = AesGcm::generate_key().unwrap();
    let short_ciphertext = vec![0u8; 5];
    assert!(AesGcm::decrypt(&short_ciphertext, &valid_key).is_err());
    
    // Zero-length outputs
    assert!(SecureRandom::generate_bytes(0).is_err());
    
    // Invalid signature lengths for Ed25519
    let ed25519_keypair = Ed25519Crypto::generate_keypair().unwrap();
    let message = b"test message";
    let short_signature = vec![0u8; 32]; // Should be 64 bytes
    
    assert!(Ed25519Crypto::verify(message, &short_signature, ed25519_keypair.verifying_key()).is_err());
}
