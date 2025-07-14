use libsilver::prelude::*;

fn main() -> CryptoResult<()> {
    println!("🔐 LibSilver Default AES Implementation Example\n");

    // Generate a new AES-256 key
    let key = AesGcm::generate_key()?;
    println!("✅ Generated AES-256 key: {} bytes", key.len());

    // Example 1: Basic encryption and decryption using default AesGcm (now AWS-LC-RS)
    println!("\n1. Default AesGcm (AWS-LC-RS) Encryption/Decryption");
    println!("===================================================");
    
    let plaintext = b"Hello, Default AES! This uses AWS-LC-RS by default.";
    println!("📝 Plaintext: {}", String::from_utf8_lossy(plaintext));
    
    let ciphertext = AesGcm::encrypt(plaintext, &key)?;
    println!("🔒 Ciphertext length: {} bytes (includes nonce + tag)", ciphertext.len());
    
    let decrypted = AesGcm::decrypt(&ciphertext, &key)?;
    println!("🔓 Decrypted: {}", String::from_utf8_lossy(&decrypted));
    println!("✅ Default AesGcm encryption/decryption successful!");

    // Example 2: Verify compatibility between AesGcm and AwsLcAesGcm
    println!("\n2. Compatibility Verification");
    println!("=============================");
    
    let test_message = b"Testing compatibility between AesGcm and AwsLcAesGcm";
    
    // Encrypt with AesGcm (default)
    let aes_gcm_ciphertext = AesGcm::encrypt(test_message, &key)?;
    
    // Decrypt with AwsLcAesGcm (explicit)
    let aws_lc_decrypted = AwsLcAesGcm::decrypt(&aes_gcm_ciphertext, &key)?;
    
    // Encrypt with AwsLcAesGcm (explicit)
    let aws_lc_ciphertext = AwsLcAesGcm::encrypt(test_message, &key)?;
    
    // Decrypt with AesGcm (default)
    let aes_gcm_decrypted = AesGcm::decrypt(&aws_lc_ciphertext, &key)?;
    
    println!("📝 Original message: {}", String::from_utf8_lossy(test_message));
    println!("🔓 AesGcm->AwsLcAesGcm: {}", String::from_utf8_lossy(&aws_lc_decrypted));
    println!("🔓 AwsLcAesGcm->AesGcm: {}", String::from_utf8_lossy(&aes_gcm_decrypted));
    
    assert_eq!(test_message, &aws_lc_decrypted[..]);
    assert_eq!(test_message, &aes_gcm_decrypted[..]);
    println!("✅ Perfect compatibility confirmed!");

    // Example 3: AAD support with default AesGcm
    println!("\n3. AAD Support with Default AesGcm");
    println!("==================================");
    
    let secret_data = b"Confidential information";
    let aad = b"user_id:12345,session:abc123";
    
    let ciphertext_with_aad = AesGcm::encrypt_with_aad(secret_data, &key, aad)?;
    let decrypted_with_aad = AesGcm::decrypt_with_aad(&ciphertext_with_aad, &key, aad)?;
    
    println!("📝 Secret data: {}", String::from_utf8_lossy(secret_data));
    println!("🏷️  AAD: {}", String::from_utf8_lossy(aad));
    println!("🔓 Decrypted with AAD: {}", String::from_utf8_lossy(&decrypted_with_aad));
    
    assert_eq!(secret_data, &decrypted_with_aad[..]);
    println!("✅ AAD encryption/decryption successful!");

    // Example 4: Alternative RustCrypto implementation
    println!("\n4. Alternative RustCrypto Implementation");
    println!("=======================================");
    
    let rustcrypto_key = RustCryptoAesGcm::generate_key()?;
    let rustcrypto_plaintext = b"Using RustCrypto AES implementation";
    
    let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt(rustcrypto_plaintext, &rustcrypto_key)?;
    let rustcrypto_decrypted = RustCryptoAesGcm::decrypt(&rustcrypto_ciphertext, &rustcrypto_key)?;
    
    println!("📝 RustCrypto plaintext: {}", String::from_utf8_lossy(rustcrypto_plaintext));
    println!("🔓 RustCrypto decrypted: {}", String::from_utf8_lossy(&rustcrypto_decrypted));
    
    assert_eq!(rustcrypto_plaintext, &rustcrypto_decrypted[..]);
    println!("✅ RustCrypto implementation works correctly!");

    println!("\n5. Summary");
    println!("==========");
    println!("🎯 AesGcm now defaults to AWS-LC-RS for:");
    println!("   • FIPS 140-2 validated cryptography");
    println!("   • Enhanced security with RandomizedNonceKey");
    println!("   • Optimized performance");
    println!("   • Full API compatibility");
    println!("🔧 RustCryptoAesGcm remains available for pure Rust needs");
    println!("🚀 Both implementations are fully tested and production-ready");

    println!("\n🎉 Default AES implementation example completed successfully!");

    Ok(())
}
