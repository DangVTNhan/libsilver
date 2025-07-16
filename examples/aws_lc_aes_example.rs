use libsilver::prelude::*;

fn main() -> CryptoResult<()> {
    println!("🔐 LibSilver AWS-LC-RS AES-256-GCM Example\n");

    // Generate a new AES-256 key
    let key = AwsLcAesGcm::generate_key()?;
    println!("✅ Generated AES-256 key: {} bytes", key.len());

    // Example 1: Basic encryption and decryption
    println!("\n1. Basic Encryption/Decryption");
    println!("==============================");
    
    let plaintext = b"Hello, AWS-LC-RS World! This is a secret message.";
    println!("📝 Plaintext: {}", String::from_utf8_lossy(plaintext));
    
    let ciphertext = AwsLcAesGcm::encrypt(plaintext, &key)?;
    println!("🔒 Ciphertext length: {} bytes (includes nonce + tag)", ciphertext.len());
    
    let decrypted = AwsLcAesGcm::decrypt(&ciphertext, &key)?;
    println!("🔓 Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    assert_eq!(plaintext, &decrypted[..]);
    println!("✅ Encryption/Decryption successful!");

    // Example 2: Encryption with Additional Authenticated Data (AAD)
    println!("\n2. Encryption with AAD");
    println!("======================");
    
    let message = b"Confidential data";
    let aad = b"user_id:12345,timestamp:2024-01-01";
    
    println!("📝 Message: {}", String::from_utf8_lossy(message));
    println!("🏷️  AAD: {}", String::from_utf8_lossy(aad));
    
    let ciphertext_with_aad = AwsLcAesGcm::encrypt_with_aad(message, &key, aad)?;
    let decrypted_with_aad = AwsLcAesGcm::decrypt_with_aad(&ciphertext_with_aad, &key, aad)?;
    
    println!("🔓 Decrypted with AAD: {}", String::from_utf8_lossy(&decrypted_with_aad));
    assert_eq!(message, &decrypted_with_aad[..]);
    println!("✅ AAD encryption/decryption successful!");

    // Example 3: Using high-level convenience functions
    println!("\n3. High-Level Convenience Functions");
    println!("===================================");
    
    let data = b"Using high-level AWS-LC-RS functions";
    println!("📝 Data: {}", String::from_utf8_lossy(data));
    
    let encrypted = libsilver::crypto::encrypt_aes_aws_lc(data, &key)?;
    let decrypted = libsilver::crypto::decrypt_aes_aws_lc(&encrypted, &key)?;
    
    println!("🔓 Decrypted: {}", String::from_utf8_lossy(&decrypted));
    assert_eq!(data, &decrypted[..]);
    println!("✅ High-level functions successful!");

    // Example 4: Comparison with RustCrypto implementation
    println!("\n4. Comparison with RustCrypto AES-GCM");
    println!("=====================================");
    
    let test_data = b"Comparing implementations";
    println!("📝 Test data: {}", String::from_utf8_lossy(test_data));
    
    // Encrypt with both implementations
    let rustcrypto_encrypted = AesGcm::encrypt(test_data, &key)?;
    let aws_lc_encrypted = AwsLcAesGcm::encrypt(test_data, &key)?;
    
    println!("🔒 RustCrypto ciphertext length: {} bytes", rustcrypto_encrypted.len());
    println!("🔒 AWS-LC-RS ciphertext length: {} bytes", aws_lc_encrypted.len());
    
    // Both should decrypt correctly
    let rustcrypto_decrypted = AesGcm::decrypt(&rustcrypto_encrypted, &key)?;
    let aws_lc_decrypted = AwsLcAesGcm::decrypt(&aws_lc_encrypted, &key)?;
    
    println!("🔓 RustCrypto decrypted: {}", String::from_utf8_lossy(&rustcrypto_decrypted));
    println!("🔓 AWS-LC-RS decrypted: {}", String::from_utf8_lossy(&aws_lc_decrypted));
    
    assert_eq!(test_data, &rustcrypto_decrypted[..]);
    assert_eq!(test_data, &aws_lc_decrypted[..]);
    assert_eq!(rustcrypto_decrypted, aws_lc_decrypted);
    println!("✅ Both implementations work correctly!");

    // Example 5: Performance characteristics
    println!("\n5. Key Features");
    println!("===============");
    println!("🚀 AWS-LC-RS provides:");
    println!("   • FIPS 140-2 validated cryptography");
    println!("   • Optimized performance on AWS infrastructure");
    println!("   • Same API compatibility as RustCrypto");
    println!("   • Memory-safe Rust implementation");
    println!("   • Support for AAD (Additional Authenticated Data)");
    
    println!("\n🎉 AWS-LC-RS AES-256-GCM example completed successfully!");
    
    Ok(())
}
