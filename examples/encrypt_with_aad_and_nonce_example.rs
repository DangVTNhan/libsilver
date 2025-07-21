use libsilver::core::symmetric::{AesGcm, RustCryptoAesGcm, AwsLcAesGcm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== LibSilver encrypt_with_aad_and_nonce Example ===\n");

    // Test data
    let plaintext = b"This is a secret message that needs encryption with AAD and custom nonce!";
    let aad = b"additional authenticated data - user metadata";
    let custom_nonce = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]; // 12 bytes

    println!("Original plaintext: {:?}", String::from_utf8_lossy(plaintext));
    println!("AAD: {:?}", String::from_utf8_lossy(aad));
    println!("Custom nonce: {:02X?}\n", custom_nonce);

    // Generate a key
    let key = AesGcm::generate_key()?;
    println!("Generated key: {:02X?}\n", key);

    // === Test with default AesGcm (AWS-LC-RS) ===
    println!("=== Using AesGcm (AWS-LC-RS by default) ===");
    
    let ciphertext = AesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &custom_nonce)?;
    println!("Ciphertext: {:02X?}", ciphertext);
    
    // Create full ciphertext format for decryption (nonce + ciphertext)
    let mut full_ciphertext = Vec::with_capacity(12 + ciphertext.len());
    full_ciphertext.extend_from_slice(&custom_nonce);
    full_ciphertext.extend_from_slice(&ciphertext);
    
    let decrypted = AesGcm::decrypt_with_aad(&full_ciphertext, &key, aad)?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    println!("Decryption successful: {}\n", decrypted == plaintext);

    // === Test with RustCrypto implementation ===
    println!("=== Using RustCryptoAesGcm ===");
    
    let rustcrypto_ciphertext = RustCryptoAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &custom_nonce)?;
    println!("RustCrypto ciphertext: {:02X?}", rustcrypto_ciphertext);
    
    // Create full ciphertext format for decryption
    let mut rustcrypto_full_ciphertext = Vec::with_capacity(12 + rustcrypto_ciphertext.len());
    rustcrypto_full_ciphertext.extend_from_slice(&custom_nonce);
    rustcrypto_full_ciphertext.extend_from_slice(&rustcrypto_ciphertext);
    
    let rustcrypto_decrypted = RustCryptoAesGcm::decrypt_with_aad(&rustcrypto_full_ciphertext, &key, aad)?;
    println!("RustCrypto decrypted: {:?}", String::from_utf8_lossy(&rustcrypto_decrypted));
    println!("RustCrypto decryption successful: {}\n", rustcrypto_decrypted == plaintext);

    // === Test with AWS-LC-RS implementation directly ===
    println!("=== Using AwsLcAesGcm directly ===");
    
    let aws_lc_ciphertext = AwsLcAesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &custom_nonce)?;
    println!("AWS-LC-RS ciphertext: {:02X?}", aws_lc_ciphertext);
    
    // Create full ciphertext format for decryption
    let mut aws_lc_full_ciphertext = Vec::with_capacity(12 + aws_lc_ciphertext.len());
    aws_lc_full_ciphertext.extend_from_slice(&custom_nonce);
    aws_lc_full_ciphertext.extend_from_slice(&aws_lc_ciphertext);
    
    let aws_lc_decrypted = AwsLcAesGcm::decrypt_with_aad(&aws_lc_full_ciphertext, &key, aad)?;
    println!("AWS-LC-RS decrypted: {:?}", String::from_utf8_lossy(&aws_lc_decrypted));
    println!("AWS-LC-RS decryption successful: {}\n", aws_lc_decrypted == plaintext);

    // === Cross-implementation compatibility test ===
    println!("=== Cross-implementation compatibility ===");
    println!("RustCrypto and AWS-LC-RS produce same ciphertext: {}", rustcrypto_ciphertext == aws_lc_ciphertext);
    println!("AesGcm and AWS-LC-RS produce same ciphertext: {}", ciphertext == aws_lc_ciphertext);
    
    // Test cross-decryption
    let cross_decrypted1 = RustCryptoAesGcm::decrypt_with_aad(&aws_lc_full_ciphertext, &key, aad)?;
    let cross_decrypted2 = AwsLcAesGcm::decrypt_with_aad(&rustcrypto_full_ciphertext, &key, aad)?;
    
    println!("Cross-decryption successful: {}", 
        cross_decrypted1 == plaintext && cross_decrypted2 == plaintext);

    // === Demonstrate deterministic encryption ===
    println!("\n=== Deterministic encryption with same nonce ===");
    let ciphertext1 = AesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &custom_nonce)?;
    let ciphertext2 = AesGcm::encrypt_with_aad_and_nonce(plaintext, &key, aad, &custom_nonce)?;
    println!("Same nonce produces identical ciphertext: {}", ciphertext1 == ciphertext2);

    // === Demonstrate AAD authentication ===
    println!("\n=== AAD authentication test ===");
    let wrong_aad = b"wrong additional authenticated data";
    
    let mut test_full_ciphertext = Vec::with_capacity(12 + ciphertext.len());
    test_full_ciphertext.extend_from_slice(&custom_nonce);
    test_full_ciphertext.extend_from_slice(&ciphertext);
    
    match AesGcm::decrypt_with_aad(&test_full_ciphertext, &key, wrong_aad) {
        Ok(_) => println!("ERROR: Decryption should have failed with wrong AAD!"),
        Err(_) => println!("✓ Decryption correctly failed with wrong AAD"),
    }

    println!("\n=== Example completed successfully! ===");
    Ok(())
}
