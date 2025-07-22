use libsilver::core::stream_symmetric::{StreamCipher, AES_NONCE_SIZE};
use libsilver::core::random::SecureRandom;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== LibSilver Stream Cipher Authenticated Encryption Example ===\n");

    // Generate a secure key for AES-256-GCM
    let key = SecureRandom::generate_key(32)?;
    println!("Generated 256-bit key: {} bytes", key.len());

    // Create a new stream cipher instance
    let cipher = StreamCipher::new(key.as_bytes())?;
    println!("Stream cipher initialized successfully\n");

    // Example 1: Basic authenticated encryption without AAD
    println!("--- Example 1: Basic Authenticated Encryption ---");
    let message1 = b"Hello, authenticated world!";
    println!("Original message: {:?}", std::str::from_utf8(message1)?);

    // Encrypt with separate tag
    let auth_result1 = cipher.encrypt_chunk_with_tag(message1)?;
    println!("Ciphertext length: {} bytes", auth_result1.ciphertext.len());
    println!("Authentication tag length: {} bytes", auth_result1.tag.len());
    println!("Nonce length: {} bytes", auth_result1.nonce.len());

    // Decrypt using separate components
    let decrypted1 = cipher.decrypt_chunk_with_tag(
        &auth_result1.ciphertext,
        &auth_result1.tag,
        &auth_result1.nonce
    )?;
    println!("Decrypted message: {:?}\n", std::str::from_utf8(&decrypted1)?);

    // Example 2: Authenticated encryption with Additional Authenticated Data (AAD)
    println!("--- Example 2: Authenticated Encryption with AAD ---");
    let message2 = b"Sensitive financial data";
    let aad = b"user_id:12345,timestamp:2024-01-15T10:30:00Z";
    println!("Message: {:?}", std::str::from_utf8(message2)?);
    println!("AAD: {:?}", std::str::from_utf8(aad)?);

    // Encrypt with AAD
    let ciphertext2 = cipher.encrypt_chunk_with_aad(message2, aad)?;
    println!("Encrypted with AAD - total ciphertext: {} bytes (includes nonce + ciphertext + tag)",
             ciphertext2.len());

    // Decrypt with AAD
    let decrypted2 = cipher.decrypt_chunk_with_aad(&ciphertext2, aad)?;
    println!("Decrypted message: {:?}\n", std::str::from_utf8(&decrypted2)?);

    // Example 3: Multiple chunks with different AAD
    println!("--- Example 3: Multiple Chunks with Different AAD ---");
    let chunks = [
        (b"Chunk 1 data", b"metadata:chunk1"),
        (b"Chunk 2 data", b"metadata:chunk2"),
        (b"Chunk 3 data", b"metadata:chunk3"),
    ];

    let mut encrypted_chunks = Vec::new();

    // Encrypt multiple chunks
    for (i, (data, chunk_aad)) in chunks.iter().enumerate() {
        let ciphertext = cipher.encrypt_chunk_with_aad(*data, *chunk_aad)?;
        println!("Encrypted chunk {}: {} bytes -> {} bytes total",
                 i + 1, data.len(), ciphertext.len());
        encrypted_chunks.push((ciphertext, chunk_aad.as_slice()));
    }

    // Decrypt multiple chunks
    println!("\nDecrypting chunks:");
    for (i, (ciphertext, chunk_aad)) in encrypted_chunks.iter().enumerate() {
        let decrypted = cipher.decrypt_chunk_with_aad(ciphertext, chunk_aad)?;
        println!("Decrypted chunk {}: {:?}", i + 1, std::str::from_utf8(&decrypted)?);
    }

    // Example 4: Demonstrating authentication failure
    println!("\n--- Example 4: Authentication Failure Detection ---");
    let message4 = b"Important message";
    let correct_aad = b"correct_metadata";
    let wrong_aad = b"wrong_metadata";

    let ciphertext4 = cipher.encrypt_chunk_with_aad(message4, correct_aad)?;
    println!("Encrypted message with correct AAD");

    // Try to decrypt with wrong AAD (should fail)
    match cipher.decrypt_chunk_with_aad(&ciphertext4, wrong_aad) {
        Ok(_) => println!("ERROR: Decryption should have failed!"),
        Err(e) => println!("✓ Authentication correctly failed: {}", e),
    }

    // Try with tampered ciphertext (should fail)
    let mut tampered_ciphertext = ciphertext4.clone();
    if tampered_ciphertext.len() > AES_NONCE_SIZE {
        tampered_ciphertext[AES_NONCE_SIZE] ^= 0x01; // Flip one bit in the actual ciphertext part
    }

    match cipher.decrypt_chunk_with_aad(&tampered_ciphertext, correct_aad) {
        Ok(_) => println!("ERROR: Decryption should have failed!"),
        Err(e) => println!("✓ Tampering correctly detected: {}", e),
    }

    // Example 5: Empty data with AAD
    println!("\n--- Example 5: Empty Data with AAD ---");
    let empty_data = b"";
    let metadata = b"empty_file_metadata";
    
    let ciphertext5 = cipher.encrypt_chunk_with_aad(empty_data, metadata)?;
    println!("Encrypted empty data - total ciphertext: {} bytes (nonce + tag only)",
             ciphertext5.len());

    let decrypted5 = cipher.decrypt_chunk_with_aad(&ciphertext5, metadata)?;
    println!("Decrypted empty data: {} bytes", decrypted5.len());

    println!("\n=== All examples completed successfully! ===");
    Ok(())
}
