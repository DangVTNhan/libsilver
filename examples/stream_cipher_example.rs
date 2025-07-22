use libsilver::core::StreamCipher;
use std::error::Error;
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== LibSilver Stream Cipher Example ===");
    
    // Generate a random key (or use a fixed one for testing)
    let key = vec![1u8; 32]; // 32-byte key for AES-256
    
    // Create a new stream cipher instance
    let cipher = StreamCipher::new(&key)?;
    println!("✅ Stream cipher initialized successfully");
    
    // Example 1: Basic encryption and decryption
    println!("\n1. Basic Encryption/Decryption");
    println!("==============================");
    
    let plaintext = b"This is a secret message that will be encrypted using AES-256-GCM in streaming mode.";
    println!("📝 Original plaintext: {}", String::from_utf8_lossy(plaintext));
    
    // Encrypt the plaintext
    let ciphertext = cipher.encrypt_chunk(plaintext)?;
    println!("🔒 Encrypted ciphertext: {} bytes", ciphertext.len());
    
    // Decrypt the ciphertext
    let decrypted = cipher.decrypt_chunk(&ciphertext)?;
    println!("🔓 Decrypted plaintext: {}", String::from_utf8_lossy(&decrypted));
    
    assert_eq!(plaintext, &decrypted[..]);
    println!("✅ Encryption/decryption successful!");
    
    // Example 2: Multiple chunks
    println!("\n2. Multiple Chunks");
    println!("=================");
    
    let chunk1 = b"This is the first chunk of data.";
    let chunk2 = b"This is the second chunk of data.";
    let chunk3 = b"This is the third chunk of data.";
    
    println!("📝 Chunk 1: {}", String::from_utf8_lossy(chunk1));
    println!("📝 Chunk 2: {}", String::from_utf8_lossy(chunk2));
    println!("📝 Chunk 3: {}", String::from_utf8_lossy(chunk3));
    
    // Encrypt each chunk
    let ciphertext1 = cipher.encrypt_chunk(chunk1)?;
    let ciphertext2 = cipher.encrypt_chunk(chunk2)?;
    let ciphertext3 = cipher.encrypt_chunk(chunk3)?;
    
    println!("🔒 Encrypted chunk 1: {} bytes", ciphertext1.len());
    println!("🔒 Encrypted chunk 2: {} bytes", ciphertext2.len());
    println!("🔒 Encrypted chunk 3: {} bytes", ciphertext3.len());
    
    // Decrypt each chunk
    let decrypted1 = cipher.decrypt_chunk(&ciphertext1)?;
    let decrypted2 = cipher.decrypt_chunk(&ciphertext2)?;
    let decrypted3 = cipher.decrypt_chunk(&ciphertext3)?;
    
    println!("🔓 Decrypted chunk 1: {}", String::from_utf8_lossy(&decrypted1));
    println!("🔓 Decrypted chunk 2: {}", String::from_utf8_lossy(&decrypted2));
    println!("🔓 Decrypted chunk 3: {}", String::from_utf8_lossy(&decrypted3));
    
    assert_eq!(chunk1, &decrypted1[..]);
    assert_eq!(chunk2, &decrypted2[..]);
    assert_eq!(chunk3, &decrypted3[..]);
    println!("✅ Multi-chunk encryption/decryption successful!");
    
    // Example 3: Nonce counter and reset
    println!("\n3. Nonce Counter and Reset");
    println!("=========================");
    
    let counter_before = cipher.get_nonce_counter()?;
    println!("🔢 Current nonce counter: {}", counter_before);
    
    // Encrypt a few more chunks to increment the counter
    for i in 0..5 {
        let data = format!("Test data {}", i).into_bytes();
        cipher.encrypt_chunk(&data)?;
    }
    
    let counter_after = cipher.get_nonce_counter()?;
    println!("🔢 Nonce counter after 5 operations: {}", counter_after);
    assert_eq!(counter_after, counter_before + 5);
    
    // Reset the cipher
    cipher.reset()?;
    let counter_reset = cipher.get_nonce_counter()?;
    println!("🔄 Nonce counter after reset: {}", counter_reset);
    assert_eq!(counter_reset, 0);
    println!("✅ Nonce counter and reset working correctly!");
    
    // Example 4: Thread safety
    println!("\n4. Thread Safety");
    println!("===============");
    
    let shared_cipher = cipher.clone();
    
    // Spawn a thread that uses the cipher
    let handle = thread::spawn(move || {
        let thread_plaintext = b"Message encrypted in a separate thread";
        let thread_ciphertext = shared_cipher.encrypt_chunk(thread_plaintext).unwrap();
        let thread_decrypted = shared_cipher.decrypt_chunk(&thread_ciphertext).unwrap();
        assert_eq!(thread_plaintext, &thread_decrypted[..]);
        thread_ciphertext
    });
    
    // Use the cipher in the main thread simultaneously
    let main_plaintext = b"Message encrypted in the main thread";
    let main_ciphertext = cipher.encrypt_chunk(main_plaintext)?;
    let main_decrypted = cipher.decrypt_chunk(&main_ciphertext)?;
    assert_eq!(main_plaintext, &main_decrypted[..]);
    
    // Wait for the thread to complete
    let thread_ciphertext = handle.join().unwrap();
    
    println!("🧵 Main thread ciphertext: {} bytes", main_ciphertext.len());
    println!("🧵 Worker thread ciphertext: {} bytes", thread_ciphertext.len());
    println!("✅ Thread-safe operations successful!");
    
    println!("\n=== Example completed successfully! ===");
    Ok(())
}
