use libsilver::core::{
    MlKem512, MlKem768, MlKem1024,
    MlDsa44, MlDsa65, MlDsa87
};
use libsilver::error::CryptoResult;

fn main() -> CryptoResult<()> {
    println!("LibSilver Post-Quantum Size Constants Demo");
    println!("==========================================");
    println!("Demonstrating size constants and buffer allocation");

    // ML-KEM Size Constants Demo
    println!("\n📏 ML-KEM Size Constants:");
    println!("-------------------------");
    
    println!("ML-KEM-512:");
    println!("  • Public key size:   {} bytes", MlKem512::public_key_size());
    println!("  • Private key size:  {} bytes", MlKem512::private_key_size());
    println!("  • Ciphertext size:   {} bytes", MlKem512::ciphertext_size());
    println!("  • Shared secret size: {} bytes", MlKem512::shared_secret_size());

    println!("\nML-KEM-768 (Recommended):");
    println!("  • Public key size:   {} bytes", MlKem768::public_key_size());
    println!("  • Private key size:  {} bytes", MlKem768::private_key_size());
    println!("  • Ciphertext size:   {} bytes", MlKem768::ciphertext_size());
    println!("  • Shared secret size: {} bytes", MlKem768::shared_secret_size());

    println!("\nML-KEM-1024:");
    println!("  • Public key size:   {} bytes", MlKem1024::public_key_size());
    println!("  • Private key size:  {} bytes", MlKem1024::private_key_size());
    println!("  • Ciphertext size:   {} bytes", MlKem1024::ciphertext_size());
    println!("  • Shared secret size: {} bytes", MlKem1024::shared_secret_size());

    // ML-DSA Size Constants Demo
    println!("\n📏 ML-DSA Size Constants:");
    println!("-------------------------");
    
    println!("ML-DSA-44:");
    println!("  • Public key size:     {} bytes", MlDsa44::public_key_size());
    println!("  • Private key size:    {} bytes", MlDsa44::private_key_size());
    println!("  • Max signature size:  {} bytes", MlDsa44::max_signature_size());

    println!("\nML-DSA-65 (Recommended):");
    println!("  • Public key size:     {} bytes", MlDsa65::public_key_size());
    println!("  • Private key size:    {} bytes", MlDsa65::private_key_size());
    println!("  • Max signature size:  {} bytes", MlDsa65::max_signature_size());

    println!("\nML-DSA-87:");
    println!("  • Public key size:     {} bytes", MlDsa87::public_key_size());
    println!("  • Private key size:    {} bytes", MlDsa87::private_key_size());
    println!("  • Max signature size:  {} bytes", MlDsa87::max_signature_size());

    // Practical Usage Example
    println!("\n🔧 Practical Usage with Size Constants:");
    println!("---------------------------------------");

    // Pre-allocate buffers using size constants
    println!("Pre-allocating buffers for ML-KEM-768:");
    let mut public_key_buffer = vec![0u8; MlKem768::public_key_size()];
    let mut private_key_buffer = vec![0u8; MlKem768::private_key_size()];
    let mut ciphertext_buffer = vec![0u8; MlKem768::ciphertext_size()];
    let mut shared_secret_buffer = vec![0u8; MlKem768::shared_secret_size()];

    println!("✓ Allocated {} bytes for public key", public_key_buffer.len());
    println!("✓ Allocated {} bytes for private key", private_key_buffer.len());
    println!("✓ Allocated {} bytes for ciphertext", ciphertext_buffer.len());
    println!("✓ Allocated {} bytes for shared secret", shared_secret_buffer.len());

    // Generate key pair and use the buffers
    let keypair = MlKem768::generate_keypair()?;
    public_key_buffer.copy_from_slice(keypair.public_key_bytes());
    private_key_buffer.copy_from_slice(keypair.private_key_bytes());

    let encapsulation = MlKem768::encapsulate(&public_key_buffer)?;
    ciphertext_buffer.copy_from_slice(&encapsulation.ciphertext);
    shared_secret_buffer.copy_from_slice(&encapsulation.shared_secret);

    println!("✓ Successfully used pre-allocated buffers!");

    // Verify the operation worked
    let decapsulated_secret = MlKem768::decapsulate(&ciphertext_buffer, &private_key_buffer)?;
    assert_eq!(shared_secret_buffer, decapsulated_secret);
    println!("✓ Verification successful!");

    // ML-DSA Example with size constants
    println!("\nPre-allocating buffers for ML-DSA-65:");
    let mut dsa_public_key_buffer = vec![0u8; MlDsa65::public_key_size()];
    let mut dsa_private_key_buffer = vec![0u8; MlDsa65::private_key_size()];
    let mut signature_buffer = vec![0u8; MlDsa65::max_signature_size()];

    println!("✓ Allocated {} bytes for DSA public key", dsa_public_key_buffer.len());
    println!("✓ Allocated {} bytes for DSA private key", dsa_private_key_buffer.len());
    println!("✓ Allocated {} bytes for signature", signature_buffer.len());

    let dsa_keypair = MlDsa65::generate_keypair()?;
    dsa_public_key_buffer.copy_from_slice(dsa_keypair.public_key_bytes());
    dsa_private_key_buffer.copy_from_slice(dsa_keypair.private_key_bytes());

    let message = b"Hello, post-quantum world with pre-allocated buffers!";
    let signature = MlDsa65::sign(message, &dsa_private_key_buffer)?;
    
    // Note: Actual signature might be smaller than max size
    println!("✓ Actual signature size: {} bytes (max: {})", 
             signature.len(), MlDsa65::max_signature_size());

    let is_valid = MlDsa65::verify(message, &signature, &dsa_public_key_buffer)?;
    assert!(is_valid);
    println!("✓ DSA verification successful!");

    println!("\n🎉 Size constants make buffer management easy and efficient!");
    println!("   Use these constants for:");
    println!("   • Pre-allocating buffers");
    println!("   • Validating input sizes");
    println!("   • Network protocol design");
    println!("   • Memory pool management");

    Ok(())
}
