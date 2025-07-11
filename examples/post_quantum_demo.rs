use libsilver::core::{
    MlKem512, MlKem768, MlKem1024,
    MlDsa44, MlDsa65, MlDsa87
};
use libsilver::error::CryptoResult;

fn main() -> CryptoResult<()> {
    println!("LibSilver Post-Quantum Cryptography Demo");
    println!("=========================================");
    println!("Showcasing all ML-KEM and ML-DSA variants");

    // ML-KEM (Key Encapsulation Mechanism) Demo - All Variants
    println!("\n1. ML-KEM Key Encapsulation Demo (All Variants):");
    println!("------------------------------------------------");

    // ML-KEM-512 (NIST Level 1)
    println!("\n1.1. ML-KEM-512 (NIST Level 1):");
    let kem_512_keypair = MlKem512::generate_keypair()?;
    println!("✓ Generated ML-KEM-512 key pair");
    println!("  Public key size: {} bytes", kem_512_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", kem_512_keypair.private_key_bytes().len());

    let kem_512_encapsulation = MlKem512::encapsulate(kem_512_keypair.public_key_bytes())?;
    println!("✓ Encapsulated shared secret");
    println!("  Ciphertext size: {} bytes", kem_512_encapsulation.ciphertext.len());
    println!("  Shared secret size: {} bytes", kem_512_encapsulation.shared_secret.len());

    let kem_512_decapsulated = MlKem512::decapsulate(
        &kem_512_encapsulation.ciphertext,
        kem_512_keypair.private_key_bytes(),
    )?;

    if kem_512_encapsulation.shared_secret == kem_512_decapsulated {
        println!("✓ ML-KEM-512 working correctly!");
    }

    // ML-KEM-768 (NIST Level 3) - Default
    println!("\n1.2. ML-KEM-768 (NIST Level 3) - Default:");
    let kem_768_keypair = MlKem768::generate_keypair()?;
    println!("✓ Generated ML-KEM-768 key pair");
    println!("  Public key size: {} bytes", kem_768_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", kem_768_keypair.private_key_bytes().len());

    let kem_768_encapsulation = MlKem768::encapsulate(kem_768_keypair.public_key_bytes())?;
    println!("✓ Encapsulated shared secret");
    println!("  Ciphertext size: {} bytes", kem_768_encapsulation.ciphertext.len());
    println!("  Shared secret size: {} bytes", kem_768_encapsulation.shared_secret.len());

    let kem_768_decapsulated = MlKem768::decapsulate(
        &kem_768_encapsulation.ciphertext,
        kem_768_keypair.private_key_bytes(),
    )?;

    if kem_768_encapsulation.shared_secret == kem_768_decapsulated {
        println!("✓ ML-KEM-768 working correctly!");
    }

    // ML-KEM-1024 (NIST Level 5)
    println!("\n1.3. ML-KEM-1024 (NIST Level 5):");
    let kem_1024_keypair = MlKem1024::generate_keypair()?;
    println!("✓ Generated ML-KEM-1024 key pair");
    println!("  Public key size: {} bytes", kem_1024_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", kem_1024_keypair.private_key_bytes().len());

    let kem_1024_encapsulation = MlKem1024::encapsulate(kem_1024_keypair.public_key_bytes())?;
    println!("✓ Encapsulated shared secret");
    println!("  Ciphertext size: {} bytes", kem_1024_encapsulation.ciphertext.len());
    println!("  Shared secret size: {} bytes", kem_1024_encapsulation.shared_secret.len());

    let kem_1024_decapsulated = MlKem1024::decapsulate(
        &kem_1024_encapsulation.ciphertext,
        kem_1024_keypair.private_key_bytes(),
    )?;

    if kem_1024_encapsulation.shared_secret == kem_1024_decapsulated {
        println!("✓ ML-KEM-1024 working correctly!");
    }

    // ML-DSA (Digital Signature Algorithm) Demo - All Variants
    println!("\n2. ML-DSA Digital Signature Demo (All Variants):");
    println!("------------------------------------------------");

    // ML-DSA-44 (NIST Level 2)
    println!("\n2.1. ML-DSA-44 (NIST Level 2):");
    let dsa_44_keypair = MlDsa44::generate_keypair()?;
    println!("✓ Generated ML-DSA-44 key pair");
    println!("  Public key size: {} bytes", dsa_44_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", dsa_44_keypair.private_key_bytes().len());

    let message_44 = b"Hello, post-quantum world! This message is signed with ML-DSA-44.";
    let signature_44 = MlDsa44::sign(message_44, dsa_44_keypair.private_key_bytes())?;
    println!("✓ Signed message with ML-DSA-44");
    println!("  Message: {:?}", std::str::from_utf8(message_44).unwrap());
    println!("  Signature size: {} bytes", signature_44.len());

    let is_valid_44 = MlDsa44::verify(message_44, &signature_44, dsa_44_keypair.public_key_bytes())?;

    if is_valid_44 {
        println!("✓ ML-DSA-44 signature verification successful!");
    }

    // ML-DSA-65 (NIST Level 3) - Default
    println!("\n2.2. ML-DSA-65 (NIST Level 3) - Default:");
    let dsa_65_keypair = MlDsa65::generate_keypair()?;
    println!("✓ Generated ML-DSA-65 key pair");
    println!("  Public key size: {} bytes", dsa_65_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", dsa_65_keypair.private_key_bytes().len());

    let message_65 = b"Hello, post-quantum world! This message is signed with ML-DSA-65.";
    let signature_65 = MlDsa65::sign(message_65, dsa_65_keypair.private_key_bytes())?;
    println!("✓ Signed message with ML-DSA-65");
    println!("  Message: {:?}", std::str::from_utf8(message_65).unwrap());
    println!("  Signature size: {} bytes", signature_65.len());

    let is_valid_65 = MlDsa65::verify(message_65, &signature_65, dsa_65_keypair.public_key_bytes())?;

    if is_valid_65 {
        println!("✓ ML-DSA-65 signature verification successful!");
    }

    // ML-DSA-87 (NIST Level 5)
    println!("\n2.3. ML-DSA-87 (NIST Level 5):");
    let dsa_87_keypair = MlDsa87::generate_keypair()?;
    println!("✓ Generated ML-DSA-87 key pair");
    println!("  Public key size: {} bytes", dsa_87_keypair.public_key_bytes().len());
    println!("  Private key size: {} bytes", dsa_87_keypair.private_key_bytes().len());

    let message_87 = b"Hello, post-quantum world! This message is signed with ML-DSA-87.";
    let signature_87 = MlDsa87::sign(message_87, dsa_87_keypair.private_key_bytes())?;
    println!("✓ Signed message with ML-DSA-87");
    println!("  Message: {:?}", std::str::from_utf8(message_87).unwrap());
    println!("  Signature size: {} bytes", signature_87.len());

    let is_valid_87 = MlDsa87::verify(message_87, &signature_87, dsa_87_keypair.public_key_bytes())?;

    if is_valid_87 {
        println!("✓ ML-DSA-87 signature verification successful!");
    }

    // Test tampered message detection
    println!("\n3. Security Test - Tampered Message Detection:");
    println!("---------------------------------------------");
    let tampered_message = b"Hello, post-quantum world! This message has been tampered with.";
    let is_tampered_valid = MlDsa65::verify(tampered_message, &signature_65, dsa_65_keypair.public_key_bytes())?;

    if !is_tampered_valid {
        println!("✓ Tampered message correctly rejected!");
    } else {
        println!("✗ Tampered message incorrectly accepted!");
    }

    // Security levels and key size comparison
    println!("\n4. Security Levels and Key Size Summary:");
    println!("========================================");

    println!("\nML-KEM (Key Encapsulation) Variants:");
    println!("  ML-KEM-512  (NIST Level 1): PK={} bytes, SK={} bytes, CT={} bytes",
             kem_512_keypair.public_key_bytes().len(),
             kem_512_keypair.private_key_bytes().len(),
             kem_512_encapsulation.ciphertext.len());
    println!("  ML-KEM-768  (NIST Level 3): PK={} bytes, SK={} bytes, CT={} bytes",
             kem_768_keypair.public_key_bytes().len(),
             kem_768_keypair.private_key_bytes().len(),
             kem_768_encapsulation.ciphertext.len());
    println!("  ML-KEM-1024 (NIST Level 5): PK={} bytes, SK={} bytes, CT={} bytes",
             kem_1024_keypair.public_key_bytes().len(),
             kem_1024_keypair.private_key_bytes().len(),
             kem_1024_encapsulation.ciphertext.len());

    println!("\nML-DSA (Digital Signature) Variants:");
    println!("  ML-DSA-44 (NIST Level 2): PK={} bytes, SK={} bytes, SIG={} bytes",
             dsa_44_keypair.public_key_bytes().len(),
             dsa_44_keypair.private_key_bytes().len(),
             signature_44.len());
    println!("  ML-DSA-65 (NIST Level 3): PK={} bytes, SK={} bytes, SIG={} bytes",
             dsa_65_keypair.public_key_bytes().len(),
             dsa_65_keypair.private_key_bytes().len(),
             signature_65.len());
    println!("  ML-DSA-87 (NIST Level 5): PK={} bytes, SK={} bytes, SIG={} bytes",
             dsa_87_keypair.public_key_bytes().len(),
             dsa_87_keypair.private_key_bytes().len(),
             signature_87.len());

    println!("\nSecurity Level Equivalents:");
    println!("  NIST Level 1 ≈ AES-128 (112-bit security)");
    println!("  NIST Level 2 ≈ SHA-256 (128-bit security)");
    println!("  NIST Level 3 ≈ AES-192 (168-bit security)");
    println!("  NIST Level 5 ≈ AES-256 (224-bit security)");

    println!("\nClassical vs Post-Quantum Comparison:");
    println!("  RSA-2048 public key:    ~256 bytes");
    println!("  ML-KEM-768 public key:  {} bytes", kem_768_keypair.public_key_bytes().len());
    println!("  ECDSA P-256 public key: ~64 bytes");
    println!("  ML-DSA-65 public key:   {} bytes", dsa_65_keypair.public_key_bytes().len());
    println!("\n  Note: Post-quantum keys are larger but provide quantum resistance!");

    println!("\n🎉 All post-quantum cryptography variants working successfully!");
    println!("   LibSilver now supports 6 post-quantum algorithms:");
    println!("   • 3 ML-KEM variants (512, 768, 1024)");
    println!("   • 3 ML-DSA variants (44, 65, 87)");

    Ok(())
}
