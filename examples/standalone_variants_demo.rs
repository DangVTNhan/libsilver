use libsilver::core::{
    MlKem512, MlKem768, MlKem1024,
    MlDsa44, MlDsa65, MlDsa87
};
use libsilver::error::CryptoResult;

fn main() -> CryptoResult<()> {
    println!("LibSilver Standalone Variants Demo");
    println!("==================================");
    println!("Direct function calls for each post-quantum variant");

    // ML-KEM-512 Example
    println!("\n1. ML-KEM-512 Direct Usage:");
    println!("---------------------------");
    
    // Generate key pair
    let kem512_keypair = MlKem512::generate_keypair()?;
    println!("✓ Generated ML-KEM-512 key pair");
    
    // Encapsulate
    let kem512_encapsulation = MlKem512::encapsulate(kem512_keypair.public_key_bytes())?;
    println!("✓ Encapsulated shared secret");
    
    // Decapsulate
    let kem512_shared_secret = MlKem512::decapsulate(
        &kem512_encapsulation.ciphertext,
        kem512_keypair.private_key_bytes()
    )?;
    println!("✓ Decapsulated shared secret");
    
    assert_eq!(kem512_encapsulation.shared_secret, kem512_shared_secret);
    println!("✓ ML-KEM-512 working correctly!");

    // ML-KEM-768 Example (Recommended)
    println!("\n2. ML-KEM-768 Direct Usage (Recommended):");
    println!("------------------------------------------");
    
    let kem768_keypair = MlKem768::generate_keypair()?;
    let kem768_encapsulation = MlKem768::encapsulate(kem768_keypair.public_key_bytes())?;
    let kem768_shared_secret = MlKem768::decapsulate(
        &kem768_encapsulation.ciphertext,
        kem768_keypair.private_key_bytes()
    )?;
    
    assert_eq!(kem768_encapsulation.shared_secret, kem768_shared_secret);
    println!("✓ ML-KEM-768 working correctly!");

    // ML-KEM-1024 Example
    println!("\n3. ML-KEM-1024 Direct Usage:");
    println!("----------------------------");
    
    let kem1024_keypair = MlKem1024::generate_keypair()?;
    let kem1024_encapsulation = MlKem1024::encapsulate(kem1024_keypair.public_key_bytes())?;
    let kem1024_shared_secret = MlKem1024::decapsulate(
        &kem1024_encapsulation.ciphertext,
        kem1024_keypair.private_key_bytes()
    )?;
    
    assert_eq!(kem1024_encapsulation.shared_secret, kem1024_shared_secret);
    println!("✓ ML-KEM-1024 working correctly!");

    // ML-DSA-44 Example
    println!("\n4. ML-DSA-44 Direct Usage:");
    println!("--------------------------");
    
    let dsa44_keypair = MlDsa44::generate_keypair()?;
    let message = b"Hello from ML-DSA-44!";
    let dsa44_signature = MlDsa44::sign(message, dsa44_keypair.private_key_bytes())?;
    let dsa44_valid = MlDsa44::verify(message, &dsa44_signature, dsa44_keypair.public_key_bytes())?;
    
    assert!(dsa44_valid);
    println!("✓ ML-DSA-44 working correctly!");

    // ML-DSA-65 Example (Recommended)
    println!("\n5. ML-DSA-65 Direct Usage (Recommended):");
    println!("-----------------------------------------");
    
    let dsa65_keypair = MlDsa65::generate_keypair()?;
    let message = b"Hello from ML-DSA-65!";
    let dsa65_signature = MlDsa65::sign(message, dsa65_keypair.private_key_bytes())?;
    let dsa65_valid = MlDsa65::verify(message, &dsa65_signature, dsa65_keypair.public_key_bytes())?;
    
    assert!(dsa65_valid);
    println!("✓ ML-DSA-65 working correctly!");

    // ML-DSA-87 Example
    println!("\n6. ML-DSA-87 Direct Usage:");
    println!("--------------------------");
    
    let dsa87_keypair = MlDsa87::generate_keypair()?;
    let message = b"Hello from ML-DSA-87!";
    let dsa87_signature = MlDsa87::sign(message, dsa87_keypair.private_key_bytes())?;
    let dsa87_valid = MlDsa87::verify(message, &dsa87_signature, dsa87_keypair.public_key_bytes())?;
    
    assert!(dsa87_valid);
    println!("✓ ML-DSA-87 working correctly!");

    println!("\n🎉 All standalone variants working perfectly!");
    println!("   Now you can use direct function calls like:");
    println!("   • MlKem512::encapsulate()");
    println!("   • MlKem768::decapsulate()");
    println!("   • MlDsa65::sign()");
    println!("   • MlDsa87::verify()");
    println!("   And many more!");

    Ok(())
}
