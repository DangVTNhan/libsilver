pub mod symmetric;
pub mod stream_symmetric;
pub mod asymmetric;
pub mod post_quantum;
pub mod hash;
pub mod kdf;
pub mod random;

// Re-export commonly used types and functions
pub use symmetric::{AesGcm, AwsLcAesGcm, RustCryptoAesGcm, ChaCha20Poly1305Cipher};
pub use stream_symmetric::StreamCipher;
pub use asymmetric::{RsaCrypto, EcdsaCrypto, Ed25519Crypto, RsaKeyPair, EcdsaKeyPair, Ed25519KeyPair};
pub use post_quantum::{
    // ML-KEM structs and key pairs
    MlKem512, MlKem768, MlKem1024,
    MlKem512KeyPair, MlKem768KeyPair, MlKem1024KeyPair,
    MlKem512Encapsulation, MlKem768Encapsulation, MlKem1024Encapsulation,
    // ML-DSA structs and key pairs
    MlDsa44, MlDsa65, MlDsa87,
    MlDsa44KeyPair, MlDsa65KeyPair, MlDsa87KeyPair,
};
pub use hash::{Sha256Hash, Sha512Hash, Blake3Hash, Hmac};
pub use kdf::{Argon2Kdf, HkdfKdf, Pbkdf2Kdf, SecureKeyDerivation};
pub use random::{SecureRandom, SecureKey};