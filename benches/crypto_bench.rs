use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use libsilver::prelude::*;

fn symmetric_encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric_encryption");
    
    let data_sizes = [1024, 4096, 16384, 65536]; // 1KB, 4KB, 16KB, 64KB
    
    for size in data_sizes.iter() {
        let data = vec![0u8; *size];
        
        // AES-256-GCM
        let aes_key = AesGcm::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("AES-256-GCM_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::encrypt(black_box(&data), black_box(&aes_key)).unwrap()
                })
            },
        );
        
        let aes_ciphertext = AesGcm::encrypt(&data, &aes_key).unwrap();
        group.bench_with_input(
            BenchmarkId::new("AES-256-GCM_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::decrypt(black_box(&aes_ciphertext), black_box(&aes_key)).unwrap()
                })
            },
        );
        
        // ChaCha20-Poly1305
        let chacha_key = ChaCha20Poly1305Cipher::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("ChaCha20-Poly1305_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    ChaCha20Poly1305Cipher::encrypt(black_box(&data), black_box(&chacha_key)).unwrap()
                })
            },
        );
        
        let chacha_ciphertext = ChaCha20Poly1305Cipher::encrypt(&data, &chacha_key).unwrap();
        group.bench_with_input(
            BenchmarkId::new("ChaCha20-Poly1305_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    ChaCha20Poly1305Cipher::decrypt(black_box(&chacha_ciphertext), black_box(&chacha_key)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn hashing_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    
    let data_sizes = [1024, 4096, 16384, 65536];
    
    for size in data_sizes.iter() {
        let data = vec![0u8; *size];
        
        group.bench_with_input(
            BenchmarkId::new("SHA-256", size),
            size,
            |b, _| {
                b.iter(|| {
                    Sha256Hash::hash(black_box(&data)).unwrap()
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("SHA-512", size),
            size,
            |b, _| {
                b.iter(|| {
                    Sha512Hash::hash(black_box(&data)).unwrap()
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("BLAKE3", size),
            size,
            |b, _| {
                b.iter(|| {
                    Blake3Hash::hash(black_box(&data)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn signature_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("digital_signatures");
    
    let message = b"Message to sign for benchmarking";
    
    // Ed25519
    let ed25519_keypair = Ed25519Crypto::generate_keypair().unwrap();
    group.bench_function("Ed25519_sign", |b| {
        b.iter(|| {
            Ed25519Crypto::sign(black_box(message), black_box(ed25519_keypair.signing_key())).unwrap()
        })
    });
    
    let ed25519_signature = Ed25519Crypto::sign(message, ed25519_keypair.signing_key()).unwrap();
    group.bench_function("Ed25519_verify", |b| {
        b.iter(|| {
            Ed25519Crypto::verify(
                black_box(message),
                black_box(&ed25519_signature),
                black_box(ed25519_keypair.verifying_key())
            ).unwrap()
        })
    });
    
    // ECDSA P-256
    let ecdsa_keypair = EcdsaCrypto::generate_keypair().unwrap();
    group.bench_function("ECDSA_P256_sign", |b| {
        b.iter(|| {
            EcdsaCrypto::sign(black_box(message), black_box(ecdsa_keypair.signing_key())).unwrap()
        })
    });
    
    let ecdsa_signature = EcdsaCrypto::sign(message, ecdsa_keypair.signing_key()).unwrap();
    group.bench_function("ECDSA_P256_verify", |b| {
        b.iter(|| {
            EcdsaCrypto::verify(
                black_box(message),
                black_box(&ecdsa_signature),
                black_box(ecdsa_keypair.verifying_key())
            ).unwrap()
        })
    });
    
    group.finish();
}

fn key_derivation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    
    let password = b"benchmark_password";
    let salt = SecureRandom::generate_salt().unwrap();
    
    group.bench_function("Argon2_derive_32bytes", |b| {
        b.iter(|| {
            Argon2Kdf::derive_key(black_box(password), black_box(&salt), black_box(32)).unwrap()
        })
    });
    
    group.bench_function("PBKDF2_SHA256_100k_32bytes", |b| {
        b.iter(|| {
            Pbkdf2Kdf::derive_sha256(black_box(password), black_box(&salt), black_box(100_000), black_box(32)).unwrap()
        })
    });
    
    group.bench_function("HKDF_SHA256_32bytes", |b| {
        b.iter(|| {
            HkdfKdf::derive_sha256(black_box(password), Some(black_box(&salt)), black_box(b"context"), black_box(32)).unwrap()
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    symmetric_encryption_benchmark,
    hashing_benchmark,
    signature_benchmark,
    key_derivation_benchmark
);
criterion_main!(benches);
