use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use libsilver::prelude::*;
use std::time::Duration;

fn aes_encryption_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES_Encryption_Comparison");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    // Test different data sizes: 64B, 1KB, 4KB, 16KB, 64KB, 256KB, 1MB
    let data_sizes = [64, 1024, 4096, 16384, 65536, 262144, 1048576];
    
    for size in data_sizes.iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        // RustCrypto AES-GCM Encryption
        let rustcrypto_key = AesGcm::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("RustCrypto_AES_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::encrypt(black_box(&data), black_box(&rustcrypto_key)).unwrap()
                })
            },
        );
        
        // AWS-LC-RS AES-GCM Encryption
        let aws_lc_key = AwsLcAesGcm::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("AWS_LC_RS_AES_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AwsLcAesGcm::encrypt(black_box(&data), black_box(&aws_lc_key)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn aes_decryption_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES_Decryption_Comparison");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    
    let data_sizes = [64, 1024, 4096, 16384, 65536, 262144, 1048576];
    
    for size in data_sizes.iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Prepare ciphertexts for decryption benchmarks
        let rustcrypto_key = AesGcm::generate_key().unwrap();
        let rustcrypto_ciphertext = AesGcm::encrypt(&data, &rustcrypto_key).unwrap();
        
        let aws_lc_key = AwsLcAesGcm::generate_key().unwrap();
        let aws_lc_ciphertext = AwsLcAesGcm::encrypt(&data, &aws_lc_key).unwrap();
        
        // RustCrypto AES-GCM Decryption
        group.bench_with_input(
            BenchmarkId::new("RustCrypto_AES_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::decrypt(black_box(&rustcrypto_ciphertext), black_box(&rustcrypto_key)).unwrap()
                })
            },
        );
        
        // AWS-LC-RS AES-GCM Decryption
        group.bench_with_input(
            BenchmarkId::new("AWS_LC_RS_AES_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AwsLcAesGcm::decrypt(black_box(&aws_lc_ciphertext), black_box(&aws_lc_key)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn aes_with_aad_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES_AAD_Comparison");
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(500);
    
    let data_sizes = [1024, 4096, 16384, 65536];
    let aad = b"user_id:12345,session:abc123,timestamp:1640995200";
    
    for size in data_sizes.iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        
        // RustCrypto AES-GCM with AAD
        let rustcrypto_key = AesGcm::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("RustCrypto_AES_AAD_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::encrypt_with_aad(black_box(&data), black_box(&rustcrypto_key), black_box(aad)).unwrap()
                })
            },
        );
        
        // AWS-LC-RS AES-GCM with AAD
        let aws_lc_key = AwsLcAesGcm::generate_key().unwrap();
        group.bench_with_input(
            BenchmarkId::new("AWS_LC_RS_AES_AAD_encrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AwsLcAesGcm::encrypt_with_aad(black_box(&data), black_box(&aws_lc_key), black_box(aad)).unwrap()
                })
            },
        );
        
        // Decryption with AAD
        let rustcrypto_aad_ciphertext = AesGcm::encrypt_with_aad(&data, &rustcrypto_key, aad).unwrap();
        let aws_lc_aad_ciphertext = AwsLcAesGcm::encrypt_with_aad(&data, &aws_lc_key, aad).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("RustCrypto_AES_AAD_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AesGcm::decrypt_with_aad(black_box(&rustcrypto_aad_ciphertext), black_box(&rustcrypto_key), black_box(aad)).unwrap()
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("AWS_LC_RS_AES_AAD_decrypt", size),
            size,
            |b, _| {
                b.iter(|| {
                    AwsLcAesGcm::decrypt_with_aad(black_box(&aws_lc_aad_ciphertext), black_box(&aws_lc_key), black_box(aad)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn key_generation_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES_Key_Generation");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);
    
    group.bench_function("RustCrypto_AES_key_gen", |b| {
        b.iter(|| {
            AesGcm::generate_key().unwrap()
        })
    });
    
    group.bench_function("AWS_LC_RS_AES_key_gen", |b| {
        b.iter(|| {
            AwsLcAesGcm::generate_key().unwrap()
        })
    });
    
    group.finish();
}

fn memory_usage_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES_Memory_Usage_Simulation");
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(100);
    
    // Simulate multiple concurrent operations
    let concurrent_ops = [10, 50, 100];
    
    for ops in concurrent_ops.iter() {
        group.bench_with_input(
            BenchmarkId::new("RustCrypto_AES_concurrent", ops),
            ops,
            |b, ops_count| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(*ops_count);
                    for _ in 0..*ops_count {
                        let key = AesGcm::generate_key().unwrap();
                        let data = vec![0u8; 4096];
                        let ciphertext = AesGcm::encrypt(&data, &key).unwrap();
                        let _decrypted = AesGcm::decrypt(&ciphertext, &key).unwrap();
                        results.push(ciphertext);
                    }
                    black_box(results);
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("AWS_LC_RS_AES_concurrent", ops),
            ops,
            |b, ops_count| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(*ops_count);
                    for _ in 0..*ops_count {
                        let key = AwsLcAesGcm::generate_key().unwrap();
                        let data = vec![0u8; 4096];
                        let ciphertext = AwsLcAesGcm::encrypt(&data, &key).unwrap();
                        let _decrypted = AwsLcAesGcm::decrypt(&ciphertext, &key).unwrap();
                        results.push(ciphertext);
                    }
                    black_box(results);
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    aes_benches,
    aes_encryption_comparison,
    aes_decryption_comparison,
    aes_with_aad_comparison,
    key_generation_comparison,
    memory_usage_simulation
);
criterion_main!(aes_benches);
