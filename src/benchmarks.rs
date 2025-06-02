//! Performance benchmarks for crypto operations

#[cfg(test)]
mod benches {
    use criterion::{black_box, criterion_group, criterion_main, Criterion};
    use rand::RngCore;
    
    fn benchmark_chacha20(c: &mut Criterion) {
        let mut key = [0u8; 32];
        let mut data = vec![0u8; 1024 * 1024]; // 1MB
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut data);
        
        c.bench_function("chacha20_encrypt_1mb", |b| {
            b.iter(|| {
                let _ = crate::crypto::encrypt_chacha20(
                    black_box(&data),
                    black_box(&key)
                );
            })
        });
    }
    
    fn benchmark_ed25519(c: &mut Criterion) {
        let (private_key, _) = crate::crypto::generate_keypair().unwrap();
        let message = b"Test message for benchmarking";
        
        c.bench_function("ed25519_sign", |b| {
            b.iter(|| {
                let _ = crate::crypto::sign_message(
                    black_box(&private_key),
                    black_box(message)
                );
            })
        });
    }
    
    criterion_group!(benches, benchmark_chacha20, benchmark_ed25519);
    criterion_main!(benches);
}
