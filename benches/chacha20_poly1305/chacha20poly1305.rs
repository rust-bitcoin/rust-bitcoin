// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut g = c.benchmark_group("chacha20poly1305");
    g.measurement_time(Duration::from_secs(5)).warm_up_time(Duration::from_secs(2));

    for &size in &[128usize, 1024, 16 * 1024, 64 * 1024] {
        let key = Key::new([0u8; 32]);
        let nonce = Nonce::new([0u8; 12]);

        let pt = vec![0u8; size];
        let aad: &[u8] = b"dummy_aad";

        g.throughput(Throughput::Bytes(size as u64));

        g.bench_function(BenchmarkId::new("encrypt_no_aad", size), |b| {
            b.iter(|| {
                let mut buf = pt.clone();
                let cipher = ChaCha20Poly1305::new(key, nonce);
                let tag = cipher.encrypt(black_box(&mut buf), None);
                black_box(tag);
            });
        });

        g.bench_function(BenchmarkId::new("encrypt_with_aad", size), |b| {
            b.iter(|| {
                let mut buf = pt.clone();
                let cipher = ChaCha20Poly1305::new(key, nonce);
                let tag = cipher.encrypt(black_box(&mut buf), Some(aad));
                black_box(tag);
            });
        });

        let mut ct = pt.clone();
        let tag = ChaCha20Poly1305::new(key, nonce).encrypt(&mut ct, Some(aad));

        g.bench_function(BenchmarkId::new("decrypt_ok", size), |b| {
            b.iter(|| {
                let mut buf = ct.clone();
                let cipher = ChaCha20Poly1305::new(key, nonce);
                let res = cipher.decrypt(black_box(&mut buf), tag, Some(aad));
                res.unwrap();
                black_box(());
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);
