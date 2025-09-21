// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin_hashes::{siphash24, HashEngine};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn bench_siphash24(c: &mut Criterion) {
    let mut g = c.benchmark_group("siphash24");

    for &size in &[1024usize, 65536] {
        let mut engine = siphash24::HashEngine::with_keys(0, 0);
        let bytes = vec![1u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("engine_input", size), |b| {
            b.iter(|| {
                engine.input(black_box(&bytes));
            });
        });
    }

    // Hash-with-keys and to_u64 variants
    let k0 = 0x_07_06_05_04_03_02_01_00;
    let k1 = 0x_0f_0e_0d_0c_0b_0a_09_08;
    let bytes = vec![1u8; 1024];
    g.throughput(Throughput::Bytes(bytes.len() as u64));
    g.bench_function("hash_with_keys/1k", |b| {
        b.iter(|| {
            let _ = siphash24::Hash::hash_with_keys(k0, k1, black_box(&bytes));
        });
    });
    g.bench_function("hash_to_u64_with_keys/1k", |b| {
        b.iter(|| {
            let _ = siphash24::Hash::hash_to_u64_with_keys(k0, k1, black_box(&bytes));
        });
    });

    g.finish();
}

criterion_group!(benches, bench_siphash24);
criterion_main!(benches);
