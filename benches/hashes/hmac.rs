// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin_hashes::{sha256, HashEngine as _, HmacEngine};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn bench_hmac(c: &mut Criterion) {
    let mut g = c.benchmark_group("hmac_sha256");

    for &size in &[10usize, 1024, 65536] {
        let mut engine = HmacEngine::<sha256::HashEngine>::new(&[]);
        let bytes = vec![1u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("engine_input", size), |b| {
            b.iter(|| {
                engine.input(black_box(&bytes));
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench_hmac);
criterion_main!(benches);
