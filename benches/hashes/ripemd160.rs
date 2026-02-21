// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin_hashes::{ripemd160, HashEngine};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn bench_ripemd160(c: &mut Criterion) {
    let mut g = c.benchmark_group("ripemd160");

    for &size in &[10usize, 1024, 65536] {
        let bytes = vec![1u8; size];
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(BenchmarkId::new("engine_input", size), |b| {
            b.iter(|| {
                let mut engine = ripemd160::Hash::engine();
                engine.input(black_box(&bytes));
                black_box(engine.finalize());
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench_ripemd160);
criterion_main!(benches);
