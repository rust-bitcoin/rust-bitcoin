// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin::blockdata::witness::Witness;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_witness(c: &mut Criterion) {
    let mut g = c.benchmark_group("witness");

    g.bench_function(BenchmarkId::new("to_vec", "big"), |b| {
        let raw_witness = [[1u8]; 5];
        let witness = Witness::from_slice(&raw_witness);
        b.iter(|| {
            black_box(witness.to_vec());
        });
    });

    g.bench_function(BenchmarkId::new("to_vec", "small"), |b| {
        let raw_witness = vec![vec![1u8]; 3];
        let witness = Witness::from_slice(&raw_witness);
        b.iter(|| {
            black_box(witness.to_vec());
        });
    });

    g.finish();
}

criterion_group!(benches, bench_witness);
criterion_main!(benches);
