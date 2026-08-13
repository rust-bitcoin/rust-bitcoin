// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use base58ck::Base58CkString;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_encode_check(c: &mut Criterion) {
    let mut g = c.benchmark_group("base58ck");

    g.bench_function(BenchmarkId::new("encode_check", "50_bytes"), |b| {
        let data: Vec<u8> = (0u8..50).collect();
        b.iter(|| {
            let r = Base58CkString::encode_unbounded(black_box(&data));
            black_box(r.as_str());
        });
    });

    g.bench_function(BenchmarkId::new("encode_check", "xpub_78_bytes"), |b| {
        let data: Vec<u8> = (0u8..78).collect(); // length of xpub
        b.iter(|| {
            let r = Base58CkString::encode_unbounded(black_box(&data));
            black_box(r.as_str());
        });
    });

    g.finish();
}

criterion_group!(benches, bench_encode_check);
criterion_main!(benches);
