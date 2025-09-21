// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin_hashes::{sha256, sha512};
use bitcoin_hashes::cmp::fixed_time_eq;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_cmp(c: &mut Criterion) {
    let mut g = c.benchmark_group("cmp");

    // 32-byte comparisons
    let a32 = sha256::Hash::hash(&[0; 1]);
    let b32eq = sha256::Hash::hash(&[0; 1]);
    let b32ne = sha256::Hash::hash(&[1; 1]);

    g.bench_function(BenchmarkId::new("ct_eq", 32), |b| {
        b.iter(|| fixed_time_eq(black_box(a32.as_byte_array()), black_box(b32eq.as_byte_array())));
    });
    g.bench_function(BenchmarkId::new("slice_eq", 32), |b| {
        b.iter(|| black_box(a32.as_byte_array() == b32eq.as_byte_array()));
    });
    g.bench_function(BenchmarkId::new("ct_ne", 32), |b| {
        b.iter(|| fixed_time_eq(black_box(a32.as_byte_array()), black_box(b32ne.as_byte_array())));
    });
    g.bench_function(BenchmarkId::new("slice_ne", 32), |b| {
        b.iter(|| black_box(a32.as_byte_array() == b32ne.as_byte_array()));
    });

    // 64-byte comparisons
    let a64 = sha512::Hash::hash(&[0; 1]);
    let b64eq = sha512::Hash::hash(&[0; 1]);
    let b64ne = sha512::Hash::hash(&[1; 1]);

    g.bench_function(BenchmarkId::new("ct_eq", 64), |b| {
        b.iter(|| fixed_time_eq(black_box(a64.as_byte_array()), black_box(b64eq.as_byte_array())));
    });
    g.bench_function(BenchmarkId::new("slice_eq", 64), |b| {
        b.iter(|| black_box(a64.as_byte_array() == b64eq.as_byte_array()));
    });
    g.bench_function(BenchmarkId::new("ct_ne", 64), |b| {
        b.iter(|| fixed_time_eq(black_box(a64.as_byte_array()), black_box(b64ne.as_byte_array())));
    });
    g.bench_function(BenchmarkId::new("slice_ne", 64), |b| {
        b.iter(|| black_box(a64.as_byte_array() == b64ne.as_byte_array()));
    });

    g.finish();
}

criterion_group!(benches, bench_cmp);
criterion_main!(benches);
