// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin::blockdata::witness::{Witness, WitnessDecoder};
use bitcoin::consensus::encode;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use encoding::{decode_from_slice, Decoder as _};

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

    // Many small elements (100 and 1000).
    for count in [100, 1000] {
        let witness = Witness::from_slice(&vec![vec![0u8; 4]; count]);
        let bytes = encode::serialize(&witness);
        g.bench_with_input(BenchmarkId::new("many_elements", count), &bytes, |b, bytes| {
            b.iter(|| black_box(decode_from_slice::<Witness>(bytes).unwrap()));
        });
    }

    // Single element of different sizes.
    for size in [64, 256, 1024, 2048, 4096] {
        let witness = Witness::from_slice(&[vec![0u8; size]]);
        let bytes = encode::serialize(&witness);
        g.bench_with_input(BenchmarkId::new("one_element", size), &bytes, |b, bytes| {
            b.iter(|| black_box(decode_from_slice::<Witness>(bytes).unwrap()));
        });
    }

    // 64 KB element fed in different chunk sizes.
    let witness = Witness::from_slice(&[vec![0u8; 65536]]);
    let bytes = encode::serialize(&witness);
    for chunk in [1, 64, 256, 1024, 4096] {
        g.bench_with_input(BenchmarkId::new("chunk_64kb", chunk), &bytes, |b, bytes| {
            b.iter(|| black_box(decode_chunked(bytes, chunk)));
        });
    }

    g.finish();
}

fn decode_chunked(bytes: &[u8], chunk: usize) -> Witness {
    let mut decoder = WitnessDecoder::new();
    for piece in bytes.chunks(chunk) {
        let mut slice = piece;
        decoder.push_bytes(&mut slice).unwrap();
    }
    decoder.end().unwrap()
}

criterion_group!(benches, bench_witness);
criterion_main!(benches);
