// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::transaction::TransactionExt as _; // for total_size()
use bitcoin::consensus::{encode, Encodable};
use bitcoin::io::sink;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const SOME_TX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

fn bench_tx(c: &mut Criterion) {
    let mut g = c.benchmark_group("transaction");

    g.bench_function(BenchmarkId::new("size", "some"), |b| {
        let mut tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
        b.iter(|| {
            black_box(black_box(&mut tx).total_size());
        });
    });

    g.bench_function(BenchmarkId::new("serialize", "some"), |b| {
        let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
        let mut data = Vec::with_capacity(SOME_TX.len() / 2);
        b.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    });

    g.bench_function(BenchmarkId::new("serialize_logic", "some"), |b| {
        let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
        b.iter(|| {
            let size = tx.consensus_encode(&mut sink());
            let _ = black_box(size);
        });
    });

    g.bench_function(BenchmarkId::new("deserialize", "raw_bytes"), |b| {
        let raw_tx = hex_lit::hex!(SOME_TX);
        b.iter(|| {
            let tx: Transaction = encode::deserialize(&raw_tx).unwrap();
            black_box(tx);
        });
    });

    g.bench_function(BenchmarkId::new("deserialize_hex", "string"), |b| {
        b.iter(|| {
            let tx: Transaction = encode::deserialize_hex(SOME_TX).unwrap();
            black_box(tx);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_tx);
criterion_main!(benches);
