// SPDX-License-Identifier: CC0-1.0

use std::hint::black_box;

use bitcoin::{Txid, TxMerkleNode};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn make_leaves(count: usize) -> Vec<Txid> {
    (0..count as u32)
        .map(|i| {
            let mut buf = [0u8; 32];
            buf[..4].copy_from_slice(&i.to_le_bytes());
            Txid::from_byte_array(buf)
        })
        .collect()
}

fn bench_merkle_root_computation(c: &mut Criterion) {
    let mut g = c.benchmark_group("merkle_root");

    for &size in &[1000, 1001, 9000, 9001, 64000] {
        let leaves = make_leaves(size);

        g.throughput(Throughput::Elements(size as u64));
        g.bench_function(BenchmarkId::new("compute", size), |b| {
            b.iter(|| black_box(TxMerkleNode::calculate_root(leaves.iter().copied())));
        });
    }

    g.finish();
}

criterion_group!(benches, bench_merkle_root_computation);
criterion_main!(benches);
