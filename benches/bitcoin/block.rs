// SPDX-License-Identifier: CC0-1.0

use std::time::Duration;
use std::hint::black_box;

use bitcoin::blockdata::block::Block;
use bitcoin::consensus::{deserialize, Decodable, Encodable};
use bitcoin::io::sink;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn bench_block(c: &mut Criterion) {
    let raw_block = include_bytes!("../../bitcoin/tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
    assert_eq!(raw_block.len(), 1_381_836);
    let block: Block = deserialize(&raw_block[..]).unwrap();

    let mut g = c.benchmark_group("block");
    g.throughput(Throughput::Bytes(raw_block.len() as u64));
    g.measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(3));

    g.bench_function(BenchmarkId::new("stream_reader", "big"), |b| {
        let big_block = black_box(raw_block.as_ref());
        b.iter(|| {
            let mut reader = big_block;
            let blk = Block::consensus_decode(&mut reader).unwrap();
            black_box(blk);
        });
    });

    g.bench_function(BenchmarkId::new("serialize", "big"), |b| {
        let mut data = Vec::with_capacity(raw_block.len());
        b.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    });

    g.bench_function(BenchmarkId::new("serialize_logic", "big"), |b| {
        b.iter(|| {
            let size = block.consensus_encode(&mut sink());
            let _ = black_box(size);
        });
    });

    g.bench_function(BenchmarkId::new("deserialize", "big"), |b| {
        b.iter(|| {
            let blk: Block = deserialize(&raw_block[..]).unwrap();
            black_box(blk);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_block);
criterion_main!(benches);
