// SPDX-License-Identifier: CC0-1.0

use std::time::Duration;
use std::hint::black_box;

use bitcoin::block::Header;
use bitcoin::blockdata::block::Block;
use bitcoin::consensus::{deserialize, serialize, Decodable, Encodable};
use bitcoin::io::sink;
use bitcoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, BlockTime, CompactTarget, Sequence, TxMerkleNode, Witness};
use encoding::decode_from_slice;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};


fn build_test_block(num_tx: usize) -> Vec<u8> {
    let mut txs = Vec::with_capacity(num_tx);

    // Coinbase
    txs.push(Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::from_bytes(vec![0x04, 0x01, 0x00, 0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut { amount: Amount::from_sat(5_000_000_000).unwrap(), script_pubkey: ScriptPubKeyBuf::new() }],
    });

    // Chain: each tx spends the previous
    for i in 1..num_tx {
        txs.push(Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: txs[i - 1].compute_txid(), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut { amount: Amount::from_sat_u32(1000), script_pubkey: ScriptPubKeyBuf::new() }],
        });
    }

    let header = Header {
        version: bitcoin::block::Version::from_consensus(1),
        prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0; 32]),
        time: BlockTime::from_u32(0),
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };

    serialize(&Block::new_unchecked(header, txs))
}

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

fn bench_decode_and_validate(c: &mut Criterion) {
    let raw_block = include_bytes!("../../bitcoin/tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

    let mut g = c.benchmark_group("decode_and_validate");
    g.measurement_time(Duration::from_secs(10)).warm_up_time(Duration::from_secs(3));

    g.bench_function(BenchmarkId::new("decode", "2500tx"), |b| {
        b.iter(|| {
            let blk: Block = decode_from_slice(&raw_block[..]).unwrap();
            black_box(blk);
        });
    });

    g.bench_function(BenchmarkId::new("decode_then_validate", "2500tx"), |b| {
        b.iter(|| {
            let blk: Block = decode_from_slice(&raw_block[..]).unwrap();
            black_box(blk.validate())
        });
    });

    g.finish();
}

fn bench_large_block(c: &mut Criterion) {
    let mut g = c.benchmark_group("large_block");
    g.measurement_time(Duration::from_secs(15)).warm_up_time(Duration::from_secs(3));

    for num_tx in [1000, 10000, 64000] {
        let raw_block = build_test_block(num_tx);

        g.bench_function(BenchmarkId::new("decode", format!("{}tx", num_tx)), |b| {
            b.iter(|| {
                let blk: Block = decode_from_slice(&raw_block[..]).unwrap();
                black_box(blk);
            });
        });

        g.bench_function(BenchmarkId::new("decode_then_validate", format!("{}tx", num_tx)), |b| {
            b.iter(|| {
                let blk: Block = decode_from_slice(&raw_block[..]).unwrap();
                black_box(blk.validate())
            });
        });
    }

    g.finish();
}

criterion_group!(benches, bench_block, bench_decode_and_validate, bench_large_block);
criterion_main!(benches);
