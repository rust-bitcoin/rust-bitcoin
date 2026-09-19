// SPDX-License-Identifier: CC0-1.0

use std::convert::Infallible;
use std::hint::black_box;

use bitcoin::absolute::LockTime;
use bitcoin::bip158::BlockFilter;
use bitcoin::block::{Block, Header, Version as BlockVersion};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version as TransactionVersion};
use bitcoin::{
    Amount, BlockChecked, BlockHash, BlockTime, CompactTarget, ScriptPubKeyBuf, ScriptSigBuf,
    Sequence, TxMerkleNode, Txid, Witness,
};
use bitcoin_bip158::BasicFilter;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

struct Fixture {
    block: Block<BlockChecked>,
    prevouts: Vec<ScriptPubKeyBuf>,
    elements: Vec<ScriptPubKeyBuf>,
}

impl Fixture {
    fn new(element_count: usize) -> Self {
        let output_count = element_count / 2;
        let outputs = (0..output_count)
            .map(|index| TxOut { amount: Amount::ZERO, script_pubkey: script(0, index) })
            .collect::<Vec<_>>();
        let prevouts =
            (output_count..element_count).map(|index| script(1, index)).collect::<Vec<_>>();

        let coinbase = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::COINBASE_PREVOUT,
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs,
        };
        let spending = Transaction {
            version: TransactionVersion::TWO,
            lock_time: LockTime::ZERO,
            inputs: (0..element_count - output_count)
                .map(|index| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([0; 32]),
                        vout: index as u32,
                    },
                    script_sig: ScriptSigBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: Vec::new(),
        };
        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(0),
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let block = Block::new_unchecked(header, vec![coinbase, spending]).assume_checked(None);
        let elements = block.transactions()[0]
            .outputs
            .iter()
            .map(|output| output.script_pubkey.clone())
            .chain(prevouts.iter().cloned())
            .collect();
        Self { block, prevouts, elements }
    }

    fn basic_filter(&self) -> BasicFilter {
        BasicFilter::from_block(&self.block, |outpoint| {
            Ok::<_, Infallible>(&self.prevouts[outpoint.vout as usize])
        })
        .unwrap()
    }

    fn block_filter(&self) -> BlockFilter {
        BlockFilter::new_script_filter(&self.block, |outpoint| {
            Ok(self.prevouts[outpoint.vout as usize].as_script())
        })
        .unwrap()
    }
}

fn script(domain: u8, index: usize) -> ScriptPubKeyBuf {
    let mut bytes = Vec::with_capacity(9);
    bytes.push(domain);
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    ScriptPubKeyBuf::from_bytes(bytes)
}

fn missing_queries(
    filter: &BasicFilter,
    block_hash: BlockHash,
    count: usize,
) -> Vec<ScriptPubKeyBuf> {
    (0..)
        .map(|index| script(2, index))
        .filter(|candidate| !filter.match_any(block_hash, [candidate.as_bytes()]))
        .take(count)
        .collect()
}

fn bench_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitcoin_bip158/query");

    for element_count in [100, 1_000, 10_000] {
        let fixture = Fixture::new(element_count);
        let block_hash = fixture.block.block_hash();
        let basic_filter = fixture.basic_filter();
        let block_filter = fixture.block_filter();
        assert_eq!(basic_filter.as_bytes(), block_filter.content);
        let misses = missing_queries(&basic_filter, block_hash, *[1, 10, 100].last().unwrap());

        for query_count in [1, 10, 100] {
            let members = &fixture.elements[..query_count];
            let misses = &misses[..query_count];
            let parameter = format!("{}-elements/{}-queries", element_count, query_count);
            group.throughput(Throughput::Elements(query_count as u64));

            group.bench_function(
                BenchmarkId::new("basic_filter_match_any_miss", &parameter),
                |b| {
                    b.iter(|| {
                        black_box(basic_filter.match_any(
                            block_hash,
                            black_box(misses).iter().map(|script| script.as_bytes()),
                        ))
                    })
                },
            );

            group.bench_function(
                BenchmarkId::new("block_filter_match_any_miss", &parameter),
                |b| {
                    b.iter(|| {
                        black_box(
                            block_filter
                                .match_any(
                                    block_hash,
                                    black_box(misses).iter().map(|script| script.as_bytes()),
                                )
                                .unwrap(),
                        )
                    })
                },
            );

            group.bench_function(BenchmarkId::new("basic_filter_match_all_hit", &parameter), |b| {
                b.iter(|| {
                    black_box(basic_filter.match_all(
                        block_hash,
                        black_box(members).iter().map(|script| script.as_bytes()),
                    ))
                })
            });

            group.bench_function(BenchmarkId::new("block_filter_match_all_hit", &parameter), |b| {
                b.iter(|| {
                    black_box(
                        block_filter
                            .match_all(
                                block_hash,
                                black_box(members).iter().map(|script| script.as_bytes()),
                            )
                            .unwrap(),
                    )
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_queries);
criterion_main!(benches);
