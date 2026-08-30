#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use core::convert::Infallible;
use std::collections::BTreeSet;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Block, Header, Version as BlockVersion};
use bitcoin::transaction::Version as TransactionVersion;
use bitcoin::{
    Amount, BlockHash, BlockTime, CompactTarget, OutPoint, ScriptPubKeyBuf, ScriptSigBuf, Sequence,
    Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use bitcoin_bip158::BasicFilter;
use bitcoin_consensus_encoding::{CompactSizeEncoder, Encoder};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test((outputs, prevouts): (Vec<ScriptPubKeyBuf>, Vec<ScriptPubKeyBuf>)) {
    let coinbase = Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: outputs
            .iter()
            .cloned()
            .map(|script_pubkey| TxOut { amount: Amount::ZERO, script_pubkey })
            .collect(),
    };
    let spending = Transaction {
        version: TransactionVersion::TWO,
        lock_time: LockTime::ZERO,
        inputs: (0..prevouts.len())
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
    let block_hash = block.block_hash();
    let filter = BasicFilter::from_block(&block, |outpoint| {
        Ok::<_, Infallible>(&*prevouts[outpoint.vout as usize])
    })
    .expect("infallible prevout lookup");

    let reparsed = BasicFilter::from_bytes(filter.as_bytes()).expect("constructed filter is valid");
    assert_eq!(reparsed.as_bytes(), filter.as_bytes());
    assert_eq!(reparsed.filter_hash(), filter.filter_hash());

    let eligible_scripts = outputs
        .iter()
        .filter(|script| !script.is_empty() && !script.is_op_return())
        .chain(prevouts.iter().filter(|script| !script.is_empty()))
        .map(|script| script.as_bytes())
        .collect::<BTreeSet<_>>();
    let expected_count = CompactSizeEncoder::new(eligible_scripts.len());
    assert!(filter.as_bytes().starts_with(expected_count.current_chunk()));

    assert!(filter.match_all(block_hash, eligible_scripts.iter().copied()));
    for script in eligible_scripts {
        assert!(filter.match_any(block_hash, [script]));
    }
}

fuzz_target!(|data: (Vec<ScriptPubKeyBuf>, Vec<ScriptPubKeyBuf>)| {
    do_test(data);
});
