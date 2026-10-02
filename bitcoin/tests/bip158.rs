//! Tests for BIP158 block filters. Data lives in `tests/data`, which is excluded when publishing.

#![cfg(feature = "std")]

use std::collections::HashMap;

use bitcoin::bip158::{BlockFilter, Error};
use bitcoin::{Block, BlockHash, ScriptPubKeyBuf};
use encoding::decode_from_slice;
use serde_json::Value;

#[test]
fn blockfilters() {
    let hex = |b| hex::decode_to_vec(b).unwrap();

    // test vectors from: https://github.com/jimpo/bitcoin/blob/c7efb652f3543b001b4dd22186a354605b14f47e/src/test/data/blockfilters.json
    let data = include_str!("data/blockfilters.json");

    let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
    for t in testdata.iter().skip(1) {
        let block_hash = t.get(1).unwrap().as_str().unwrap().parse::<BlockHash>().unwrap();
        let block: Block = decode_from_slice(&hex(t.get(2).unwrap().as_str().unwrap())).unwrap();
        let block = block.assume_checked(None);
        assert_eq!(block.block_hash(), block_hash);
        let scripts = t.get(3).unwrap().as_array().unwrap();
        let filter_content = hex(t.get(5).unwrap().as_str().unwrap());

        let mut txmap = HashMap::new();
        let mut si = scripts.iter();
        for tx in block.transactions().iter().skip(1) {
            for input in &tx.inputs {
                txmap.insert(
                    input.previous_output,
                    ScriptPubKeyBuf::from(hex(si.next().unwrap().as_str().unwrap())),
                );
            }
        }

        let filter = BlockFilter::new_script_filter(&block, |o| {
            txmap.get(o).map_or_else(|| Err(Error::UtxoMissing(*o)), |s| Ok(s.clone()))
        })
        .unwrap();

        let test_filter = BlockFilter::new(filter_content.as_slice());

        assert_eq!(test_filter.content, filter.content);

        let block_hash = &block.block_hash();
        assert!(filter
            .match_all(
                *block_hash,
                &mut txmap.values().filter_map(|s| (!s.is_empty()).then_some(s.as_bytes()))
            )
            .unwrap());

        for script in txmap.values() {
            let query = [script];
            if !script.is_empty() {
                assert!(filter
                    .match_any(*block_hash, &mut query.iter().map(|s| s.as_bytes()))
                    .unwrap());
            }
        }
    }
}
