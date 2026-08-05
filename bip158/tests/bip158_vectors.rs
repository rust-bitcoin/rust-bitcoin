use std::convert::Infallible;
use std::str::FromStr;

use bitcoin_bip158::{BasicFilter, FilterHeader};
use primitives::{Block, BlockHash, BlockUnchecked, ScriptPubKeyBuf};
use serde_json::Value;

// Official BIP-0158 vectors:
// https://raw.githubusercontent.com/bitcoin/bips/master/bip-0158/testnet-19.json
// SHA256: d9049756f744e561b882a8eff507582fb7cd74ed9cf5542bdac58257449ee2a2
const VECTORS: &str = include_str!("data/testnet-19.json");

#[test]
fn bip0158_testnet_vectors() {
    let rows = serde_json::from_str::<Vec<Value>>(VECTORS).expect("valid checked-in JSON");
    assert_eq!(rows.len() - 1, 10, "unexpected number of official vectors");

    for row in rows.iter().skip(1) {
        let fields = row.as_array().expect("vector row is an array");
        let height = fields[0].as_u64().unwrap();
        let context = format!("testnet block at height {}", height);

        let raw_block = hex::decode_to_vec(fields[2].as_str().unwrap()).unwrap();
        let unchecked: Block<BlockUnchecked> = encoding::decode_from_slice(&raw_block)
            .unwrap_or_else(|e| panic!("failed to decode {}: {}", context, e));
        let block = unchecked
            .validate()
            .unwrap_or_else(|e| panic!("failed to validate {}: {}", context, e));

        let expected_block_hash = BlockHash::from_str(fields[1].as_str().unwrap()).unwrap();
        assert_eq!(block.block_hash(), expected_block_hash, "{}", context);

        let scripts = fields[3].as_array().unwrap();
        let mut scripts = scripts.iter().map(|script| {
            ScriptPubKeyBuf::from_bytes(hex::decode_to_vec(script.as_str().unwrap()).unwrap())
        });
        let filter = BasicFilter::from_block(&block, |_| {
            Ok::<_, Infallible>(scripts.next().expect("missing prevout script in vector"))
        })
        .unwrap();
        assert!(scripts.next().is_none(), "unused prevout script in {}", context);

        let expected_filter = hex::decode_to_vec(fields[5].as_str().unwrap()).unwrap();
        assert_eq!(filter.as_bytes(), expected_filter, "{}", context);
        let parsed_filter = BasicFilter::from_bytes(expected_filter)
            .unwrap_or_else(|e| panic!("failed to parse filter for {}: {}", context, e));

        let previous_header = FilterHeader::from_str(fields[4].as_str().unwrap()).unwrap();
        let expected_header = FilterHeader::from_str(fields[6].as_str().unwrap()).unwrap();
        assert_eq!(
            filter.filter_hash().filter_header(previous_header),
            expected_header,
            "{}",
            context
        );
        assert_eq!(
            parsed_filter.filter_hash().filter_header(previous_header),
            expected_header,
            "parsed filter for {}",
            context
        );
    }
}
