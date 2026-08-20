#[cfg(feature = "alloc")]
use core::convert::Infallible;

use bitcoin_bip158::{BasicFilter, FilterHeader};
#[cfg(feature = "alloc")]
use primitives::{Block, BlockHash, BlockUnchecked, ScriptPubKeyBuf};
use serde_json::Value;

// Official BIP-0158 vectors:
// https://raw.githubusercontent.com/bitcoin/bips/master/bip-0158/testnet-19.json
// SHA256: d9049756f744e561b882a8eff507582fb7cd74ed9cf5542bdac58257449ee2a2
const VECTORS: &str = include_str!("data/testnet-19.json");

fn decode_hash(s: &str) -> [u8; 32] {
    let mut bytes: [u8; 32] = hex::decode_to_array(s).unwrap();
    bytes.reverse();
    bytes
}

#[test]
fn bip0158_testnet_vectors() {
    let rows = serde_json::from_str::<Vec<Value>>(VECTORS).expect("valid checked-in JSON");

    for row in rows.iter().skip(1) {
        let fields = row.as_array().expect("vector row is an array");
        let height = fields[0].as_u64().unwrap();
        let context = format!("testnet block at height {}", height);

        let expected_filter = hex::decode_to_vec(fields[5].as_str().unwrap()).unwrap();
        let parsed_filter = BasicFilter::from_bytes(expected_filter.as_slice())
            .unwrap_or_else(|e| panic!("failed to parse filter for {}: {}", context, e));

        let previous_header =
            FilterHeader::from_byte_array(decode_hash(fields[4].as_str().unwrap()));
        let expected_header =
            FilterHeader::from_byte_array(decode_hash(fields[6].as_str().unwrap()));
        assert_eq!(
            parsed_filter.filter_hash().filter_header(previous_header),
            expected_header,
            "parsed filter for {}",
            context
        );

        #[cfg(feature = "alloc")]
        {
            let raw_block = hex::decode_to_vec(fields[2].as_str().unwrap()).unwrap();
            let unchecked: Block<BlockUnchecked> = encoding::decode_from_slice(&raw_block)
                .unwrap_or_else(|e| panic!("failed to decode {}: {}", context, e));
            let block = unchecked
                .validate()
                .unwrap_or_else(|e| panic!("failed to validate {}: {}", context, e));

            let expected_block_hash =
                BlockHash::from_byte_array(decode_hash(fields[1].as_str().unwrap()));
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

            assert_eq!(filter.as_bytes(), expected_filter, "{}", context);
            assert_eq!(
                filter.filter_hash().filter_header(previous_header),
                expected_header,
                "{}",
                context
            );
        }
    }
}
