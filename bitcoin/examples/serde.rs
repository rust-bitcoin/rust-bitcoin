//! Serializing with `serde` and `consensus::{Encodable, Decodable}`
//!
//! All types that implement consensus encoding traits can be serde de/serialized.
//! For integer types that can have multiple units we typically provide a few different modules.

use bitcoin::block::{Header, Version};
use bitcoin::consensus::serde::Hex;
use bitcoin::consensus::{self};
use bitcoin::{
    amount, fee_rate, Amount, BlockHash, BlockTime, CompactTarget, FeeRate, TxMerkleNode,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Foo {
    /// Consensus encoded into hex is often the best option.
    #[serde(with = "consensus::serde::With::<Hex>")]
    header: Header,

    /// This works but it's little-endian which may be hard to read.
    ///
    /// Integer wrapper types are more readable if the explicitly use a unit.
    #[serde(with = "consensus::serde::With::<Hex>")]
    this: Amount,

    /// `Amount` can use sats or bitcoin (`as_btc`).
    #[serde(with = "amount::serde::as_sat")]
    that: Amount,

    /// `FeeRate` can use kilo weight units or virtual bytes, both floor and ceil.
    #[serde(with = "fee_rate::serde::as_sat_per_kwu_floor")]
    fee_rate: FeeRate,
}

fn main() {
    let f = Foo {
        header: dummy_header(),
        this: Amount::ONE_SAT,
        that: Amount::ONE_BTC,
        fee_rate: FeeRate::DUST,
    };

    let s = serde_json::to_string(&f).unwrap();
    println!("{s}");

    let deser = serde_json::from_str::<Foo>(&s).unwrap();
    assert_eq!(deser, f);
}

fn dummy_header() -> Header {
    Header {
        version: Version::ONE,
        prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0x77; 32]),
        time: BlockTime::from(2),
        bits: CompactTarget::from_consensus(3),
        nonce: 4,
    }
}
