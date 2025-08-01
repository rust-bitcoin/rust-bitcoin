// SPDX-License-Identifier: CC0-1.0

//! Consensus encoding tests that use types defined in this crate.

use core::{fmt, mem};

use super::*;
use crate::bip158::FilterHash;
use crate::block::BlockHash;
use crate::merkle_tree::TxMerkleNode;
use crate::prelude::Vec;
use crate::transaction::{Transaction, TxIn, TxOut};

#[test]
fn deserialize_vec() {
    assert_eq!(deserialize(&[3u8, 2, 3, 4]).ok(), Some(vec![2u8, 3, 4]));
    assert!((deserialize(&[4u8, 2, 3, 4, 5, 6]) as Result<Vec<u8>, _>).is_err());
    // found by cargo fuzz
    assert!(deserialize::<Vec<u64>>(&[
        0xff, 0xff, 0xff, 0xff, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
        0x6b, 0xa, 0xa, 0x3a
    ])
    .is_err());

    // Check serialization that `if len > MAX_VEC_SIZE {return err}` isn't inclusive,
    // by making sure it fails with `MissingData` and not an `OversizedVectorAllocation` Error.
    let err = deserialize::<BlockHash>(&serialize(&(super::MAX_VEC_SIZE as u32))).unwrap_err();
    assert_eq!(err, DeserializeError::Parse(ParseError::MissingData));

    test_len_is_max_vec::<u8>();
    test_len_is_max_vec::<BlockHash>();
    test_len_is_max_vec::<FilterHash>();
    test_len_is_max_vec::<TxMerkleNode>();
    test_len_is_max_vec::<Transaction>();
    test_len_is_max_vec::<TxOut>();
    test_len_is_max_vec::<TxIn>();
    test_len_is_max_vec::<Vec<u8>>();
    test_len_is_max_vec::<u64>();
}

fn test_len_is_max_vec<T>()
where
    Vec<T>: Decodable,
    T: fmt::Debug,
{
    let mut buf = Vec::new();
    buf.emit_compact_size(super::MAX_VEC_SIZE / mem::size_of::<T>()).unwrap();
    let err = deserialize::<Vec<T>>(&buf).unwrap_err();
    assert_eq!(err, DeserializeError::Parse(ParseError::MissingData));
}

#[test]
fn deserialize_tx_hex() {
    let hex = include_str!("../../tests/data/previous_tx_0_hex"); // An arbitrary transaction.
    assert!(deserialize_hex::<Transaction>(hex).is_ok())
}

#[test]
fn deserialize_tx_hex_too_many_bytes() {
    use crate::consensus::DecodeError;

    let mut hex = include_str!("../../tests/data/previous_tx_0_hex").to_string(); // An arbitrary transaction.
    hex.push_str("abcdef");
    assert!(matches!(
        deserialize_hex::<Transaction>(&hex).unwrap_err(),
        FromHexError::Decode(DecodeError::Unconsumed)
    ));
}
