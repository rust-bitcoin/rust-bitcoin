//! Fuzz target comparing consensus encoding between bitcoin 0.32 and master.
//!
//! This fuzz target compares the consensus encoding produced by `bitcoin_consensus_encoding::encode_to_vec`
//! in master branch with `bitcoin::consensus::encode::serialize` from bitcoin 0.32 for all shared types.

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use honggfuzz::fuzz;

/// Helper macro to compare encoding between old and new implementations for a type.
///
/// Takes raw bytes, deserialises using the old bitcoin crate, then encodes with both
/// implementations and compares the results.
macro_rules! compare_encoding {
    // Simple path for top-level types
    ($data:expr, $ty:ident) => {
        compare_encoding!($data, bitcoin::$ty, old_bitcoin::$ty);
    };

    // Types in submodules need this because we can't easily concatenate crate prefixes.
    ($data:expr, $new_ty:ty, $old_ty:ty) => {{
        // Try to deserialise using both bitcoin crates. Skip if it can't be deserialised
        let old_result: Result<$old_ty, _> = old_bitcoin::consensus::encode::deserialize($data);
        let new_result: Result<$new_ty, _> = decode_from_slice($data);

        match (old_result, new_result) {
            (Ok(old_obj), Ok(new_obj)) => {
                // Encode with both the old and consensus_encoding implementations
                let old_encoded = old_bitcoin::consensus::encode::serialize(&old_obj);
                let new_encoded = encode_to_vec(&new_obj);
                assert_eq!(old_encoded, new_encoded);
            },
            (Ok(old_obj), _) => {
                panic!("Decoded with old decoder only: {:?}, {:?}", $data, old_obj);
            },
            (_, Ok(new_obj)) => {
                panic!("Decoded with new decoder only: {:?}, {:?}", $data, new_obj);
            },
            (_, _) => {}
        }
    }};
}

fn do_test(data: &[u8]) {
    compare_encoding!(data, Block);
    compare_encoding!(data, Transaction);
    compare_encoding!(data, TxIn);
    compare_encoding!(data, TxOut);
    compare_encoding!(data, OutPoint);
    compare_encoding!(data, Witness);
    compare_encoding!(data, Sequence);
    compare_encoding!(data, Amount);
    compare_encoding!(data, CompactTarget);
    compare_encoding!(data, BlockHash);
    compare_encoding!(data, TxMerkleNode);
    compare_encoding!(data, WitnessMerkleNode);

    compare_encoding!(data, bitcoin::block::Header, old_bitcoin::block::Header);
    compare_encoding!(data, bitcoin::absolute::LockTime, old_bitcoin::absolute::LockTime);
    compare_encoding!(data, bitcoin::block::Version, old_bitcoin::block::Version);
    compare_encoding!(data, bitcoin::transaction::Version, old_bitcoin::transaction::Version);

    // P2P types
    compare_encoding!(data, p2p::address::AddrV2, old_bitcoin::p2p::address::AddrV2);
    compare_encoding!(data, p2p::ServiceFlags, old_bitcoin::p2p::ServiceFlags);
    compare_encoding!(data, p2p::bip152::BlockTransactionsRequest, old_bitcoin::bip152::BlockTransactionsRequest);
    compare_encoding!(data, p2p::message::CommandString, old_bitcoin::p2p::message::CommandString);
    compare_encoding!(data, p2p::message::RawNetworkMessage, old_bitcoin::p2p::message::RawNetworkMessage);
    compare_encoding!(data, p2p::message_blockdata::Inventory, old_bitcoin::p2p::message_blockdata::Inventory);
    compare_encoding!(data, p2p::message_blockdata::GetBlocksMessage, old_bitcoin::p2p::message_blockdata::GetBlocksMessage);
    compare_encoding!(data, p2p::message_blockdata::GetHeadersMessage, old_bitcoin::p2p::message_blockdata::GetHeadersMessage);
    compare_encoding!(data, p2p::message_bloom::FilterAdd, old_bitcoin::p2p::message_bloom::FilterAdd);
    compare_encoding!(data, p2p::message_bloom::FilterLoad, old_bitcoin::p2p::message_bloom::FilterLoad);
    compare_encoding!(data, p2p::message_bloom::BloomFlags, old_bitcoin::p2p::message_bloom::BloomFlags);
    compare_encoding!(data, p2p::message_filter::CFHeaders, old_bitcoin::p2p::message_filter::CFHeaders);
    compare_encoding!(data, p2p::message_filter::CFilter, old_bitcoin::p2p::message_filter::CFilter);
    compare_encoding!(data, p2p::message_filter::CFCheckpt, old_bitcoin::p2p::message_filter::CFCheckpt);
    compare_encoding!(data, p2p::message_filter::GetCFCheckpt, old_bitcoin::p2p::message_filter::GetCFCheckpt);
    compare_encoding!(data, p2p::message_filter::GetCFHeaders, old_bitcoin::p2p::message_filter::GetCFHeaders);
    compare_encoding!(data, p2p::message_filter::GetCFilters, old_bitcoin::p2p::message_filter::GetCFilters);
    compare_encoding!(data, p2p::message_filter::FilterHash, old_bitcoin::bip158::FilterHash);
    compare_encoding!(data, p2p::message_filter::FilterHeader, old_bitcoin::bip158::FilterHeader);
    compare_encoding!(data, p2p::message_network::Reject, old_bitcoin::p2p::message_network::Reject);
    compare_encoding!(data, p2p::message_network::RejectReason, old_bitcoin::p2p::message_network::RejectReason);

}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00003cb1133bb113", &mut a);
        super::do_test(&a);
    }
}
