#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

//! Fuzz target comparing consensus encoding between bitcoin 0.32 and master.
//!
//! This fuzz target compares the consensus encoding produced by `bitcoin_consensus_encoding::encode_to_vec`
//! in master branch with `bitcoin::consensus::encode::serialize` from bitcoin 0.32 for all shared types.

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec, Decoder};
use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

/// Walk the `std::error::Error` source chain looking for a known decoder divergence.
///
/// Returns `true` if the error chain contains any of the following known cases where
/// the new decoder is stricter than the old bitcoin 0.32 decoder:
///
/// - `OutOfRangeError`: The new `AmountDecoder` validates the decoded value against
///   `Amount::MAX`; the old decoder accepted any `u64`. Affects all types that encode
///   an `Amount` anywhere in their structure (`TxOut`, `Transaction`, `Block`, …).
///
/// - `CommandStringDecoderError::NotAscii`: The new `CommandString` decoder rejects
///   non-ASCII bytes; the old decoder accepted them silently.
///
/// - `LengthPrefixExceedsMaxError`: The new decoders cap collection lengths at
///   `0x2_000_000`; the old decoders only rejected values above `u64::MAX`.
///
/// - `TransactionDecoderError` with "no outputs": The new `TransactionDecoder` rejects
///   transactions with zero outputs; the old decoder accepted them.
fn is_known_decoder_divergence(err: &(dyn std::error::Error + 'static)) -> bool {
    use bitcoin::blockdata::transaction::TransactionDecoderError;
    use bitcoin_consensus_encoding::LengthPrefixExceedsMaxError;
    use p2p::message::error::CommandStringDecoderError;

    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.downcast_ref::<bitcoin::amount::OutOfRangeError>().is_some() {
            return true;
        }
        if matches!(
            e.downcast_ref::<CommandStringDecoderError>(),
            Some(CommandStringDecoderError::NotAscii)
        ) {
            return true;
        }
        if e.downcast_ref::<LengthPrefixExceedsMaxError>().is_some() {
            return true;
        }
        if e.downcast_ref::<TransactionDecoderError>()
            .is_some_and(|e| e.to_string() == "transaction has no outputs")
        {
            return true;
        }
        current = e.source();
    }
    false
}

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
            }
            (Ok(old_obj), Err(ref err)) =>
                if !is_known_decoder_divergence(err) {
                    panic!("Decoded with old decoder only: {:?}, {:?} {:?}", $data, old_obj, err);
                },
            (Err(err), Ok(new_obj)) => {
                panic!("Decoded with new decoder only: {:?}, {:?} {:?}", $data, new_obj, err);
            }
            (_, _) => {}
        }
    }};
}

/// Reads a compact-size integer from the front of `data`, advancing `data` past it.
fn read_compact_size(data: &mut &[u8]) -> Option<u64> {
    let mut decoder = bitcoin::encoding::CompactSizeU64Decoder::new();
    decoder.push_bytes(data).ok()?;
    decoder.end().ok()
}

/// Returns `true` if `data`, interpreted as an `AddrV2Message`, contains a TorV2 (network_id 0x03) address.
///
/// `AddrV2Message` is encoded as: `time(u32) || services(compact-size u64) || AddrV2`.
/// The AddrV2 network_id follows the variable-length services field, so a fixed offset check is wrong.
fn addrv2_message_has_torv2(data: &[u8]) -> bool {
    (|| -> Option<bool> {
        let mut rest = data.get(4..)?; // skip time (u32 LE, 4 bytes)
        read_compact_size(&mut rest)?; // skip services (compact-size u64)
        Some(*rest.first()? == 0x03) // check AddrV2 network_id byte
    })()
    .unwrap_or(false)
}

/// Returns `true` if `data`, interpreted as an `AddrV2Payload` (`Vec<AddrV2Message>`),
/// contains any TorV2 (network_id 0x03) address.
fn addrv2_payload_has_torv2(data: &[u8]) -> bool {
    (|| -> Option<bool> {
        let mut rest = data;
        let count = read_compact_size(&mut rest)?;
        for _ in 0..count {
            let message: p2p::address::AddrV2Message =
                bitcoin::encoding::decode_from_slice_unbounded(&mut rest).ok()?;
            if let p2p::address::AddrV2::Unknown(addr_type, _) = message.addr {
                if addr_type == 0x03 {
                    return Some(true);
                }
            }
        }
        Some(false)
    })()
    .unwrap_or(false)
}

#[rustfmt::skip] // rustfmt butchers all of these with inconsistent newlines.
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
    compare_encoding!(data, p2p::ServiceFlags, old_bitcoin::p2p::ServiceFlags);
    compare_encoding!(data, p2p::Magic, old_bitcoin::p2p::Magic);
    compare_encoding!(data, p2p::address::Address, old_bitcoin::p2p::address::Address);
    compare_encoding!(data, p2p::bip152::BlockTransactions, old_bitcoin::bip152::BlockTransactions);
    compare_encoding!(data, p2p::bip152::BlockTransactionsRequest, old_bitcoin::bip152::BlockTransactionsRequest);
    compare_encoding!(data, p2p::bip152::HeaderAndShortIds, old_bitcoin::bip152::HeaderAndShortIds);
    compare_encoding!(data, p2p::bip152::PrefilledTransaction, old_bitcoin::bip152::PrefilledTransaction);
    compare_encoding!(data, p2p::bip152::ShortId, old_bitcoin::bip152::ShortId);
    compare_encoding!(data, p2p::merkle_tree::MerkleBlock, old_bitcoin::MerkleBlock);
    compare_encoding!(data, p2p::merkle_tree::PartialMerkleTree, old_bitcoin::merkle_tree::PartialMerkleTree);
    compare_encoding!(data, p2p::message_blockdata::GetBlocksMessage, old_bitcoin::p2p::message_blockdata::GetBlocksMessage);
    compare_encoding!(data, p2p::message_blockdata::GetHeadersMessage, old_bitcoin::p2p::message_blockdata::GetHeadersMessage);
    compare_encoding!(data, p2p::message_bloom::FilterAdd, old_bitcoin::p2p::message_bloom::FilterAdd);
    compare_encoding!(data, p2p::message_bloom::FilterLoad, old_bitcoin::p2p::message_bloom::FilterLoad);
    compare_encoding!(data, p2p::message_bloom::BloomFlags, old_bitcoin::p2p::message_bloom::BloomFlags);
    compare_encoding!(data, p2p::message_compact_blocks::SendCmpct, old_bitcoin::p2p::message_compact_blocks::SendCmpct);
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
    compare_encoding!(data, p2p::message_network::VersionMessage, old_bitcoin::p2p::message_network::VersionMessage);

    // Types that only exist in new bitcoin, but can encode the same as some known type
    compare_encoding!(data, p2p::ProtocolVersion, u32);
    compare_encoding!(data, p2p::address::AddrV1Message, (u32, old_bitcoin::p2p::Address));
    compare_encoding!(data, p2p::message::AddrPayload, Vec<(u32, old_bitcoin::p2p::Address)>);
    compare_encoding!(data, p2p::message::NetworkHeader, (old_bitcoin::block::Header, u8));
    compare_encoding!(data, p2p::message::Ping, u64);
    compare_encoding!(data, p2p::message::Pong, u64);
    compare_encoding!(data, p2p::message::V1NetworkMessage, old_bitcoin::p2p::message::RawNetworkMessage);
    compare_encoding!(data, p2p::message_blockdata::BlockLocator, Vec<old_bitcoin::BlockHash>);
    compare_encoding!(data, p2p::message_network::Alert, Vec<u8>);
    compare_encoding!(data, p2p::message_network::UserAgent, String);
    compare_encoding!(data, bitcoin::BlockHeight, u32);
    compare_encoding!(data, bitcoin::BlockTime, u32);

    // TorV2 (network_id 0x03) was removed from AddrV2 in bitcoin 0.33+. Bitcoin 0.32 decodes TorV2
    // as a distinct variant whose encoding differs from the new crate's AddrV2::Unknown(3, ...).
    // Skip inputs that would be decoded as TorV2 to avoid a false encoding mismatch.
    if data.first() != Some(&0x03) {
        compare_encoding!(data, p2p::address::AddrV2, old_bitcoin::p2p::address::AddrV2);
    }
    if !addrv2_message_has_torv2(data) {
        compare_encoding!(data, p2p::address::AddrV2Message, old_bitcoin::p2p::address::AddrV2Message);
    }
    if !addrv2_payload_has_torv2(data) {
        compare_encoding!(data, p2p::message::AddrV2Payload, Vec<old_bitcoin::p2p::address::AddrV2Message>);
    }
    // Inventory::Error (type_id=0) encodes differently between old/new bitcoin: old omits the
    // 32-byte hash field, new includes it. Skip inputs that would decode as the Error variant.
    if data.get(..4) != Some(&[0u8; 4]) {
        compare_encoding!(data, p2p::message_blockdata::Inventory, old_bitcoin::p2p::message_blockdata::Inventory);
    }
}

fuzz_target!(|data| {
    do_test(data);
});

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
