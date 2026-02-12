//! Fuzz target to verify roundtrip encoding/decoding for Encodable/Decodable types.
//!
//! This fuzz target checks that for all data slices that can decode to a type, the decoded
//! value re-encodes to the same slice.

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use honggfuzz::fuzz;

/// Helper macro to check roundtrip decode -> encode for a type.
macro_rules! check_roundtrip {
    ($data:expr, $enc_type:ty) => {{
        let decode_result: Result<$enc_type, _> = decode_from_slice($data);

        if let Ok(base_decoded) = decode_result {
            // We want to encode + decode the initial decoded object. Basically, we want
            // to check the roundtrip from decoded -> encoded -> decoded, rather than
            // encoded -> decoded -> encoded.
            let encoded = encode_to_vec(&base_decoded);
            let decoded = decode_from_slice::<$enc_type>(&encoded).unwrap();
            assert_eq!(base_decoded, decoded);
        }
    }};
}

/// Helper macro to check roundtrip decode -> encode for a script type.
macro_rules! check_script_roundtrip {
    ($data:expr, $enc_type:ty) => {{
        let decode_result: Result<$enc_type, _> = decode_from_slice($data);

        if let Ok(base_decoded) = decode_result {
            // We want to encode + decode the initial decoded object. Basically, we want
            // to check the roundtrip from decoded -> encoded -> decoded, rather than
            // encoded -> decoded -> encoded.
            let encoded = encode_to_vec(&(*base_decoded));
            let decoded = decode_from_slice::<$enc_type>(&encoded).unwrap();
            assert_eq!(base_decoded, decoded);
        }
    }};
}

fn do_test(data: &[u8]) {
    check_roundtrip!(data, bitcoin::Amount);
    check_roundtrip!(data, bitcoin::Block);
    check_roundtrip!(data, bitcoin::BlockHash);
    check_roundtrip!(data, bitcoin::BlockHeight);
    check_roundtrip!(data, bitcoin::BlockTime);
    check_roundtrip!(data, bitcoin::CompactTarget);
    check_roundtrip!(data, bitcoin::Sequence);
    check_roundtrip!(data, bitcoin::Transaction);
    check_roundtrip!(data, bitcoin::TxMerkleNode);
    check_roundtrip!(data, bitcoin::TxIn);
    check_roundtrip!(data, bitcoin::TxOut);
    check_roundtrip!(data, bitcoin::OutPoint);
    check_roundtrip!(data, bitcoin::Witness);
    check_roundtrip!(data, bitcoin::WitnessMerkleNode);
    check_roundtrip!(data, bitcoin::absolute::LockTime);
    check_roundtrip!(data, bitcoin::block::Header);
    check_roundtrip!(data, bitcoin::block::Version);
    check_roundtrip!(data, bitcoin::transaction::Version);

    // Script types
    check_script_roundtrip!(data, bitcoin::RedeemScriptBuf);
    check_script_roundtrip!(data, bitcoin::ScriptPubKeyBuf);
    check_script_roundtrip!(data, bitcoin::ScriptSigBuf);
    check_script_roundtrip!(data, bitcoin::TapScriptBuf);
    check_script_roundtrip!(data, bitcoin::WitnessScriptBuf);

    // P2P types
    check_roundtrip!(data, p2p::ProtocolVersion);
    check_roundtrip!(data, p2p::ServiceFlags);
    check_roundtrip!(data, p2p::address::AddrV2);
    check_roundtrip!(data, p2p::bip152::BlockTransactionsRequest);
    check_roundtrip!(data, p2p::message::CommandString);
    check_roundtrip!(data, p2p::message::FeeFilter);
    check_roundtrip!(data, p2p::message::InventoryPayload);
    check_roundtrip!(data, p2p::message::RawNetworkMessage);
    check_roundtrip!(data, p2p::message_blockdata::Inventory);
    check_roundtrip!(data, p2p::message_blockdata::GetBlocksMessage);
    check_roundtrip!(data, p2p::message_blockdata::GetHeadersMessage);
    check_roundtrip!(data, p2p::message_bloom::FilterAdd);
    check_roundtrip!(data, p2p::message_bloom::FilterLoad);
    check_roundtrip!(data, p2p::message_bloom::BloomFlags);
    check_roundtrip!(data, p2p::message_filter::CFHeaders);
    check_roundtrip!(data, p2p::message_filter::CFilter);
    check_roundtrip!(data, p2p::message_filter::CFCheckpt);
    check_roundtrip!(data, p2p::message_filter::GetCFCheckpt);
    check_roundtrip!(data, p2p::message_filter::GetCFHeaders);
    check_roundtrip!(data, p2p::message_filter::GetCFilters);
    check_roundtrip!(data, p2p::message_filter::FilterHash);
    check_roundtrip!(data, p2p::message_filter::FilterHeader);
    check_roundtrip!(data, p2p::message_network::Alert);
    check_roundtrip!(data, p2p::message_network::Reject);
    check_roundtrip!(data, p2p::message_network::RejectReason);
    check_roundtrip!(data, p2p::message_network::UserAgent);

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
        extend_vec_from_hex("0000000000000000000000000101010106000000000000000101010101010101", &mut a);
        super::do_test(&a);
    }
}
