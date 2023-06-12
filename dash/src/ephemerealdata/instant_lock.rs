//! Instant send lock is a mechanism used by the Dash network to
//! confirm transaction within 1 or 2 seconds. This data structure
//! represents a p2p message containing a data to verify such a lock.

use crate::io;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};
#[cfg(any(feature = "std", test))]
pub use std::vec::Vec;
use hashes::{Hash, HashEngine};
use crate::hash_types::{CycleHash, QuorumSigningRequestId};
use crate::{OutPoint, Txid, VarInt};
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Encodable};
use crate::internal_macros::impl_consensus_encoding;

const IS_LOCK_REQUEST_ID_PREFIX: &str = "islock";

#[derive(Clone, Eq, PartialEq)]
/// Instant send lock is a mechanism used by the Dash network to
/// confirm transaction within 1 or 2 seconds. This data structure
/// represents a p2p message containing a data to verify such a lock.
pub struct InstantLock {
    /// Instant lock version
    pub version: u8,
    /// Transaction inputs locked by this instant lock
    pub inputs: Vec<OutPoint>,
    /// Transaction hash locked by this lock
    pub txid: Txid,
    /// Hash to figure out which quorum was used to sign this IS lock
    pub cyclehash: CycleHash,
    /// Quorum signature for this IS lock
    pub signature: BLSSignature,
}

impl_consensus_encoding!(InstantLock, version, inputs, txid, cyclehash, signature);

impl InstantLock {
    /// Returns quorum signing request ID
    pub fn request_id(&self) -> Result<QuorumSigningRequestId, io::Error> {
        let mut engine = QuorumSigningRequestId::engine();

        // Prefix
        let prefix_len = VarInt(IS_LOCK_REQUEST_ID_PREFIX.len() as u64);
        prefix_len.consensus_encode(&mut engine)?;

        engine.input(IS_LOCK_REQUEST_ID_PREFIX.as_bytes());

        // Inputs
        let inputs_len = VarInt(self.inputs.len() as u64);
        inputs_len.consensus_encode(&mut engine)?;

        for input in &self.inputs {
            engine.input(&input.txid[..]);
            engine.input(&input.vout.to_le_bytes());
        }

        Ok(QuorumSigningRequestId::from_engine(engine))
    }
}

impl Debug for InstantLock {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("InstantLock")
            .field("version", &self.version)
            .field("inputs", &format_args!("{:?}", self.inputs))
            .field("txid", &format_args!("{}", self.txid))
            .field("cyclehash", &format_args!("{:?}", self.cyclehash))
            .field("signature", &format_args!("{:?}", self.signature.as_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};
    use crate::internal_macros::hex;

    #[test]
    pub fn should_decode_vec() {
        let hex = "010101102862a43d122e6675aba4b507ae307af8e1e17febc77907e08b3efa28f41b000000004b446de00a592c67402c0a65649f4ad69f29084b3e9054f5aa6b85a50b497fe136a56617591a6a89237bada6af1f9b46eba47b5d89a8c4e49ff2d0236182307c85e12d70ca7118c5034004f93e45384079f46c6c2928b45cfc5d3ad640e70dfd87a9a3069899adfb3b1622daeeead19809b74354272ccf95290678f55c13728e3c5ee8f8417fcce3dfdca2a7c9c33ec981abdff1ec35a2e4b558c3698f01c1b8";
        // let object = {
        //     version: 1,
        //     inputs: [
        //     {
        //         outpointHash: "1bf428fa3e8be00779c7eb7fe1e1f87a30ae07b5a4ab75662e123da462281001",
        //         outpointIndex: 0
        //     }
        //     ],
        //     txid: "e17f490ba5856baaf554903e4b08299fd64a9f64650a2c40672c590ae06d444b",
        //     cyclehash: "7c30826123d0f29fe4c4a8895d7ba4eb469b1fafa6ad7b23896a1a591766a536",
        //     signature: "85e12d70ca7118c5034004f93e45384079f46c6c2928b45cfc5d3ad640e70dfd87a9a3069899adfb3b1622daeeead19809b74354272ccf95290678f55c13728e3c5ee8f8417fcce3dfdca2a7c9c33ec981abdff1ec35a2e4b558c3698f01c1b8"
        // };

        let vec = hex!(hex);

        // let expected_hash = "4ee6a4ed2b6c70efd401c6c91dfaf6c61badd13f80ec07c281bb93d5270fcd58";
        // let expected_request_id = "495be44677e82895a9396fef02c6e9afc1f01d4aff70622b9f78e0e10d57064c";

        let is_lock: InstantLock = deserialize(&vec).unwrap();
        assert_eq!(is_lock.version, 1);

        // TODO: check outpoints

        assert_eq!(is_lock.cyclehash.to_string(), "7c30826123d0f29fe4c4a8895d7ba4eb469b1fafa6ad7b23896a1a591766a536");

        let serialized = serialize(&is_lock);
        assert_eq!(serialized, vec);
    }

    #[test]
    pub fn should_create_request_id() {
        let hex = "010101102862a43d122e6675aba4b507ae307af8e1e17febc77907e08b3efa28f41b000000004b446de00a592c67402c0a65649f4ad69f29084b3e9054f5aa6b85a50b497fe136a56617591a6a89237bada6af1f9b46eba47b5d89a8c4e49ff2d0236182307c85e12d70ca7118c5034004f93e45384079f46c6c2928b45cfc5d3ad640e70dfd87a9a3069899adfb3b1622daeeead19809b74354272ccf95290678f55c13728e3c5ee8f8417fcce3dfdca2a7c9c33ec981abdff1ec35a2e4b558c3698f01c1b8";
        let vec = hex!(hex);

        let expected_request_id = "495be44677e82895a9396fef02c6e9afc1f01d4aff70622b9f78e0e10d57064c";

        let is_lock: InstantLock = deserialize(vec.as_slice()).unwrap();

        let request_id = is_lock.request_id().expect("should return request id");
        assert_eq!(request_id.to_string(), expected_request_id);
    }

    // #[test]
    // #[cfg(feature = "serde")]
    // pub fn should_decode_json() {
    //     let str = r#"
    //     {
    //         "version": 1,
    //         "inputs": [
    //         {
    //             "outpointHash": "1bf428fa3e8be00779c7eb7fe1e1f87a30ae07b5a4ab75662e123da462281001",
    //             "outpointIndex": 0
    //         }
    //         ],
    //         "txid": "e17f490ba5856baaf554903e4b08299fd64a9f64650a2c40672c590ae06d444b",
    //         "cyclehash": "7c30826123d0f29fe4c4a8895d7ba4eb469b1fafa6ad7b23896a1a591766a536",
    //         "signature": "85e12d70ca7118c5034004f93e45384079f46c6c2928b45cfc5d3ad640e70dfd87a9a3069899adfb3b1622daeeead19809b74354272ccf95290678f55c13728e3c5ee8f8417fcce3dfdca2a7c9c33ec981abdff1ec35a2e4b558c3698f01c1b8"
    //     }"#;
    //
    //     let is_lock: InstantLock = serde_json::from_str(str).unwrap();
    // }
}
