//! Chain lock is a mechanism used by the Dash network to
//! confirm latest block using LLMQ signature. This approach
//! reduces mining uncertenaty and mitigate 51% attack.
//! This data structure represents a p2p message containing a data to verify such a lock.

use crate::io;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
use core::fmt::{Debug};
#[cfg(any(feature = "std", test))]
pub use std::vec::Vec;
use hashes::{Hash, HashEngine};
use crate::bls_sig_utils::BLSSignature;
use crate::{BlockHash, QuorumSigningRequestId, VarInt};
use crate::consensus::{Encodable};
use crate::internal_macros::impl_consensus_encoding;

const CL_REQUEST_ID_PREFIX: &str = "clsig";

/// Chain lock is a mechanism used by the Dash network to
/// confirm latest block using LLMQ signature. This approach
/// reduces mining uncertainty and mitigate 51% attack.
/// This data structure represents a p2p message containing a data to verify such a lock.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChainLock {
    /// Block height
    pub block_height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Quorum signature
    pub signature: BLSSignature,
}

impl_consensus_encoding!(ChainLock, block_height, block_hash, signature);

impl ChainLock {
    /// Returns quorum signing request ID
    pub fn request_id(&self) -> Result<QuorumSigningRequestId, io::Error> {
        let mut engine = QuorumSigningRequestId::engine();

        // Prefix
        let prefix_len = VarInt(CL_REQUEST_ID_PREFIX.len() as u64);
        prefix_len.consensus_encode(&mut engine)?;

        engine.input(CL_REQUEST_ID_PREFIX.as_bytes());

        // Inputs
        engine.input(&self.block_height.to_le_bytes());

        Ok(QuorumSigningRequestId::from_engine(engine))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use hex::{FromHex, ToHex};
    use crate::consensus::deserialize;
    use crate::internal_macros::hex;
    use super::*;

    #[test]
    pub fn should_decode_vec() {
        // {
        //    height: 84202,
        //    blockHash:
        //      '0000000007e0a65b763c0a4fb2274ff757abdbd19c9efe9de189f5828c70a5f4',
        //    signature:
        //      '0a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c',
        //  };

        //     expectedHash2 =
        //       'e0b872dbf38b0f6f04fed617bef820776530b2155429024fbb092fc3a6ad6437';

        let chain_lock_hex = "ea480100f4a5708c82f589e19dfe9e9cd1dbab57f74f27b24f0a3c765ba6e007000000000a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c";
        let signature_hex = "0a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c";
        let chain_lock: ChainLock = deserialize(&hex!(chain_lock_hex)).unwrap();

        assert_eq!(chain_lock.block_height, 84202);
        assert_eq!(chain_lock.block_hash.to_string(), "0000000007e0a65b763c0a4fb2274ff757abdbd19c9efe9de189f5828c70a5f4");
        assert_eq!(chain_lock.signature.to_string(), signature_hex);
    }

    #[test]
    pub fn should_create_request_id() {
        let hex = "ea480100f4a5708c82f589e19dfe9e9cd1dbab57f74f27b24f0a3c765ba6e007000000000a43f1c3e5b3e8dbd670bca8d437dc25572f72d8e1e9be673e9ebbb606570307c3e5f5d073f7beb209dd7e0b8f96c751060ab3a7fb69a71d5ccab697b8cfa5a91038a6fecf76b7a827d75d17f01496302942aa5e2c7f4a48246efc8d3941bf6c";

        let expected_request_id = "5d92e094e2aa582b76e8bf519f42c5e8fc141bbe548e9660726f744adad03966";

        let vec = Vec::from_hex(hex).unwrap();

        let chain_lokc: ChainLock = deserialize(&vec).unwrap();

        let request_id = chain_lokc.request_id().expect("should return request id");

        assert_eq!(request_id.to_string(), expected_request_id);
    }
}
