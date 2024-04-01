// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash types.
//!
//! This module is deprecated. You can find hash types in their respective, hopefully obvious, modules.

#[deprecated(since = "0.0.0-NEXT-RELEASE", note = "use crate::T instead")]
pub use crate::{
    BlockHash, FilterHash, FilterHeader, TxMerkleNode, Txid, WitnessCommitment, WitnessMerkleNode,
    Wtxid,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::Hash;
    use crate::{
        LegacySighash, PubkeyHash, ScriptHash, SegwitV0Sighash, TapSighash, WPubkeyHash,
        WScriptHash, XKeyIdentifier,
    };

    #[test]
    fn hash_display() {
        assert_eq!(
            Txid::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );

        assert_eq!(
            Wtxid::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            BlockHash::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            LegacySighash::hash(&[]).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
        assert_eq!(
            SegwitV0Sighash::hash(&[]).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
        assert_eq!(
            TapSighash::hash(&[]).to_string(),
            "dabc11914abcd8072900042a2681e52f8dba99ce82e224f97b5fdb7cd4b9c803",
        );

        assert_eq!(PubkeyHash::hash(&[]).to_string(), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",);
        assert_eq!(ScriptHash::hash(&[]).to_string(), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",);
        assert_eq!(WPubkeyHash::hash(&[]).to_string(), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",);
        assert_eq!(
            WScriptHash::hash(&[]).to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );

        assert_eq!(
            TxMerkleNode::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            WitnessMerkleNode::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            WitnessCommitment::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            XKeyIdentifier::hash(&[]).to_string(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );

        assert_eq!(
            FilterHash::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            FilterHeader::hash(&[]).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
    }
}
