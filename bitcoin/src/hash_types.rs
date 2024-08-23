// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash types.
//!
//! This module is deprecated. You can find hash types in their respective, hopefully obvious, modules.

#[deprecated(since = "TBD", note = "use crate::T instead")]
pub use crate::{
    BlockHash, FilterHash, FilterHeader, TxMerkleNode, Txid, WitnessCommitment, WitnessMerkleNode,
    Wtxid,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LegacySighash, PubkeyHash, ScriptHash, SegwitV0Sighash, TapSighash, WPubkeyHash,
        WScriptHash, XKeyIdentifier,
    };

    #[rustfmt::skip]
    /// sha256d of the empty string
    const DUMMY32: [u8; 32] = [
        0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
        0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
        0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
        0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56,
    ];
    /// hash160 of the empty string
    #[rustfmt::skip]
    const DUMMY20: [u8; 20] = [
        0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06,
        0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb,
    ];

    #[test]
    fn hash_display() {
        assert_eq!(
            Txid::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );

        assert_eq!(
            Wtxid::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            BlockHash::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            LegacySighash::from_byte_array(DUMMY32).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
        assert_eq!(
            SegwitV0Sighash::from_byte_array(DUMMY32).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
        assert_eq!(
            TapSighash::from_byte_array(DUMMY32).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );

        assert_eq!(
            PubkeyHash::from_byte_array(DUMMY20).to_string(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );
        assert_eq!(
            ScriptHash::from_byte_array(DUMMY20).to_string(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );
        assert_eq!(
            WPubkeyHash::from_byte_array(DUMMY20).to_string(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );
        assert_eq!(
            WScriptHash::from_byte_array(DUMMY32).to_string(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );

        assert_eq!(
            TxMerkleNode::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            WitnessMerkleNode::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            WitnessCommitment::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            XKeyIdentifier::from_byte_array(DUMMY20).to_string(),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );

        assert_eq!(
            FilterHash::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
        assert_eq!(
            FilterHeader::from_byte_array(DUMMY32).to_string(),
            "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d",
        );
    }
}
