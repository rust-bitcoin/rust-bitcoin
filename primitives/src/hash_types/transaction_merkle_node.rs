// SPDX-License-Identifier: CC0-1.0

//! The `TxMerkleNode` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

/// A hash of the Merkle tree branch or root for transactions.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxMerkleNode(sha256d::Hash);

// The new hash wrapper type.
type HashType = TxMerkleNode;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

encoding::encoder_newtype! {
    /// The encoder for the [`TxMerkleNode`] type.
    pub struct TxMerkleNodeEncoder(encoding::ArrayEncoder<32>);
}

impl encoding::Encodable for TxMerkleNode {
    type Encoder<'e> = TxMerkleNodeEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        TxMerkleNodeEncoder(encoding::ArrayEncoder::new(self.to_byte_array()))
    }
}
