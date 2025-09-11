// SPDX-License-Identifier: CC0-1.0

//! The `BlockHash` type.

#[cfg(not(feature = "hex"))]
use core::fmt;
#[cfg(feature = "hex")]
use core::str;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::Encodable;
use hashes::sha256d;
#[cfg(feature = "hex")]
use hex::FromHex as _;

/// A bitcoin block hash.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHash(sha256d::Hash);

impl BlockHash {
    /// Dummy hash used as the previous blockhash of the genesis block.
    pub const GENESIS_PREVIOUS_BLOCK_HASH: Self = Self::from_byte_array([0; 32]);
}

// The new hash wrapper type.
type HashType = BlockHash;
// The inner hash type from `hashes`.
type Inner = sha256d::Hash;

include!("./generic.rs");

encoding::encoder_newtype! {
    /// The encoder for the [`BlockHash`] type.
    pub struct BlockHashEncoder(encoding::ArrayEncoder<32>);
}

impl Encodable for BlockHash {
    type Encoder<'e> = BlockHashEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockHashEncoder(encoding::ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}
