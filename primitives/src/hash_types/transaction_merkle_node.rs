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

const LEN: usize = 32;
#[cfg(feature = "hex")]
const REVERSE: bool = true;

/// A hash of the Merkle tree branch or root for transactions.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxMerkleNode(sha256d::Hash);

type HashType = TxMerkleNode;

impl TxMerkleNode {
    /// Constructs a new type from the underlying byte array.
    pub const fn from_byte_array(bytes: [u8; LEN]) -> Self {
        Self(sha256d::Hash::from_byte_array(bytes))
    }
}

include!("./generic.rs");

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TxMerkleNode {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxMerkleNode::from_byte_array(u.arbitrary()?))
    }
}
