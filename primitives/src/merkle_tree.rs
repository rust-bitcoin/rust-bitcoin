// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

use crate::internal_macros;

hashes::hash_newtype! {
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
}

#[cfg(feature = "hex")]
internal_macros::impl_hex_string_traits!(TxMerkleNode, 32, true);
#[cfg(not(feature = "hex"))]
internal_macros::impl_debug_only!(TxMerkleNode, 32, true);

#[cfg(feature = "hex")]
internal_macros::impl_hex_string_traits!(WitnessMerkleNode, 32, true);
#[cfg(not(feature = "hex"))]
internal_macros::impl_debug_only!(WitnessMerkleNode, 32, true);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TxMerkleNode {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxMerkleNode::from_byte_array(u.arbitrary()?))
    }
}
