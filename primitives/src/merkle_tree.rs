// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::sha256d;

#[cfg(feature = "consensus-encoding-unbuffered-io")]
use crate::internal_macros;

hashes::hash_newtype! {
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(TxMerkleNode, WitnessMerkleNode);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(TxMerkleNode, WitnessMerkleNode);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TxMerkleNode, WitnessMerkleNode);

#[cfg(feature = "consensus-encoding-unbuffered-io")]
internal_macros::impl_hashencode!(TxMerkleNode);
#[cfg(feature = "consensus-encoding-unbuffered-io")]
internal_macros::impl_hashencode!(WitnessMerkleNode);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TxMerkleNode {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(TxMerkleNode::from_byte_array(u.arbitrary()?))
    }
}
