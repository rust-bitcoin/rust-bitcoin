// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

use hashes::sha256d;

hashes::hash_newtype! {
    /// A hash of the Merkle tree branch or root for transactions.
    pub struct TxMerkleNode(sha256d::Hash);
    /// A hash corresponding to the Merkle tree root for witness data.
    pub struct WitnessMerkleNode(sha256d::Hash);
}
