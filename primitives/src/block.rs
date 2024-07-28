// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.

use hashes::sha256d;

hashes::hash_newtype! {
    /// A bitcoin block hash.
    pub struct BlockHash(sha256d::Hash);
    /// A hash corresponding to the witness structure commitment in the coinbase transaction.
    pub struct WitnessCommitment(sha256d::Hash);
}

impl BlockHash {
    /// The "all zeros" blockhash.
    ///
    /// This is not the hash of a real block. It is used as the previous blockhash
    /// of the genesis block and in other placeholder contexts.
    pub fn all_zeros() -> Self { Self::from_byte_array([0; 32]) }
}
