// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Merkle tree functions.

// This module is unusual in that it exists because of a bunch of (krufty) reasons:
//
// - We based the name off of the original `bitcoin` module.
// - We want the API to be the same here as in `bitcoin`.
// - We define all the other hash types in some module so the merkle tree hash types need a module.
//
// C'est la vie.

#[doc(inline)]
pub use crate::hash_types::{TxMerkleNode, TxMerkleNodeEncoder, WitnessMerkleNode};
