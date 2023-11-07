// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash types.
//!
//! This module defines types for hashes used throughout the library. These
//! types are needed in order to avoid mixing data of the same hash format
//! (e.g. `SHA256d`) but of different meaning (such as transaction id, block
//! hash).
//!

#[deprecated(since = "0.0.0-NEXT-RELEASE", note = "use crate::T instead")]
pub use crate::{
    BlockHash, FilterHash, FilterHeader, TxMerkleNode, Txid, WitnessCommitment, WitnessMerkleNode,
    Wtxid,
};
