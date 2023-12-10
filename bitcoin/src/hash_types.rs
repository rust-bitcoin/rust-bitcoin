// SPDX-License-Identifier: CC0-1.0

//! Bitcoin hash types.
//!
//! This module is deprecated. You can find hash types in their respective, hopefully obvious, modules.

#[deprecated(since = "0.0.0-NEXT-RELEASE", note = "use crate::T instead")]
pub use crate::{
    BlockHash, FilterHash, FilterHeader, TxMerkleNode, Txid, WitnessCommitment, WitnessMerkleNode,
    Wtxid,
};
