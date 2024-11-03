// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! This crate can be used in a no-std environment but requires an allocator.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

pub mod block;
#[cfg(feature = "alloc")]
pub mod locktime;
pub mod merkle_tree;
pub mod opcodes;
pub mod pow;
#[cfg(feature = "alloc")]
pub mod script;
pub mod sequence;
pub mod taproot;
pub mod transaction;
#[cfg(feature = "alloc")]
pub mod witness;

#[doc(inline)]
pub use units::amount::{Amount, SignedAmount};
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use units::{
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    weight::Weight,
};

#[doc(inline)]
pub use self::{
    block::{BlockHash, WitnessCommitment},
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    pow::CompactTarget,
    sequence::Sequence,
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
    transaction::{Txid, Wtxid},
};
#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    locktime::{absolute, relative},
    transaction::{Transaction, TxIn, TxOut},
    witness::Witness,
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "alloc")]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    pub use alloc::sync;
}
