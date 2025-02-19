// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! This crate can be used in a no-std environment but a lot of the functionality requires an
//! allocator i.e., requires the `alloc` feature to be enabled.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Pedantic lints that we enforce.
// #![warn(clippy::must_use_candidate)]
#![warn(clippy::return_self_not_must_use)]
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

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

pub mod block;
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
pub use units::{
    amount::{self, Amount, SignedAmount},
    block::{BlockHeight, BlockInterval},
    fee_rate::{self, FeeRate},
    weight::{self, Weight},
};

#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    block::{
        Block, Checked as BlockChecked, Unchecked as BlockUnchecked, Validation as BlockValidation,
    },
    script::{Script, ScriptBuf, ScriptHash, WScriptHash},
    transaction::{Transaction, TxIn, TxOut},
    witness::Witness,
};
#[doc(inline)]
pub use self::{
    block::{BlockHash, Header as BlockHeader, Version as BlockVersion, WitnessCommitment},
    locktime::{absolute, relative},
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    opcodes::Opcode,
    pow::CompactTarget,
    sequence::Sequence,
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
    transaction::{OutPoint, Txid, Version as TxVersion, Wtxid},
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
