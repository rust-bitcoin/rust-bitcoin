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
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod internal_macros;

pub mod block;
pub mod constants;
#[cfg(feature = "alloc")]
pub mod locktime;
pub mod merkle_tree;
pub mod opcodes;
pub mod pow;
pub mod script;
pub mod sequence;
pub mod transaction;

#[doc(inline)]
pub use units::*;

#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::locktime::{absolute, relative};
#[doc(inline)]
pub use self::{
    block::{BlockHash, WitnessCommitment},
    constants::{MAX_REDEEM_SCRIPT_SIZE, MAX_WITNESS_SCRIPT_SIZE},
    script::{
        witness_program::{self, WitnessProgram},
        witness_version::{self, WitnessVersion},
        Script, ScriptBuf, ScriptHash, WScriptHash,
    },
    sequence::Sequence,
    transaction::{Txid, Wtxid},
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
    pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use hex::DisplayHex;
}
