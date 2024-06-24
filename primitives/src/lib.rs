// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

#[cfg(bench)]
extern crate test;

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export the `bitcoinconsensus` crate.
#[cfg(feature = "bitcoinconsensus")]
pub extern crate bitcoinconsensus;

/// Re-export the `bech32` crate.
#[cfg(feature = "bech32")]
pub extern crate bech32;

/// Re-export the `base58ck` crate.
#[cfg(feature = "base58")]
pub extern crate base58;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `ordered` crate.
#[cfg(feature = "ordered")]
pub extern crate ordered;

/// Re-export the `secp256k1` crate.
#[cfg(feature = "secp256k1")]
pub extern crate secp256k1;

#[cfg(feature = "serde")]
extern crate actual_serde as serde;

/// Re-export the `bitcoin-units` crate.
pub extern crate units;

/// Re-export everything from the `units` while maintaining module structure.
///
/// These re-exports allow `bitcoin-primitives` users to ignore `units` and just use
/// `primitives` for non-niche use cases (incl. error types usage). For example:
///
/// - `use primitives::{absolute, Weight}`;
/// - `use primitives::amount::{self, Amount}`;  // Type plus module for errors.
#[doc(inline)]
pub use units::{
    amount::{self, Amount, Denomination, SignedAmount},
    block::{BlockHeight, BlockInterval, TooBigForRelativeBlockHeightError},
    fee_rate::{self, FeeRate},
    parse,
    weight::{self, Weight},
};

#[rustfmt::skip]                // Keep prelude types separate.
#[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
pub use alloc::sync;
#[cfg(all(not(feature = "std"), not(test)))]
pub use alloc::{
    borrow::{Borrow, BorrowMut, Cow, ToOwned},
    boxed::Box,
    collections::{btree_map, BTreeMap, BTreeSet, BinaryHeap},
    format, rc, slice,
    string::{String, ToString},
    vec,
    vec::Vec,
};
#[cfg(any(feature = "std", test))]
pub use std::{
    borrow::{Borrow, BorrowMut, Cow, ToOwned},
    boxed::Box,
    collections::{btree_map, BTreeMap, BTreeSet, BinaryHeap},
    format, rc,
    string::{String, ToString},
    sync, vec,
    vec::Vec,
};
