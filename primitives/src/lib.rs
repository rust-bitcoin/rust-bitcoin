// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin - primitive types.
//!
//! This crate provides primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! The rules used to work out what goes in this crate are:
//!
//! - Types that don't depend on anything else from the ecosystem except `bitcoin-internals`.
//! - Types that operate only on Rust types.
//!
//! So if `rust-bitcoin` is analogous to std then `bitcoin-primitives` is analogous to core (calling
//! it core would have obviously been confusing).
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![no_std]
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

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "bitcoinconsensus")]
pub extern crate bitcoinconsensus;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `ordered` crate.
#[cfg(feature = "ordered")]
pub extern crate ordered;

/// Re-export the `ordered` crate.
#[cfg(feature = "crypto")]
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;

/// Re-export the `bitcoin-units` crate.
pub extern crate units;

// private modules.
#[cfg(feature = "alloc")]
mod internal_macros;

// alloc feature gated public modules.

#[cfg(feature = "alloc")]
pub mod block;
#[cfg(feature = "alloc")]
pub mod consensus;
#[cfg(feature = "alloc")]
pub mod constants;
#[cfg(all(feature = "crypto", feature = "alloc"))]
mod crypto;
#[cfg(feature = "alloc")]
pub mod key;
#[cfg(feature = "alloc")]
pub mod locktime;
#[cfg(feature = "alloc")]
pub mod merkle_tree;
#[cfg(feature = "alloc")]
pub mod network;
#[cfg(feature = "alloc")]
pub mod opcodes;
#[cfg(feature = "alloc")]
pub mod policy;
#[cfg(feature = "alloc")]
pub mod pow;
#[cfg(feature = "alloc")]
pub mod script;
#[cfg(all(feature = "alloc", feature = "serde"))]
pub mod serde_utils;
#[cfg(feature = "alloc")]
pub mod taproot;
#[cfg(feature = "alloc")]
pub mod transaction;
#[cfg(feature = "alloc")]
pub mod witness;

/// Re-export everything from the `units` while crate maintaining module structure.
///
/// These re-exports allow `bitcoin-primitives` users to ignore `units` and just use
/// `primitives`. For example:
///
/// - `use primitives::{absolute, Weight}`;
/// - `use primitives::amount::{self, Amount}`;  // Type plus module for errors.
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use units::{
    amount::{self, Amount, SignedAmount},
    fee_rate::{self, FeeRate},
    weight::{self, Weight},
};

/// Re-export keys and sighash.
#[cfg(feature = "crypto")]
pub use self::crypto::{
    ecdsa, // `taproot` intentionally not re-expoted, we use `src/taproot.rs` instead.
    key::{CompressedPublicKey, Keypair, PrivateKey, PublicKey, XOnlyPublicKey},
    sighash::{self, LegacySighash, SegwitV0Sighash, SighashCache, TapSighash, TapSighashTag},
};
/// Re-export types/modules for typical usage.
///
/// Most users should be able to just grab everything straight from the `primitives` crate root.
/// Only niche users should need to dig into the exact submodules.
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::{
    block::{Block, BlockHash, TxMerkleNode, WitnessCommitment, WitnessMerkleNode},
    consensus::{params, VarInt},
    key::{PubkeyHash, WPubkeyHash},
    locktime::{absolute, relative},
    merkle_tree::MerkleBlock,
    network::{Network, NetworkKind},
    opcodes::Opcode,
    pow::{CompactTarget, Target, Work},
    script::witness_program::{self, WitnessProgram},
    script::witness_version::{self, WitnessVersion},
    script::{Script, ScriptBuf, ScriptHash, WScriptHash},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
    transaction::{OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Wtxid},
    witness::Witness,
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::{string::{String, ToString}, vec, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, format, slice, rc};

    #[cfg(feature = "std")]
    pub use std::{string::{String, ToString}, vec, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, format, rc};

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    use hex::DisplayHex;
}
