// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Library
//!
//! This is a library that supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! Except for its dependency on libsecp256k1 (and optionally libbitcoinconsensus),
//! this library is written entirely in Rust. It illustrates the benefits of
//! strong type safety, including ownership and lifetime, for financial and/or cryptographic software.
//!
//! See README.md for detailed documentation about development and supported
//! environments.
//!
//! ## Available feature flags
//!
//! * `std` - the usual dependency on `std` (default).
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `base64` - (dependency), enables encoding of PSBTs and message signatures.
//! * `rand` - (dependency), makes it more convenient to generate random values.
//! * `serde` - (dependency), implements `serde`-based serialization and
//!                 deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `bitcoinconsensus-std` - enables `std` in `bitcoinconsensus` and communicates it
//!                            to this crate so it knows how to implement
//!                            `std::error::Error`. At this time there's a hack to
//!                            achieve the same without this feature but it could
//!                            happen the implementations diverge one day.
//! * `ordered` - (dependency), adds implementations of `ArbitraryOrdOrd` to some structs.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454

// Disable 16-bit support at least for now as we can't guarantee it yet.
#[cfg(target_pointer_width = "16")]
compile_error!(
    "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
    know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
);

#[cfg(bench)]
extern crate test;

#[macro_use]
extern crate alloc;

/// Re-expot the `bitcoin-address` crate.
pub extern crate address;

#[cfg(feature = "base64")]
/// Encodes and decodes base64 as bytes or utf8.
pub extern crate actual_base64 as base64;

/// Bitcoin base58 encoding and decoding.
pub extern crate base58;

/// Re-expot the `bip32` crate.
pub extern crate bip32;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `ordered` crate.
#[cfg(feature = "ordered")]
pub extern crate ordered;

/// Re-export the `bitcoin-primitives` crate.
pub extern crate primitives;

/// Re-export the `psbt-v0` crate.
pub extern crate psbt;

/// Rust wrapper library for Pieter Wuille's libsecp256k1.  Implements ECDSA and BIP 340 signatures
/// for the SECG elliptic curve group secp256k1 and related utilities.
pub extern crate secp256k1;

#[cfg(feature = "serde")]
extern crate actual_serde as serde;

mod internal_macros;

#[macro_use]
pub mod p2p;
pub mod bip152;
pub mod bip158;
pub mod consensus;
pub mod hash_types;
pub mod network;
pub mod sign_message;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    bip158::{FilterHash, FilterHeader},
    bip32::XKeyIdentifier,
    network::NetworkExt,
    psbt::Psbt,
};
#[doc(inline)]
pub use address::{Address, AddressType, KnownHrp};
#[doc(inline)]
pub use primitives::{
    amount::{self, Amount, Denomination, SignedAmount},
    block::{self, Block, BlockHash, BlockHeight, BlockInterval, WitnessCommitment},
    consensus::encode::VarInt,
    consensus::params,
    constants,
    ecdsa,
    fee_rate::{self, FeeRate}, // Comes from `units`.
    key::{
        self, CompressedPublicKey, PrivateKey, PubkeyHash, PublicKey, WPubkeyHash, XOnlyPublicKey,
    },
    locktime::{self, absolute, relative},
    merkle_tree::{MerkleBlock, TxMerkleNode, WitnessMerkleNode},
    network::{Network, NetworkKind},
    opcodes::{self, Opcode},
    pow::{CompactTarget, Target, Work},
    script::witness_program::{self, WitnessProgram},
    script::witness_version::{self, WitnessVersion},
    script::{self, Script, ScriptBuf, ScriptHash, WScriptHash},
    sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    sighash::{EcdsaSighashType, TapSighashType},
    taproot,
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
    transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Wtxid},
    weight::{self, Weight}, // Comes from `units`.
    witness::{self, Witness},
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

    pub use crate::io::sink;

    pub use hex::DisplayHex;
}

/// Unit parsing utilities.
pub mod parse {
    /// Re-export everything from the [`units::parse`] module.
    pub use units::parse::ParseIntError;
}
