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

#[cfg(feature = "base64")]
/// Encodes and decodes base64 as bytes or utf8.
pub extern crate base64;

/// Bitcoin base58 encoding and decoding.
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

/// Re-export the `primitives` crate.
pub extern crate primitives;

/// Rust wrapper library for Pieter Wuille's libsecp256k1.  Implements ECDSA and BIP 340 signatures
/// for the SECG elliptic curve group secp256k1 and related utilities.
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;

#[cfg(test)]
#[macro_use]
mod test_macros;
mod internal_macros;

#[macro_use]
pub mod p2p;
pub mod address;
pub mod bip152;
pub mod bip158;
pub mod bip32;
pub mod blockdata;
pub mod consensus;
// Private until we either make this a crate or flatten it - still to be decided.
pub(crate) mod crypto;
pub mod hash_types;
pub mod network;
pub mod psbt;
#[cfg(feature = "serde")]
pub mod serde_utils;
pub mod sign_message;
pub mod taproot;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    amount::{Amount, Denomination, SignedAmount},
    bip158::{FilterHash, FilterHeader},
    bip32::XKeyIdentifier,
    blockdata::block::{self, Block, BlockHash, TxMerkleNode, WitnessMerkleNode, WitnessCommitment},
    blockdata::constants,
    blockdata::fee_rate::FeeRate,
    blockdata::locktime::{self, absolute, relative},
    blockdata::opcodes::{self, Opcode},
    blockdata::script::witness_program::{self, WitnessProgram},
    blockdata::script::witness_version::{self, WitnessVersion},
    blockdata::script::{self, Script, ScriptBuf, ScriptHash, WScriptHash},
    blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Wtxid},
    blockdata::weight::Weight,
    blockdata::witness::{self, Witness},
    consensus::encode::VarInt,
    consensus::params,
    crypto::ecdsa,
    crypto::key::{self, PrivateKey, PubkeyHash, PublicKey, CompressedPublicKey, WPubkeyHash, XOnlyPublicKey},
    crypto::sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    merkle_tree::MerkleBlock,
    network::{Network, NetworkKind},
    pow::{CompactTarget, Target, Work},
    psbt::Psbt,
    sighash::{EcdsaSighashType, TapSighashType},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
};
/// Re-export all the extension traits.
pub use crate::network::NetworkExt;

pub mod merkle_tree {
    //! Bitcoin merkle tree functions.

    pub use primitives::merkle_tree::*;
}

pub mod pow {
    //! Proof-of-work related integer types.
    //!
    //! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
    //! functions here are designed to be fast, by that we mean it is safe to use them to check headers.

    pub use primitives::pow::*;

    #[cfg(test)]
    mod tests {
        use hashes::Hash;

        use crate::consensus::Params;
        use crate::{block, constants, BlockHash, CompactTarget, Network, TxMerkleNode};

        #[test]
        fn compact_target_from_upwards_difficulty_adjustment_using_headers() {
            let params = Params::new(Network::Signet);
            let epoch_start = constants::genesis_block(&params).header;
            // Block 2015, the only information used are `bits` and `time`
            let current = block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1599332177,
                bits: epoch_start.bits,
                nonce: epoch_start.nonce,
            };
            let adjustment =
                CompactTarget::from_header_difficulty_adjustment(epoch_start, current, params);
            let adjustment_bits = CompactTarget::from_consensus(503394215); // Block 2016 compact target
            assert_eq!(adjustment, adjustment_bits);
        }
    }
}

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

pub mod amount {
    //! Bitcoin amounts.
    //!
    //! This module mainly introduces the [Amount] and [SignedAmount] types.
    //! We refer to the documentation on the types for more information.

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(inline)]
    pub use units::amount::{
        Amount, CheckedSum, Denomination, Display, ParseAmountError, SignedAmount,
    };
    #[cfg(feature = "serde")]
    pub use units::amount::serde;
}

/// Unit parsing utilities.
pub mod parse {
    /// Re-export everything from the [`units::parse`] module.
    pub use units::parse::ParseIntError;
}
