// SPDX-License-Identifier: CC0-1.0

//! # Rust Bitcoin Library
//!
//! This is a library that supports the Bitcoin network protocol and associated primitives. It is
//! designed for Rust programs built to work with the Bitcoin network.
//!
//! Except for its dependency on libsecp256k1 (and optionally libbitcoinconsensus), this library is
//! written entirely in Rust. It illustrates the benefits of strong type safety, including ownership
//! and lifetime, for financial and/or cryptographic software.
//!
//! See README.md for detailed documentation about development and supported environments.
//!
//! # Cargo features
//!
//! * `base64` (dependency) - enables encoding of PSBTs and message signatures.
//! * `bitcoinconsensus` (dependency) - enables validating scripts and transactions.
//! * `default` - enables `std` and `secp-recovery`.
//! * `rand` (transitive dependency) - makes it more convenient to generate random values.
//! * `rand-std` - same as `rand` but also enables `std` here and in `secp256k1`.
//! * `serde` (dependency) - implements `serde`-based serialization and deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `std` - the usual dependency on `std`.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_notable_trait))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
#![cfg_attr(bench, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.

// We only support machines with index size of 4 bytes or more.
//
// Bitcoin consensus code relies on being able to have containers with more than 65536 (2^16)
// entries in them so we cannot support consensus logic on machines that only have 16-bit memory
// addresses.
//
// We specifically do not use `target_pointer_width` because of the possibility that pointer width
// does not equal index size.
//
// ref: https://github.com/rust-bitcoin/rust-bitcoin/pull/2929#discussion_r1661848565
internals::const_assert!(
    core::mem::size_of::<usize>() >= 4;
    "platforms that have usize less than 32 bits are not supported"
);

#[cfg(bench)]
extern crate test;

#[macro_use]
extern crate alloc;

/// Encodes and decodes base64 as bytes or utf8.
#[cfg(feature = "base64")]
pub extern crate base64;

/// Bitcoin base58 encoding and decoding.
pub extern crate base58;

/// Re-export the `bech32` crate.
pub extern crate bech32;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `rust-secp256k1` crate.
///
/// Rust wrapper library for Pieter Wuille's libsecp256k1. Implements ECDSA and BIP-340 signatures
/// for the SECG elliptic curve group secp256k1 and related utilities.
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod internal_macros;
#[cfg(feature = "serde")]
mod serde_utils;

#[macro_use]
pub mod p2p;
pub mod address;
pub mod bip152;
pub mod bip158;
pub mod bip32;
pub mod blockdata;
pub mod consensus;
#[cfg(feature = "bitcoinconsensus")]
pub mod consensus_validation;
// Private until we either make this a crate or flatten it - still to be decided.
pub(crate) mod crypto;
pub mod hash_types;
pub mod merkle_tree;
pub mod network;
pub mod policy;
pub mod pow;
pub mod psbt;
pub mod sign_message;
pub mod taproot;

// Re-export the type from where it is defined but the module from the highest place up the stack
// that it is available in the event that we add some functionality there.
#[doc(inline)]
pub use primitives::{
    block::{
        Block, BlockHash, Checked as BlockChecked, Header as BlockHeader,
        Unchecked as BlockUnchecked, Validation as BlockValidation, Version as BlockVersion,
        WitnessCommitment,
    },
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    pow::CompactTarget, // No `pow` module outside of `primitives`.
    script::{Script, ScriptBuf},
    sequence::{self, Sequence}, // No `sequence` module outside of `primitives`.
    transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version as TransactionVersion, Wtxid},
    witness::Witness,
};
#[doc(inline)]
pub use units::{
    amount::{Amount, Denomination, SignedAmount},
    block::{BlockHeight, BlockInterval},
    fee_rate::FeeRate,
    timestamp::{self, Timestamp},
    weight::Weight,
};

#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    bip158::{FilterHash, FilterHeader},
    bip32::XKeyIdentifier,
    crypto::ecdsa,
    crypto::key::{self, CompressedPublicKey, PrivateKey, PublicKey, XOnlyPublicKey},
    crypto::sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    merkle_tree::MerkleBlock,
    network::params::{self, Params},
    network::{Network, NetworkKind, TestnetVersion},
    pow::{Target, Work},
    psbt::Psbt,
    sighash::{EcdsaSighashType, TapSighashType},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
};
// Re-export all modules from `blockdata`, users should never need to use `blockdata` directly.
#[doc(inline)]
pub use crate::{
    // Also, re-export types and modules from `blockdata` that don't come from `primitives`.
    blockdata::locktime::{absolute, relative},
    blockdata::opcodes::{self, Opcode},
    blockdata::script::witness_program::{self, WitnessProgram},
    blockdata::script::witness_version::{self, WitnessVersion},
    // These modules also re-export all the respective `primitives` types.
    blockdata::{block, constants, fee_rate, locktime, script, transaction, weight, witness},
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(all(not(feature = "std"), not(test), target_has_atomic = "ptr"))]
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
    //! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
    //! We refer to the documentation on the types for more information.

    use crate::consensus::{encode, Decodable, Encodable};
    use crate::io::{BufRead, Write};

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(inline)]
    pub use units::amount::{
        Amount, CheckedSum, Denomination, Display, InvalidCharacterError, MissingDenominationError,
        MissingDigitsError, OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, SignedAmount, TooPreciseError,
        UnknownDenominationError,
    };
    #[cfg(feature = "serde")]
    pub use units::amount::serde;

    impl Decodable for Amount {
        #[inline]
        fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
            Ok(Amount::from_sat(Decodable::consensus_decode(r)?))
        }
    }

    impl Encodable for Amount {
        #[inline]
        fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
            self.to_sat().consensus_encode(w)
        }
    }
}

/// Unit parsing utilities.
pub mod parse {
    /// Re-export everything from the [`units::parse`] module.
    #[doc(inline)]
    pub use units::parse::{
        hex_check_unprefixed, hex_remove_prefix, hex_u128, hex_u128_unchecked, hex_u128_unprefixed,
        hex_u32, hex_u32_unchecked, hex_u32_unprefixed, int_from_box, int_from_str,
        int_from_string, ParseIntError, PrefixedHexError, UnprefixedHexError,
    };
}

mod encode_impls {
    //! Encodable/Decodable implementations.
    // While we are deprecating, re-exporting, and generally moving things around just put these here.

    use units::{BlockHeight, BlockInterval};

    use crate::consensus::{encode, Decodable, Encodable};
    use crate::io::{BufRead, Write};

    /// Implements Encodable and Decodable for a simple wrapper type.
    ///
    /// Wrapper type is required to implement `to_u32()` and `From<u32>`.
    macro_rules! impl_encodable_for_u32_wrapper {
        ($ty:ident) => {
            impl Decodable for $ty {
                #[inline]
                fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
                    let inner = u32::consensus_decode(r)?;
                    Ok($ty::from(inner))
                }
            }

            impl Encodable for $ty {
                #[inline]
                fn consensus_encode<W: Write + ?Sized>(
                    &self,
                    w: &mut W,
                ) -> Result<usize, io::Error> {
                    let inner = self.to_u32();
                    inner.consensus_encode(w)
                }
            }
        };
    }

    impl_encodable_for_u32_wrapper!(BlockHeight);
    impl_encodable_for_u32_wrapper!(BlockInterval);
}
