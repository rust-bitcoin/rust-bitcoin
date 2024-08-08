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
//! * `ordered` (dependency) - adds implementations of `ArbitraryOrd` to some structs.
//! * `rand` (transitive dependency) - makes it more convenient to generate random values.
//! * `rand-std` - same as `rand` but also enables `std` here and in `secp256k1`.
//! * `serde` (dependency) - implements `serde`-based serialization and deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `std` - the usual dependency on `std`.

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

/// Rust wrapper library for Pieter Wuille's libsecp256k1.  Implements ECDSA and BIP 340 signatures
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

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    amount::{Amount, Denomination, SignedAmount},
    bip158::{FilterHash, FilterHeader},
    bip32::XKeyIdentifier,
    blockdata::block::{self, Block, BlockHash, WitnessCommitment},
    blockdata::constants,
    blockdata::fee_rate::FeeRate,
    blockdata::locktime::{self, absolute, relative},
    blockdata::opcodes::{self, Opcode},
    blockdata::script::witness_program::{self, WitnessProgram},
    blockdata::script::witness_version::{self, WitnessVersion},
    blockdata::script::{self, Script, ScriptBuf, ScriptHash, WScriptHash},
    blockdata::transaction::{self, OutPoint, Transaction, TxIn, TxOut, Txid, Wtxid},
    blockdata::weight::Weight,
    blockdata::witness::{self, Witness},
    consensus::encode::VarInt,
    crypto::ecdsa,
    crypto::key::{self, PrivateKey, PubkeyHash, PublicKey, CompressedPublicKey, WPubkeyHash, XOnlyPublicKey},
    crypto::sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    merkle_tree::{MerkleBlock, TxMerkleNode, WitnessMerkleNode},
    network::{Network, NetworkKind},
    network::params::{self, Params},
    pow::{CompactTarget, Target, Work},
    psbt::Psbt,
    sighash::{EcdsaSighashType, TapSighashType},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
};
#[doc(inline)]
pub use primitives::Sequence;
pub use units::{BlockHeight, BlockInterval};

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
    //! This module mainly introduces the [Amount] and [SignedAmount] types.
    //! We refer to the documentation on the types for more information.

    use crate::consensus::{encode, Decodable, Encodable};
    use crate::io::{BufRead, Write};

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(inline)]
    pub use units::amount::{
        Amount, CheckedSum, Denomination, Display, ParseAmountError, SignedAmount,
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
        hex_u32, hex_u32_unchecked, hex_u32_unprefixed, int, ContainsPrefixError,
        MissingPrefixError, ParseIntError, PrefixedHexError, UnprefixedHexError,
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
