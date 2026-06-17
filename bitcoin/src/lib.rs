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
//! * `arbitrary` (dependency) - arbitrary type implementations for testing.
//! * `base64` (dependency) - enables encoding of PSBTs and message signatures.
//! * `bitcoinconsensus` (dependency) - enables validating scripts and transactions.
//! * `default` - enables `std` and `secp-recovery`.
//! * `rand` (transitive dependency) - makes it more convenient to generate random values.
//! * `serde` (dependency) - implements `serde`-based serialization and deserialization.
//! * `secp-lowmemory` - optimizations for low-memory devices.
//! * `secp-recovery` - enables calculating public key from a signature and message.
//! * `std` - the usual dependency on `std`.

#![no_std]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_notable_trait))]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Instead of littering the codebase for non-fuzzing and bench code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::incompatible_msrv)] // Has FPs and we're testing it which is more reliable anyway.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

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

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;

pub extern crate base58;
#[cfg(feature = "base64")]
pub extern crate base64;
pub extern crate bech32;
pub extern crate encoding;
pub extern crate hashes;
pub extern crate hex;
pub extern crate io;
pub extern crate primitives;
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[macro_use]
pub extern crate serde;

mod internal_macros;

include!("../include/array_newtype.rs");
include!("../include/newtype.rs"); // Explained in `REPO_DIR/docs/README.md`.

pub mod ext {
    //! Re-export all the extension traits so downstream can use wildcard imports.
    //!
    //! As part of stabilizing `primitives` and `units` we created a bunch of extension traits in
    //! `rust-bitcoin` to hold all the API that we are not yet ready to stabilize. This module
    //! re-exports all of them to improve ergonomics for users comfortable with wildcard imports.
    //!
    //! # Examples
    //!
    //! ```
    //! # #![allow(unused_imports)] // Because that is what we are demoing.
    //! // Wildcard import all of the extension traits.
    //! use bitcoin::ext::*;
    //!
    //! // If, for some reason, you want the name to be in scope access it via the module. E.g.
    //! use bitcoin::script::ScriptSigExt;
    //! ```
    #[rustfmt::skip] // Use terse custom grouping.
    pub use crate::{
        block::{BlockCheckedExt as _, HeaderExt as _},
        key::{FullPublicKeyExt as _, LegacyPublicKeyExt as _},
        network::NetworkExt as _,
        opcodes::OpcodeExt as _,
        pow::{CompactTargetExt as _, TargetExt as _, WorkExt as _},
        script::{BuilderExt as _, PushBytesExt as _, ScriptExt as _, ScriptBufExt as _, TapScriptExt as _, ScriptPubKeyExt as _, ScriptPubKeyBufExt as _, WitnessScriptExt as _, ScriptSigExt as _},
        taproot::{TapLeafHashExt as _, TapNodeHashExt as _},
        transaction::{TxidExt as _, WtxidExt as _, OutPointExt as _, TxInExt as _, TxOutExt as _, TransactionExt as _},
        witness::WitnessExt as _,
    };
    #[cfg(feature = "bitcoinconsensus")]
    pub use crate::consensus_validation::{ScriptPubKeyExt as _, TransactionExt as _};
    #[cfg(feature = "secp-recovery")]
    pub use crate::key::PrivateKeyExt as _;
}
pub mod address;
pub mod bip158;
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
pub mod sign_message;
pub mod taproot;

// Re-export the type from where it is defined but the module from the highest place up the stack
// that it is available in the event that we add some functionality there.
#[doc(inline)]
pub use primitives::{
    block::{
        compute_merkle_root, compute_witness_root, Block, BlockHash, Checked as BlockChecked,
        Header as BlockHeader, InvalidBlockError, Unchecked as BlockUnchecked,
        Validation as BlockValidation, Version as BlockVersion, WitnessCommitment,
    },
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    script::{
        RedeemScript, RedeemScriptBuf, RedeemScriptTag, ScriptHashableTag, ScriptPubKey,
        ScriptPubKeyBuf, ScriptPubKeyTag, ScriptSig, ScriptSigBuf, ScriptSigTag, SignetBlockScript,
        SignetBlockScriptBuf, SignetBlockScriptTag, Tag, TapScript, TapScriptBuf, TapScriptTag,
        WitnessScript, WitnessScriptBuf, WitnessScriptTag,
    },
    transaction::{OutPoint, Transaction, TxIn, TxOut, Txid, Version as TransactionVersion, Wtxid},
    witness::Witness,
};
#[doc(inline)]
pub use units::{
    amount::{Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::FeeRate,
    parse_int,
    pow::CompactTarget,
    result::{self, NumOpResult},
    sequence::{self, Sequence},
    time::{self, BlockTime, BlockTimeDecoder, BlockTimeDecoderError},
    weight::Weight,
};

#[deprecated(since = "TBD", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

#[deprecated(since = "TBD", note = "use `FullPublicKey` instead")]
#[doc(hidden)]
pub type CompressedPublicKey = FullPublicKey;

#[deprecated(since = "TBD", note = "use `LegacyPublicKey` instead")]
#[doc(hidden)]
pub type PublicKey = LegacyPublicKey;

// Re-export modules directly from lower level crates
#[doc(inline)]
pub use key_expression::bip32;

#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    bip32::XKeyIdentifier,
    crypto::ecdsa,
    crypto::key::{
        self, FullPublicKey, Keypair, LegacyPublicKey, PrivateKey, WifKey, XOnlyPublicKey,
    },
    crypto::sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    network::params::{self, Params},
    network::{Network, NetworkKind, TestnetVersion},
    pow::{Target, Work},
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
    #[cfg(not(feature = "std"))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    #[cfg(target_has_atomic = "ptr")]
    #[cfg(not(feature = "std"))]
    pub use alloc::sync;

    #[cfg(feature = "std")]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc, sync};

    #[cfg(not(feature = "std"))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "std")]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use crate::io::sink;

    pub use hex::DisplayHex;
}

pub mod amount {
    //! Bitcoin amounts.
    //!
    //! This module mainly introduces the [`Amount`] and [`SignedAmount`] types.
    //! We refer to the documentation on the types for more information.

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[cfg(feature = "serde")]
    pub use units::amount::serde;
    #[doc(inline)]
    pub use units::amount::{Amount, AmountDecoder, AmountEncoder, SignedAmount};
    #[doc(no_inline)]
    pub use units::amount::{Denomination, Display};

    #[doc(no_inline)]
    pub use self::error::{
        AmountDecoderError, BadPositionError, InputTooLargeError, InvalidCharacterError,
        MissingDenominationError, MissingDigitsError, OutOfRangeError, ParseAmountError,
        ParseDenominationError, ParseError, PossiblyConfusingDenominationError, TooPreciseError,
        UnknownDenominationError,
    };

    /// Error types for bitcoin amounts.
    pub mod error {
        pub use units::amount::error::{
            AmountDecoderError, BadPositionError, InputTooLargeError, InvalidCharacterError,
            MissingDenominationError, MissingDigitsError, OutOfRangeError, ParseAmountError,
            ParseDenominationError, ParseError, PossiblyConfusingDenominationError,
            TooPreciseError, UnknownDenominationError,
        };
    }
}

/// A conversion trait for unsigned integer types smaller than or equal to 64-bits.
///
/// This trait exists because [`usize`] doesn't implement `Into<u64>`. We only support 32 and 64 bit
/// architectures because of consensus code so we can infallibly do the conversion.
pub trait ToU64 {
    /// Converts unsigned integer type to a [`u64`].
    fn to_u64(self) -> u64;
}

macro_rules! impl_to_u64 {
    ($($ty:ident),*) => {
        $(
            impl ToU64 for $ty { fn to_u64(self) -> u64 { self.into() } }
        )*
    }
}
impl_to_u64!(u8, u16, u32, u64);

impl ToU64 for usize {
    fn to_u64(self) -> u64 {
        internals::const_assert!(
            core::mem::size_of::<usize>() <= 8;
            "platforms that have usize larger than 64 bits are not supported"
        );
        self as u64
    }
}
