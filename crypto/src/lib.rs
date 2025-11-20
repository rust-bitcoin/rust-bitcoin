// SPDX-License-Identifier: CC0-1.0

//! Cryptography support for the rust-bitcoin ecosystem.
//!
//! Cryptography related functionality: keys and signatures.

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

pub mod ecdsa;
pub mod key;
pub mod taproot;

use core::{fmt, str};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{sha256t, HashEngine as _};
use primitives::script::{WScriptHash, WitnessProgram, WitnessScript, WitnessScriptSizeError};
use secp256k1::Scalar;
use taproot_primitives::{TapNodeHash, TapTweakHash, TapTweakTag};

#[cfg(feature = "alloc")]
use crate::prelude::{String, ToOwned};
use crate::key::TapTweak as _;

// FIXME: Brain fried right now, re-visit these re-exports.
#[rustfmt::skip]                // Keep public re-exports separate.
pub use self::key::{CompressedPublicKey, PrivateKey, PublicKey, XOnlyPublicKey,  TweakedPublicKey, UntweakedPublicKey, SortKey, PubkeyHash, WPubkeyHash, TweakedKeypair};

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding (see also
/// [`TapSighashType`]).
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EcdsaSighashType::*;

        let s = match self {
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "alloc")]
impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EcdsaSighashType::*;

        match s {
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Checks if the sighash type is [`Self::Single`] or [`Self::SinglePlusAnyoneCanPay`].
    ///
    /// This matches Bitcoin Core's behavior where SIGHASH_SINGLE bug check is based on the base
    /// type (after masking with 0x1f), regardless of the ANYONECANPAY flag.
    ///
    /// See: <https://github.com/bitcoin/bitcoin/blob/e486597/src/script/interpreter.cpp#L1618-L1619>
    pub fn is_single(&self) -> bool { matches!(self, Self::Single | Self::SinglePlusAnyoneCanPay) }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it to compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> Self {
        use EcdsaSighashType::*;

        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => AllPlusAnyoneCanPay,
            _ => All,
        }
    }

    /// Constructs a new [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<Self, NonStandardSighashTypeError> {
        use EcdsaSighashType::*;

        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(All),
            0x02 => Ok(None),
            0x03 => Ok(Single),
            0x81 => Ok(AllPlusAnyoneCanPay),
            0x82 => Ok(NonePlusAnyoneCanPay),
            0x83 => Ok(SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

impl From<EcdsaSighashType> for TapSighashType {
    fn from(s: EcdsaSighashType) -> Self {
        use TapSighashType::*;

        match s {
            EcdsaSighashType::All => All,
            EcdsaSighashType::None => None,
            EcdsaSighashType::Single => Single,
            EcdsaSighashType::AllPlusAnyoneCanPay => AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay => NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay => SinglePlusAnyoneCanPay,
        }
    }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
/// Fixed values so they can be cast as integer types for encoding.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TapSighashType {
    /// 0x0: Used when not explicitly specified, defaults to [`TapSighashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
internals::serde_string_impl!(TapSighashType, "a TapSighashType data");

impl fmt::Display for TapSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TapSighashType::*;

        let s = match self {
            Default => "SIGHASH_DEFAULT",
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "alloc")]
impl str::FromStr for TapSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use TapSighashType::*;

        match s {
            "SIGHASH_DEFAULT" => Ok(Default),
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl TapSighashType {
    /// Constructs a new [`TapSighashType`] from a raw `u8`.
    pub fn from_consensus_u8(sighash_type: u8) -> Result<Self, InvalidSighashTypeError> {
        use TapSighashType::*;

        Ok(match sighash_type {
            0x00 => Default,
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            x => return Err(InvalidSighashTypeError(x.into())),
        })
    }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSighashTypeError(pub u32);

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
// FIXME: bitcoin::psbt::input is abusing this error type.
//#[non_exhaustive]
#[cfg(feature = "alloc")]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

#[cfg(feature = "alloc")]
impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Extension functionality for the [`TapTweakHash`] type.
pub trait TapTweakHashExt: sealed::Sealed {
    /// Constructs a new BIP-0341 [`TapTweakHash`] from key and Merkle root. Produces `H_taptweak(P||R)` where
    /// `P` is the internal key and `R` is the Merkle root.
    fn from_key_and_merkle_root<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self;

    /// Converts a `TapTweakHash` into a `Scalar` ready for use with key tweaking API.
    fn to_scalar(self) -> Scalar;
}

impl TapTweakHashExt for TapTweakHash {
    fn from_key_and_merkle_root<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let mut eng = sha256t::Hash::<TapTweakTag>::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(h.as_ref());
        } else {
            // nothing to hash
        }
        let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
        Self::from_byte_array(inner.to_byte_array())
    }

     fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

/// Extension functionality for the [`WitnessProgram`] type.
pub trait WitnessProgramExt: sealed::Sealed {
    /// Constructs a new [`WitnessProgram`] from `pk` for a P2WPKH output.
    fn p2wpkh(pk: CompressedPublicKey) -> Self;

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    fn p2wsh(script: &WitnessScript) -> Result<WitnessProgram, WitnessScriptSizeError>;

    /// Constructs a new [`WitnessProgram`] from `script` for a P2WSH output.
    fn p2wsh_from_hash(hash: WScriptHash) -> WitnessProgram;

    /// Constructs a new [`WitnessProgram`] from an untweaked key for a P2TR output.
    ///
    /// This function applies BIP-0341 key-tweaking to the untweaked
    /// key using the merkle root, if it's present.
    fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> WitnessProgram;

    /// Constructs a new [`WitnessProgram`] from a tweaked key for a P2TR output.
    fn p2tr_tweaked(output_key: TweakedPublicKey) -> WitnessProgram;
}

impl WitnessProgramExt for WitnessProgram {
    fn p2wpkh(pk: CompressedPublicKey) -> Self {
        let hash = pk.wpubkey_hash();
        Self::new_p2wpkh(hash.to_byte_array())
    }

    fn p2wsh(script: &WitnessScript) -> Result<Self, WitnessScriptSizeError> {
        WScriptHash::try_from(script).map(Self::p2wsh_from_hash)
    }

    fn p2wsh_from_hash(hash: WScriptHash) -> Self { Self::new_p2wsh(hash.to_byte_array()) }

    fn p2tr<K: Into<UntweakedPublicKey>>(
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let internal_key = internal_key.into();
        let (output_key, _parity) = internal_key.tap_tweak(merkle_root);
        let pubkey = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }

    fn p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        let pubkey = output_key.as_x_only_public_key().serialize();
        Self::new_p2tr(pubkey)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::TapTweakHash {}
    impl Sealed for super::WitnessProgram {}
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EcdsaSighashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=5)?;
        match choice {
            0 => Ok(Self::All),
            1 => Ok(Self::None),
            2 => Ok(Self::Single),
            3 => Ok(Self::AllPlusAnyoneCanPay),
            4 => Ok(Self::NonePlusAnyoneCanPay),
            _ => Ok(Self::SinglePlusAnyoneCanPay),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for TapSighashType {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=6)?;
        match choice {
            0 => Ok(Self::Default),
            1 => Ok(Self::All),
            2 => Ok(Self::None),
            3 => Ok(Self::Single),
            4 => Ok(Self::AllPlusAnyoneCanPay),
            5 => Ok(Self::NonePlusAnyoneCanPay),
            _ => Ok(Self::SinglePlusAnyoneCanPay),
        }
    }
}

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(feature = "alloc")]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    pub use hex::DisplayHex;
}
