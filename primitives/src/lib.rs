// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin - primitive types
//!
//! Primitive data types that are used throughout the [`rust-bitcoin`] ecosystem.
//!
//! If you are using `rust-bitcoin` then you do not need to access this crate directly. Everything
//! here is re-exported in `rust-bitcoin` at the same path.
//!
//! This crate can be used in a no-std environment but a lot of the functionality requires an
//! allocator i.e., requires the `alloc` feature to be enabled.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin>

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Exclude lints we don't think are valuable.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "hex")]
pub extern crate hex_stable as hex;

#[doc(hidden)]
pub mod _export {
    /// A re-export of `core::*`.
    pub mod _core {
        pub use core::*;
    }
}

mod hash_types;
#[cfg(feature = "alloc")]
mod opcodes;

pub mod block;
pub mod merkle_tree;
pub mod pow;
#[cfg(feature = "alloc")]
pub mod script;
pub mod transaction;
#[cfg(feature = "alloc")]
pub mod witness;

#[doc(inline)]
pub use units::{
    amount::{self, Amount, SignedAmount},
    block::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval},
    fee_rate::{self, FeeRate},
    locktime::{self, absolute, relative},
    parse_int,
    result::{self, NumOpResult},
    sequence::{self, Sequence},
    time::{self, BlockTime, BlockTimeDecoder, BlockTimeDecoderError},
    weight::{self, Weight},
};

#[deprecated(since = "1.0.0-rc.0", note = "use `BlockHeightInterval` instead")]
#[doc(hidden)]
pub type BlockInterval = BlockHeightInterval;

#[doc(inline)]
#[cfg(feature = "alloc")]
pub use self::{
    block::{
        Block, Checked as BlockChecked, Unchecked as BlockUnchecked, Validation as BlockValidation,
    },
    script::{
        RedeemScript, RedeemScriptBuf, ScriptPubKey, ScriptPubKeyBuf, ScriptSig, ScriptSigBuf,
        TapScript, TapScriptBuf, WitnessScript, WitnessScriptBuf,
    },
    transaction::{Transaction, TxIn, TxOut},
    witness::Witness,
};
#[doc(inline)]
pub use self::{
    block::{BlockHash, Header as BlockHeader, Version as BlockVersion, WitnessCommitment},
    merkle_tree::{TxMerkleNode, WitnessMerkleNode},
    pow::CompactTarget,
    transaction::{Ntxid, OutPoint, Txid, Version as TransactionVersion, Wtxid},
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

#[cfg(all(feature = "hex", feature = "alloc"))]
use core::{fmt, convert};

#[cfg(all(feature = "hex", feature = "alloc"))]
use encoding::{Decodable, Decoder};
#[cfg(all(feature = "hex", feature = "alloc"))]
use internals::write_err;

/// An error type for errors that can occur during parsing of a `Decodable` type from hex.
#[cfg(all(feature = "hex", feature = "alloc"))]
#[non_exhaustive]
pub enum ParsePrimitiveError<T: Decodable> {
    /// Tried to decode an odd length string
    OddLengthString(hex_unstable::OddLengthStringError),
    /// Encountered an invalid hex character
    InvalidChar(hex_unstable::InvalidCharError),
    /// A decode error from `consensus_encoding`
    Decode(<T::Decoder as Decoder>::Error),
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl<T: Decodable> fmt::Debug for ParsePrimitiveError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLengthString(odd_err) => write_err!(f, "odd length string"; odd_err),
            Self::InvalidChar(char_err) => write_err!(f, "invalid character"; char_err),
            // Decoder error types don't have Debug, so we only provide this generic error
            Self::Decode(_) => write!(f, "failure decoding hex string into {}", core::any::type_name::<T>()),
        }
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl<T: Decodable> From<convert::Infallible> for ParsePrimitiveError<T> {
    fn from(never: convert::Infallible) -> Self { match never {} }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
impl<T: Decodable> fmt::Display for ParsePrimitiveError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

#[cfg(all(feature = "hex", feature = "alloc", feature = "std"))]
impl<T: Decodable> std::error::Error for ParsePrimitiveError<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OddLengthString(ref e) => Some(e),
            Self::InvalidChar(ref e) => Some(e),
            Self::Decode(_) => None,
        }
    }
}

#[cfg(all(feature = "hex", feature = "alloc"))]
pub(crate) mod hex_codec {
    use super::{fmt, Decodable, ParsePrimitiveError};

    use encoding::{Encodable, EncodableByteIter};
    use hex_unstable::{HexToBytesIter, BytesToHexIter, Case};

    /// Writes an Encodable object to the given formatter in the requested case.
    #[inline]
    fn hex_write_tx_with_case<T: Encodable + Decodable>(obj: &HexPrimitive<T>, f: &mut fmt::Formatter, case: Case) -> fmt::Result {
        let iter = BytesToHexIter::new(
            encoding::EncodableByteIter::new(obj.0),
            case
        );
        let collection = iter.collect::<alloc::string::String>();
        f.pad(&collection)
    }

    /// Hex encoding wrapper type for Encodable + Decodable types.
    ///
    /// Provides default implementations for `Display`, `Debug`, `LowerHex`, and `UpperHex`.
    /// Also provides [`Self::from_str`] for parsing a string to a `T`.
    /// This can be used to implement hex display traits for any encodable types.
    pub struct HexPrimitive<'a, T: Encodable + Decodable>(pub &'a T);

    impl<'a, T: Encodable + Decodable> IntoIterator for &HexPrimitive<'a, T> {
        type Item = u8;
        type IntoIter = EncodableByteIter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            EncodableByteIter::new(self.0)
        }
    }

    impl<T: Encodable + Decodable> HexPrimitive<'_, T> {
        /// Parses a given string into an instance of the type `T`.
        ///
        /// Since `FromStr` would return an instance of Self and thus a &T, this function
        /// is implemented directly on the struct to return the owned instance of T.
        /// Other `FromStr` implementations can directly return the result of
        /// [`DisplayHexPrimitive::from_str`].
        ///
        /// # Errors
        ///
        /// [`ParsePrimitiveError::OddLengthStringError`] if the input string is an odd length
        /// [`ParsePrimitiveError::DecodeError`] if some error occurs during decoding the object
        pub fn from_str(s: &str) -> Result<T, ParsePrimitiveError<T>> {
            let bytes = HexToBytesIter::new(s)
                .map_err(ParsePrimitiveError::OddLengthString)?
                .collect::<Result<alloc::vec::Vec<u8>, hex_unstable::InvalidCharError>>()
                .map_err(ParsePrimitiveError::InvalidChar)?;

            encoding::decode_from_slice(&bytes).map_err(ParsePrimitiveError::Decode)
        }
    }

    impl<T: Encodable + Decodable> fmt::Display for HexPrimitive<'_, T> {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
    }

    impl<T: Encodable + Decodable> fmt::Debug for HexPrimitive<'_, T> {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
    }

    impl<T: Encodable + Decodable> fmt::LowerHex for HexPrimitive<'_, T> {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { hex_write_tx_with_case(self, f, Case::Lower) }
    }

    impl<T: Encodable + Decodable> fmt::UpperHex for HexPrimitive<'_, T> {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { hex_write_tx_with_case(self, f, Case::Upper) }
    }
}
