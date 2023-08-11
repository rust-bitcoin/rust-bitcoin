// SPDX-License-Identifier: CC0-1.0

//! Error code for the signature hash implementation.

use core::fmt;

#[cfg(doc)]
use crate::crypto::sighash::Prevouts;
use crate::error::impl_std_error;
use crate::io;
use crate::prelude::String;

/// Possible errors in computing the signature message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Could happen only by using `*_encode_signing_*` methods with custom writers, engines writers
    /// like the ones used in methods `*_signature_hash` do not error.
    Io(io::ErrorKind),

    /// Requested index is greater or equal than the number of inputs in the transaction.
    IndexOutOfInputsBounds {
        /// Requested index.
        index: usize,
        /// Number of transaction inputs.
        inputs_size: usize,
    },

    /// Using `SIGHASH_SINGLE` without a "corresponding output" (an output with the same index as
    /// the input being verified) is a validation failure.
    SingleWithoutCorrespondingOutput {
        /// Requested index.
        index: usize,
        /// Number of transaction outputs.
        outputs_size: usize,
    },

    /// There are mismatches in the number of prevouts provided compared to the number of inputs in
    /// the transaction.
    PrevoutsSize,

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [`Prevouts::One`] with different index.
    PrevoutIndex,

    /// A single prevout has been provided but all prevouts are needed unless using
    /// `SIGHASH_ANYONECANPAY`.
    PrevoutKind,

    /// Annex must be at least one byte long and the first bytes must be `0x50`.
    WrongAnnex,

    /// Invalid Sighash type.
    InvalidSighashType(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            Io(error_kind) => write!(f, "writer errored: {:?}", error_kind),
            IndexOutOfInputsBounds { index, inputs_size } => write!(f, "requested index ({}) is greater or equal than the number of transaction inputs ({})", index, inputs_size),
            SingleWithoutCorrespondingOutput { index, outputs_size } => write!(f, "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})", index, outputs_size),
            PrevoutsSize => write!(f, "number of supplied prevouts differs from the number of inputs in transaction"),
            PrevoutIndex => write!(f, "the index requested is greater than available prevouts or different from the provided [Provided::Anyone] index"),
            PrevoutKind => write!(f, "a single prevout has been provided but all prevouts are needed without `ANYONECANPAY`"),
            WrongAnnex => write!(f, "annex must be at least one byte long and the first bytes must be `0x50`"),
            InvalidSighashType(hash_ty) => write!(f, "Invalid taproot signature hash type : {} ", hash_ty),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            Io(_)
            | IndexOutOfInputsBounds { .. }
            | SingleWithoutCorrespondingOutput { .. }
            | PrevoutsSize
            | PrevoutIndex
            | PrevoutKind
            | WrongAnnex
            | InvalidSighashType(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::Io(e.kind()) }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvalidSighashTypeError(pub u32);

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid sighash type {}", self.0)
    }
}

impl_std_error!(InvalidSighashTypeError);

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

impl_std_error!(NonStandardSighashTypeError);

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

impl_std_error!(SighashTypeParseError);
