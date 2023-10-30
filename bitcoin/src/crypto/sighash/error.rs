// SPDX-License-Identifier: CC0-1.0

//! Error code for the signature hash implementation.

use core::fmt;

use internals::write_err;

#[cfg(doc)]
use crate::crypto::sighash::Prevouts;
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
    PrevoutsSize(PrevoutsSizeError),

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [`Prevouts::One`] with different index.
    PrevoutsIndex(PrevoutsIndexError),

    /// A single prevout has been provided but all prevouts are needed unless using
    /// `SIGHASH_ANYONECANPAY`.
    PrevoutsKind(PrevoutsKindError),

    /// Annex must be at least one byte long and the first bytes must be `0x50`.
    WrongAnnex,

    /// Invalid Sighash type.
    InvalidSighashType(u32),

    /// Script is not a witness program for a p2wpkh output.
    NotP2wpkhScript,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match *self {
            Io(error_kind) => write!(f, "writer errored: {:?}", error_kind),
            IndexOutOfInputsBounds { index, inputs_size } => write!(f, "requested index ({}) is greater or equal than the number of transaction inputs ({})", index, inputs_size),
            SingleWithoutCorrespondingOutput { index, outputs_size } => write!(f, "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})", index, outputs_size),
            PrevoutsSize(ref e) => write_err!(f, "prevouts size"; e),
            PrevoutsIndex(ref e) => write_err!(f, "prevouts index"; e),
            PrevoutsKind(ref e) => write_err!(f, "prevouts kind"; e),
            WrongAnnex => write!(f, "annex must be at least one byte long and the first bytes must be `0x50`"),
            InvalidSighashType(hash_ty) => write!(f, "Invalid taproot signature hash type : {} ", hash_ty),
            NotP2wpkhScript => write!(f, "script is not a script pubkey for a p2wpkh output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            PrevoutsSize(ref e) => Some(e),
            PrevoutsIndex(ref e) => Some(e),
            PrevoutsKind(ref e) => Some(e),
            Io(_)
            | IndexOutOfInputsBounds { .. }
            | SingleWithoutCorrespondingOutput { .. }
            | WrongAnnex
            | InvalidSighashType(_)
            | NotP2wpkhScript => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::Io(e.kind()) }
}

impl From<PrevoutsSizeError> for Error {
    fn from(e: PrevoutsSizeError) -> Self { Self::PrevoutsSize(e) }
}

impl From<PrevoutsKindError> for Error {
    fn from(e: PrevoutsKindError) -> Self { Self::PrevoutsKind(e) }
}

impl From<PrevoutsIndexError> for Error {
    fn from(e: PrevoutsIndexError) -> Self { Self::PrevoutsIndex(e) }
}

/// The number of supplied prevouts differs from the number of inputs in the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsSizeError;

impl fmt::Display for PrevoutsSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "number of supplied prevouts differs from the number of inputs in transaction")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsSizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// A single prevout was been provided but all prevouts are needed without `ANYONECANPAY`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsKindError;

impl fmt::Display for PrevoutsKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "single prevout provided but all prevouts are needed without `ANYONECANPAY`")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsKindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// [`Prevouts`] index related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrevoutsIndexError {
    /// Invalid index when accessing a [`Prevouts::One`] kind.
    InvalidOneIndex,
    /// Invalid index when accessing a [`Prevouts::All`] kind.
    InvalidAllIndex,
}

impl fmt::Display for PrevoutsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex => write!(f, "invalid index when accessing a Prevouts::One kind"),
            InvalidAllIndex => write!(f, "invalid index when accessing a Prevouts::All kind"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex | InvalidAllIndex => None,
        }
    }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
