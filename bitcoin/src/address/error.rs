//! Error code for the address module.

use core::fmt;

use internals::write_err;

use crate::address::{Address, NetworkUnchecked};
use crate::blockdata::script::{witness_program, witness_version};
use crate::prelude::String;
use crate::{base58, Network};

/// Address error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A witness version construction error.
    WitnessVersion(witness_version::TryFromError),
    /// A witness program error.
    WitnessProgram(witness_program::Error),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// Address's network differs from required one.
    NetworkValidation {
        /// Network that was required.
        required: Network,
        /// Network on which the address was found to be valid.
        found: Network,
        /// The address itself
        address: Address<NetworkUnchecked>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            WitnessVersion(ref e) => write_err!(f, "witness version construction error"; e),
            WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            UncompressedPubkey =>
                write!(f, "an uncompressed pubkey was used where it is not allowed"),
            ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
            UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
            NetworkValidation { required, found, ref address } => {
                write!(f, "address ")?;
                address.fmt_internal(f)?; // Using fmt_internal in order to remove the "Address<NetworkUnchecked>(..)" wrapper
                write!(
                    f,
                    " belongs to network {} which is different from required {}",
                    found, required
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            WitnessVersion(e) => Some(e),
            WitnessProgram(e) => Some(e),
            UncompressedPubkey
            | ExcessiveScriptSize
            | UnrecognizedScript
            | NetworkValidation { .. } => None,
        }
    }
}

impl From<witness_version::TryFromError> for Error {
    fn from(e: witness_version::TryFromError) -> Error { Error::WitnessVersion(e) }
}

impl From<witness_program::Error> for Error {
    fn from(e: witness_program::Error) -> Error { Error::WitnessProgram(e) }
}

/// Address type is either invalid or not supported in rust-bitcoin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownAddressTypeError(pub String);

impl fmt::Display for UnknownAddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "failed to parse {} as address type", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownAddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Address parsing error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Base58 error.
    Base58(base58::Error),
    /// Bech32 segwit decoding error.
    Bech32(bech32::segwit::DecodeError),
    /// A witness version conversion/parsing error.
    WitnessVersion(witness_version::TryFromError),
    /// A witness program error.
    WitnessProgram(witness_program::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 error"; e),
            Bech32(ref e) => write_err!(f, "bech32 segwit decoding error"; e),
            WitnessVersion(ref e) => write_err!(f, "witness version conversion/parsing error"; e),
            WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Base58(ref e) => Some(e),
            Bech32(ref e) => Some(e),
            WitnessVersion(ref e) => Some(e),
            WitnessProgram(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for ParseError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}

impl From<bech32::segwit::DecodeError> for ParseError {
    fn from(e: bech32::segwit::DecodeError) -> Self { Self::Bech32(e) }
}

impl From<witness_version::TryFromError> for ParseError {
    fn from(e: witness_version::TryFromError) -> Self { Self::WitnessVersion(e) }
}

impl From<witness_program::Error> for ParseError {
    fn from(e: witness_program::Error) -> Self { Self::WitnessProgram(e) }
}
