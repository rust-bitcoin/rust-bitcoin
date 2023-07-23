// SPDX-License-Identifier: CC0-1.0

//! Error code for the `address` module.

use core::fmt;

use internals::write_err;

use super::{Address, NetworkUnchecked};
use crate::blockdata::script::{witness_program, witness_version};
use crate::{base58, Network};

/// A general purpose address error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Parsing address from string failed.
    Parse(ParseError),
    /// A payload related error.
    Payload(PayloadError),
    /// Address is not valid for network.
    RequireNetwork(RequireNetworkError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Parse(ref e) => write_err!(f, "parsing address failed"; e),
            Payload(ref e) => write_err!(f, "payload error"; e),
            RequireNetwork(ref e) => write_err!(f, "require network"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            Parse(ref e) => Some(e),
            Payload(ref e) => Some(e),
            RequireNetwork(ref e) => Some(e),
        }
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self { Self::Parse(e) }
}

impl From<PayloadError> for Error {
    fn from(e: PayloadError) -> Self { Self::Payload(e) }
}

impl From<RequireNetworkError> for Error {
    fn from(e: RequireNetworkError) -> Self { Self::RequireNetwork(e) }
}

/// Address parsing error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ParseError {
    /// Base58 encoding error.
    Base58(base58::Error),
    /// Bech32 encoding error.
    Bech32(bech32::Error),
    /// The bech32 payload was empty.
    EmptyBech32Payload,
    /// The wrong checksum algorithm was used. See BIP-0350.
    InvalidBech32Variant {
        /// Bech32 variant that is required by the used Witness version.
        expected: bech32::Variant,
        /// The actual Bech32 variant encoded in the address representation.
        found: bech32::Variant,
    },
    /// A witness version conversion/parsing error.
    WitnessVersion(witness_version::Error),
    /// A witness program error.
    WitnessProgram(witness_program::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 address encoding error"; e),
            Bech32(ref e) => write_err!(f, "bech32 address encoding error"; e),
            EmptyBech32Payload => write!(f, "the bech32 payload was empty"),
            InvalidBech32Variant { expected, found } => write!(
                f,
                "invalid bech32 checksum variant found {:?} when {:?} was expected",
                found, expected
            ),
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
            EmptyBech32Payload | InvalidBech32Variant { .. } => None,
        }
    }
}

impl From<base58::Error> for ParseError {
    fn from(e: base58::Error) -> Self { Self::Base58(e) }
}

impl From<bech32::Error> for ParseError {
    fn from(e: bech32::Error) -> Self { Self::Bech32(e) }
}

impl From<witness_version::Error> for ParseError {
    fn from(e: witness_version::Error) -> Self { Self::WitnessVersion(e) }
}

impl From<witness_program::Error> for ParseError {
    fn from(e: witness_program::Error) -> Self { Self::WitnessProgram(e) }
}

/// A payload related error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum PayloadError {
    /// A witness version conversion/parsing error.
    WitnessVersion(witness_version::Error),
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

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PayloadError::*;

        match *self {
            WitnessVersion(ref e) => write_err!(f, "witness version conversion/parsing error"; e),
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
impl std::error::Error for PayloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::PayloadError::*;

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

impl From<witness_version::Error> for PayloadError {
    fn from(e: witness_version::Error) -> Self { Self::WitnessVersion(e) }
}

impl From<witness_program::Error> for PayloadError {
    fn from(e: witness_program::Error) -> Self { Self::WitnessProgram(e) }
}

/// Address is not valid for network.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequireNetworkError(pub Network);

impl fmt::Display for RequireNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "address is not valid for the {} network", self.0)
    }
}

crate::error::impl_std_error!(RequireNetworkError);
