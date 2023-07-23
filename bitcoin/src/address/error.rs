// SPDX-License-Identifier: CC0-1.0

//! Error code for the `address` module.

use core::fmt;

use internals::write_err;

use super::{Address, NetworkUnchecked};
use crate::blockdata::script::{witness_program, witness_version};
use crate::{base58, Network};

/// Address error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
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
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// Address type is either invalid or not supported in rust-bitcoin.
    UnknownAddressType(String),
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
            UncompressedPubkey =>
                write!(f, "an uncompressed pubkey was used where it is not allowed"),
            ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
            UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
            UnknownAddressType(ref s) => write!(
                f,
                "unknown address type: '{}' is either invalid or not supported in rust-bitcoin",
                s
            ),
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
        use self::Error::*;

        match *self {
            Base58(ref e) => Some(e),
            Bech32(ref e) => Some(e),
            WitnessVersion(ref e) => Some(e),
            WitnessProgram(ref e) => Some(e),
            EmptyBech32Payload
            | InvalidBech32Variant { .. }
            | UncompressedPubkey
            | ExcessiveScriptSize
            | UnrecognizedScript
            | UnknownAddressType(_)
            | NetworkValidation { .. } => None,
        }
    }
}

impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error { Error::Base58(e) }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error { Error::Bech32(e) }
}

impl From<witness_version::Error> for Error {
    fn from(e: witness_version::Error) -> Error { Error::WitnessVersion(e) }
}

impl From<witness_program::Error> for Error {
    fn from(e: witness_program::Error) -> Error { Error::WitnessProgram(e) }
}
