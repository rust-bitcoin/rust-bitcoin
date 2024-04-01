//! Error code for the address module.

use core::fmt;

use internals::write_err;

use crate::address::{Address, NetworkUnchecked};
use crate::blockdata::script::{witness_program, witness_version};
use crate::prelude::*;
use crate::Network;

/// Error while generating address from script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromScriptError {
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// A witness program error.
    WitnessProgram(witness_program::Error),
    /// A witness version construction error.
    WitnessVersion(witness_version::TryFromError),
}

internals::impl_from_infallible!(FromScriptError);

impl fmt::Display for FromScriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromScriptError::*;

        match *self {
            WitnessVersion(ref e) => write_err!(f, "witness version construction error"; e),
            WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromScriptError::*;

        match *self {
            UnrecognizedScript => None,
            WitnessVersion(ref e) => Some(e),
            WitnessProgram(ref e) => Some(e),
        }
    }
}

impl From<witness_program::Error> for FromScriptError {
    fn from(e: witness_program::Error) -> Self { Self::WitnessProgram(e) }
}

impl From<witness_version::TryFromError> for FromScriptError {
    fn from(e: witness_version::TryFromError) -> Self { Self::WitnessVersion(e) }
}

/// Error while generating address from a p2sh script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum P2shError {
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
}

internals::impl_from_infallible!(P2shError);

impl fmt::Display for P2shError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use P2shError::*;

        match *self {
            ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for P2shError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use P2shError::*;

        match self {
            ExcessiveScriptSize => None,
        }
    }
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
    /// Tried to parse an unknown HRP.
    UnknownHrp(UnknownHrpError),
    /// Legacy address is too long.
    LegacyAddressTooLong(LegacyAddressTooLongError),
    /// Invalid base58 payload data length for legacy address.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Invalid legacy address prefix in base58 data payload.
    InvalidLegacyPrefix(InvalidLegacyPrefixError),
    /// Address's network differs from required one.
    NetworkValidation(NetworkValidationError),
}

internals::impl_from_infallible!(ParseError);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 error"; e),
            Bech32(ref e) => write_err!(f, "bech32 segwit decoding error"; e),
            WitnessVersion(ref e) => write_err!(f, "witness version conversion/parsing error"; e),
            WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            UnknownHrp(ref e) => write_err!(f, "tried to parse an unknown hrp"; e),
            LegacyAddressTooLong(ref e) => write_err!(f, "legacy address base58 string"; e),
            InvalidBase58PayloadLength(ref e) => write_err!(f, "legacy address base58 data"; e),
            InvalidLegacyPrefix(ref e) => write_err!(f, "legacy address base58 prefix"; e),
            NetworkValidation(ref e) => write_err!(f, "validation error"; e),
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
            UnknownHrp(ref e) => Some(e),
            LegacyAddressTooLong(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            InvalidLegacyPrefix(ref e) => Some(e),
            NetworkValidation(ref e) => Some(e),
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

impl From<UnknownHrpError> for ParseError {
    fn from(e: UnknownHrpError) -> Self { Self::UnknownHrp(e) }
}

impl From<LegacyAddressTooLongError> for ParseError {
    fn from(e: LegacyAddressTooLongError) -> Self { Self::LegacyAddressTooLong(e) }
}

impl From<InvalidBase58PayloadLengthError> for ParseError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self { Self::InvalidBase58PayloadLength(e) }
}

impl From<InvalidLegacyPrefixError> for ParseError {
    fn from(e: InvalidLegacyPrefixError) -> Self { Self::InvalidLegacyPrefix(e) }
}

impl From<NetworkValidationError> for ParseError {
    fn from(e: NetworkValidationError) -> Self { Self::NetworkValidation(e) }
}

/// Unknown HRP error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHrpError(pub String);

impl fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "unknown hrp: {}", self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownHrpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Address's network differs from required one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkValidationError {
    /// Network that was required.
    pub(crate) required: Network,
    /// The address itself.
    pub(crate) address: Address<NetworkUnchecked>,
}

impl fmt::Display for NetworkValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "address ")?;
        fmt::Display::fmt(&self.address.0, f)?;
        write!(f, " is not valid on {}", self.required)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetworkValidationError {}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding address string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize { self.length }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decoded base58 data was an invalid length: {} (expected 21)", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

/// Legacy base58 address was too long, max 50 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAddressTooLongError {
    /// The length of the legacy address.
    pub(crate) length: usize,
}

impl LegacyAddressTooLongError {
    /// Returns the invalid legacy address length.
    pub fn invalid_legcay_address_length(&self) -> usize { self.length }
}

impl fmt::Display for LegacyAddressTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "legacy address is too long: {} (max 50 characters)", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LegacyAddressTooLongError {}

/// Invalid legacy address prefix in decoded base58 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidLegacyPrefixError {
    /// The invalid prefix byte.
    pub(crate) invalid: u8,
}

impl InvalidLegacyPrefixError {
    /// Returns the invalid prefix.
    pub fn invalid_legacy_address_prefix(&self) -> u8 { self.invalid }
}

impl fmt::Display for InvalidLegacyPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid legacy address prefix in decoded base58 data {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLegacyPrefixError {}
