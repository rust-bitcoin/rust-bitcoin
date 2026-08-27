//! Error code for the address module.

use core::convert::Infallible;
use core::fmt;

use internals::error::InputString;
use internals::write_err;
#[cfg(feature = "alloc")]
use network::Network;
use primitives::witness_version;

use crate::witness_program;
#[cfg(feature = "alloc")]
use crate::{Address, NetworkUnchecked};

/// Error while generating address from script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromScriptError {
    /// Script is not a p2pkh, p2sh or witness program.
    UnrecognizedScript,
    /// A witness program error.
    WitnessProgram(witness_program::Error),
    /// A witness version construction error.
    WitnessVersion(witness_version::InvalidWitnessVersionError),
}

impl From<Infallible> for FromScriptError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FromScriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WitnessVersion(ref e) => write_err!(f, "witness version construction error"; e),
            Self::WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            Self::UnrecognizedScript => write!(f, "script is not a p2pkh, p2sh or witness program"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnrecognizedScript => None,
            Self::WitnessVersion(ref e) => Some(e),
            Self::WitnessProgram(ref e) => Some(e),
        }
    }
}

/// Address type is either invalid or not supported in rust-bitcoin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownAddressTypeError(pub(super) InputString);

impl fmt::Display for UnknownAddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Outputs "failed to parse <input string> as address type".
        write!(f, "{}", self.0.display_cannot_parse("address type"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownAddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self(_) = self;
        None
    }
}

/// Address parsing error.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Base58 legacy decoding error.
    Base58(Base58Error),
    /// Bech32 SegWit decoding error.
    Bech32(Bech32Error),
    /// Address's network differs from required one.
    NetworkValidation(NetworkValidationError),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(ref e) => write_err!(f, "base58 error"; e),
            Self::Bech32(ref e) => write_err!(f, "bech32 error"; e),
            Self::NetworkValidation(ref e) => write_err!(f, "validation error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(ref e) => Some(e),
            Self::Bech32(ref e) => Some(e),
            Self::NetworkValidation(ref e) => Some(e),
        }
    }
}

/// Unknown HRP error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHrpError(pub(super) InputString);

impl fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Outputs "'<input string>' is not a known hrp" or "unknown hrp"
        self.0.unknown_variant("hrp", f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownHrpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self(_) = self;
        None
    }
}

/// Address's network differs from required one.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkValidationError {
    /// Network that was required.
    pub(crate) required: Network,
    /// The address itself.
    pub(crate) address: Address<NetworkUnchecked>,
}

#[cfg(feature = "alloc")]
impl fmt::Display for NetworkValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "address ")?;
        fmt::Display::fmt(&self.address.inner(), f)?;
        write!(f, " is not valid on {}", self.required)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetworkValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { required: _, address: _ } = self;
        None
    }
}

/// Bech32 related error.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bech32Error {
    /// Parse SegWit Bech32 error.
    ParseBech32(ParseBech32Error),
    /// A witness version conversion/parsing error.
    WitnessVersion(witness_version::InvalidWitnessVersionError),
    /// A witness program error.
    WitnessProgram(witness_program::Error),
    /// Tried to parse an unknown HRP.
    UnknownHrp(UnknownHrpError),
}

#[cfg(feature = "alloc")]
impl From<Infallible> for Bech32Error {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ParseBech32(ref e) => write_err!(f, "SegWit parsing error"; e),
            Self::WitnessVersion(ref e) =>
                write_err!(f, "witness version conversion/parsing error"; e),
            Self::WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            Self::UnknownHrp(ref e) => write_err!(f, "unknown hrp error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bech32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseBech32(ref e) => Some(e),
            Self::WitnessVersion(ref e) => Some(e),
            Self::WitnessProgram(ref e) => Some(e),
            Self::UnknownHrp(ref e) => Some(e),
        }
    }
}

/// Bech32 parsing related error.
// This wrapper exists because we do not want to expose the `bech32` crate in our public API.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBech32Error(pub(crate) bech32::segwit::DecodeError);

#[cfg(feature = "alloc")]
impl From<Infallible> for ParseBech32Error {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ParseBech32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "bech32 parsing error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseBech32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Base58 related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base58Error {
    /// Parse legacy Base58 error.
    ParseBase58(base58::DecodeCheckArrayError),
    /// Legacy address is too long.
    LegacyAddressTooLong(LegacyAddressTooLongError),
    /// Invalid legacy address prefix in base58 data payload.
    InvalidLegacyPrefix(InvalidLegacyPrefixError),
}

impl From<Infallible> for Base58Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Base58Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ParseBase58(ref e) => write_err!(f, "legacy parsing error"; e),
            Self::LegacyAddressTooLong(ref e) => write_err!(f, "legacy address length error"; e),
            Self::InvalidLegacyPrefix(ref e) => write_err!(f, "legacy prefix error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Base58Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParseBase58(ref e) => Some(e),
            Self::LegacyAddressTooLong(ref e) => Some(e),
            Self::InvalidLegacyPrefix(ref e) => Some(e),
        }
    }
}

/// Legacy base58 address was too long, max 50 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyAddressTooLongError {
    /// The length of the legacy address.
    pub(crate) length: usize,
}

impl LegacyAddressTooLongError {
    /// Returns the invalid legacy address length.
    pub fn invalid_legacy_address_length(&self) -> usize { self.length }

    #[doc(hidden)]
    #[deprecated = "Use invalid_legacy_address_length() instead"]
    pub fn invalid_legcay_address_length(&self) -> usize { self.invalid_legacy_address_length() }
}

impl fmt::Display for LegacyAddressTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "legacy address is too long: {} (max 50 characters)", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LegacyAddressTooLongError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { length: _ } = self;
        None
    }
}

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
impl std::error::Error for InvalidLegacyPrefixError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let Self { invalid: _ } = self;
        None
    }
}
