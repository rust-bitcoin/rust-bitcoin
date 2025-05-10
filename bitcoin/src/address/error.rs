//! Error code for the address module.

use core::convert::Infallible;
use core::fmt;
use alloc::boxed::Box;

use internals::error::ParseErrorContext;
use internals::write_err;

use crate::address::{Address, NetworkUnchecked};
use crate::prelude::String;
use crate::script::{witness_program, witness_version};
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

impl From<Infallible> for FromScriptError {
    fn from(never: Infallible) -> Self { match never {} }
}

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
    /// Base58 legacy decoding error.
    Base58(Base58Error),
    /// Bech32 SegWit decoding error.
    Bech32(Bech32Error),
    /// Address's network differs from required one.
    NetworkValidation(NetworkValidationError),
}

impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Base58(ref e) => write_err!(f, "base58 error"; e),
            Bech32(ref e) => write_err!(f, "bech32 error"; e),
            NetworkValidation(ref e) => write_err!(f, "validation error"; e),
        }
    }
}

impl ParseErrorContext for ParseError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        // Helper struct to prevent lifetime issues with returning refs to temporary strings
        struct ExpectingDisplay<D: fmt::Display>(D);
        impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        match self {
            ParseError::Base58(e) => e.expecting(),
            ParseError::Bech32(e) => e.expecting(),
            ParseError::NetworkValidation(e) => Box::new(ExpectingDisplay(e.expecting())),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            ParseError::Base58(e) => e.help(),
            ParseError::Bech32(e) => e.help(),
            ParseError::NetworkValidation(e) => e.help(),
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match self {
            ParseError::Base58(e) => e.change_suggestion(),
            ParseError::Bech32(e) => e.change_suggestion(),
            ParseError::NetworkValidation(e) => e.note(),
        }
    }

    fn note(&self) -> Option<&'static str> {
        match self {
            ParseError::Base58(e) => e.note(),
            ParseError::Bech32(e) => e.note(),
            ParseError::NetworkValidation(e) => e.note(),
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
            NetworkValidation(ref e) => Some(e),
        }
    }
}

impl From<Base58Error> for ParseError {
    fn from(e: Base58Error) -> Self { Self::Base58(e) }
}

impl From<Bech32Error> for ParseError {
    fn from(e: Bech32Error) -> Self { Self::Bech32(e) }
}

impl From<UnknownHrpError> for ParseError {
    fn from(e: UnknownHrpError) -> ParseError { Self::Bech32(e.into()) }
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
        fmt::Display::fmt(&self.address.inner(), f)?;
        write!(f, " is not valid on {}", self.required)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NetworkValidationError {}

/// Helper struct to display the expecting message for NetworkValidationError
struct NetworkValidationExpecting<'a>(&'a NetworkValidationError);

impl fmt::Display for NetworkValidationExpecting<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an address valid for the {} network", self.0.required)
    }
}

impl NetworkValidationError {
    fn expecting<'a>(&'a self) -> impl fmt::Display + 'a {
        struct ExpectingDisplay<'a>(&'a Network);
        impl<'a> fmt::Display for ExpectingDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an address for the {} network", self.0)
            }
        }
        ExpectingDisplay(&self.required)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay<'a>(&'a Address<NetworkUnchecked>);
        impl<'a> fmt::Display for HelpDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "The address is for network {:?}, which is incompatible.", self.0.network_kind())
            }
        }
        Some(Box::new(HelpDisplay(&self.address)))
    }

    fn note(&self) -> Option<&'static str> {
        Some("Bitcoin addresses are network-specific. Make sure you're using the correct network type.")
    }
}

/// Bech32 related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bech32Error {
    /// Parse SegWit Bech32 error.
    ParseBech32(ParseBech32Error),
    /// A witness version conversion/parsing error.
    WitnessVersion(witness_version::TryFromError),
    /// A witness program error.
    WitnessProgram(witness_program::Error),
    /// Tried to parse an unknown HRP.
    UnknownHrp(UnknownHrpError),
}

impl From<Infallible> for Bech32Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bech32Error::*;

        match *self {
            ParseBech32(ref e) => write_err!(f, "SegWit parsing error"; e),
            WitnessVersion(ref e) => write_err!(f, "witness version conversion/parsing error"; e),
            WitnessProgram(ref e) => write_err!(f, "witness program error"; e),
            UnknownHrp(ref e) => write_err!(f, "unknown hrp error"; e),
        }
    }
}

impl ParseErrorContext for Bech32Error {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        // Helper struct to prevent lifetime issues with returning refs to temporary strings
        struct ExpectingDisplay<D: fmt::Display>(D);
        impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        match self {
            Bech32Error::ParseBech32(e) => e.expecting(),
            Bech32Error::WitnessVersion(_) => Box::new("a valid witness version (0-16)"),
            Bech32Error::WitnessProgram(_) => Box::new("a valid witness program length (2-40 bytes) that matches the version"),
            Bech32Error::UnknownHrp(ref e) => Box::new("a known human-readable prefix (hrp)"),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Bech32Error::WitnessVersion(e) => Some(Box::new(e.to_string())),
            Bech32Error::WitnessProgram(e) => Some(Box::new(e.to_string())),
            Bech32Error::UnknownHrp(e) => e.help(),
            Bech32Error::ParseBech32(e) => e.help(),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bech32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bech32Error::*;

        match *self {
            ParseBech32(ref e) => Some(e),
            WitnessVersion(ref e) => Some(e),
            WitnessProgram(ref e) => Some(e),
            UnknownHrp(ref e) => Some(e),
        }
    }
}

impl From<witness_version::TryFromError> for Bech32Error {
    fn from(e: witness_version::TryFromError) -> Self { Self::WitnessVersion(e) }
}

impl From<witness_program::Error> for Bech32Error {
    fn from(e: witness_program::Error) -> Self { Self::WitnessProgram(e) }
}

impl From<UnknownHrpError> for Bech32Error {
    fn from(e: UnknownHrpError) -> Self { Self::UnknownHrp(e) }
}

/// Bech32 parsing related error.
// This wrapper exists because we do not want to expose the `bech32` crate in our public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBech32Error(pub(crate) bech32::segwit::DecodeError);

impl From<Infallible> for ParseBech32Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseBech32Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "bech32 parsing error"; self.0)
    }
}

impl ParseErrorContext for ParseBech32Error {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("valid bech32 or bech32m encoding with correct checksum and character set")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new(self.0.to_string()))
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
    ParseBase58(base58::Error),
    /// Legacy address is too long.
    LegacyAddressTooLong(LegacyAddressTooLongError),
    /// Invalid base58 payload data length for legacy address.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Invalid legacy address prefix in base58 data payload.
    InvalidLegacyPrefix(InvalidLegacyPrefixError),
}

impl From<Infallible> for Base58Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Base58Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Base58Error::*;

        match *self {
            ParseBase58(ref e) => write_err!(f, "legacy parsing error"; e),
            LegacyAddressTooLong(ref e) => write_err!(f, "legacy address length error"; e),
            InvalidBase58PayloadLength(ref e) => write_err!(f, "legacy payload length error"; e),
            InvalidLegacyPrefix(ref e) => write_err!(f, "legacy prefix error"; e),
        }
    }
}

impl ParseErrorContext for Base58Error {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        // Helper struct to manage lifetimes
        struct ExpectingDisplay<D: fmt::Display>(D);
        impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        use Base58Error::*;
        match self {
            ParseBase58(e) => e.expecting(),
            LegacyAddressTooLong(_) => Box::new("a base58 string of at most 50 characters"),
            InvalidBase58PayloadLength(_) => Box::new("a base58 payload of 21 bytes for a legacy address"),
            InvalidLegacyPrefix(_) => Box::new("a valid network prefix byte (e.g., 0 for p2pkh, 5 for p2sh on mainnet)"),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            Base58Error::ParseBase58(e) => e.help(),
            _ => None
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match self {
            Base58Error::ParseBase58(e) => e.change_suggestion(),
            _ => None
        }
    }

    fn note(&self) -> Option<&'static str> {
        match self {
            Base58Error::ParseBase58(e) => e.note(),
            Base58Error::InvalidLegacyPrefix(_) => Some("Common prefixes: Mainnet P2PKH=0, P2SH=5; Testnet P2PKH=111, P2SH=196."),
            _ => None
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Base58Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Base58Error::*;

        match *self {
            ParseBase58(ref e) => Some(e),
            LegacyAddressTooLong(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            InvalidLegacyPrefix(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for Base58Error {
    fn from(e: base58::Error) -> Self { Self::ParseBase58(e) }
}

impl From<LegacyAddressTooLongError> for Base58Error {
    fn from(e: LegacyAddressTooLongError) -> Self { Self::LegacyAddressTooLong(e) }
}

impl From<InvalidBase58PayloadLengthError> for Base58Error {
    fn from(e: InvalidBase58PayloadLengthError) -> Self { Self::InvalidBase58PayloadLength(e) }
}

impl From<InvalidLegacyPrefixError> for Base58Error {
    fn from(e: InvalidLegacyPrefixError) -> Self { Self::InvalidLegacyPrefix(e) }
}

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

// Add help for UnknownHrpError
impl UnknownHrpError {
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay<'a>(&'a String);
        impl<'a> fmt::Display for HelpDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "The human-readable part \"{}\" is not recognized.", self.0)
            }
        }
        Some(Box::new(HelpDisplay(&self.0)))
    }
}
