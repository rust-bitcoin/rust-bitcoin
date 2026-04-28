//! Error code for the address module.

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use addresses::error::{
    Base58Error, Bech32Error, FromScriptError, InvalidBase58PayloadLengthError,
    InvalidLegacyPrefixError, LegacyAddressTooLongError, NetworkValidationError,
    ParseError, UnknownAddressTypeError, UnknownHrpError, ParseBech32Error,
};
