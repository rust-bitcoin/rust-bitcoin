// SPDX-License-Identifier: CC0-1.0

//! Error types for bitcoin amounts.

use core::fmt;

use internals::error::InputString;
use internals::write_err;

use super::INPUT_STRING_LEN_LIMIT;

/// An error during amount parsing amount with denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Invalid amount.
    Amount(ParseAmountError),

    /// Invalid denomination.
    Denomination(ParseDenominationError),

    /// The denomination was not identified.
    MissingDenomination(MissingDenominationError),
}

internals::impl_from_infallible!(ParseError);

impl From<ParseAmountError> for ParseError {
    fn from(e: ParseAmountError) -> Self { Self::Amount(e) }
}

impl From<ParseDenominationError> for ParseError {
    fn from(e: ParseDenominationError) -> Self { Self::Denomination(e) }
}

impl From<OutOfRangeError> for ParseError {
    fn from(e: OutOfRangeError) -> Self { Self::Amount(e.into()) }
}

impl From<TooPreciseError> for ParseError {
    fn from(e: TooPreciseError) -> Self { Self::Amount(e.into()) }
}

impl From<MissingDigitsError> for ParseError {
    fn from(e: MissingDigitsError) -> Self { Self::Amount(e.into()) }
}

impl From<InputTooLargeError> for ParseError {
    fn from(e: InputTooLargeError) -> Self { Self::Amount(e.into()) }
}

impl From<InvalidCharacterError> for ParseError {
    fn from(e: InvalidCharacterError) -> Self { Self::Amount(e.into()) }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::Amount(error) => write_err!(f, "invalid amount"; error),
            ParseError::Denomination(error) => write_err!(f, "invalid denomination"; error),
            // We consider this to not be a source because it currently doesn't contain useful
            // information
            ParseError::MissingDenomination(_) =>
                f.write_str("the input doesn't contain a denomination"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Amount(error) => Some(error),
            ParseError::Denomination(error) => Some(error),
            // We consider this to not be a source because it currently doesn't contain useful
            // information
            ParseError::MissingDenomination(_) => None,
        }
    }
}

/// An error during amount parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseAmountError {
    /// The amount is too big or too small.
    OutOfRange(OutOfRangeError),
    /// Amount has higher precision than supported by the type.
    TooPrecise(TooPreciseError),
    /// A digit was expected but not found.
    MissingDigits(MissingDigitsError),
    /// Input string was too large.
    InputTooLarge(InputTooLargeError),
    /// Invalid character in input.
    InvalidCharacter(InvalidCharacterError),
}

impl From<TooPreciseError> for ParseAmountError {
    fn from(value: TooPreciseError) -> Self { Self::TooPrecise(value) }
}

impl From<MissingDigitsError> for ParseAmountError {
    fn from(value: MissingDigitsError) -> Self { Self::MissingDigits(value) }
}

impl From<InputTooLargeError> for ParseAmountError {
    fn from(value: InputTooLargeError) -> Self { Self::InputTooLarge(value) }
}

impl From<InvalidCharacterError> for ParseAmountError {
    fn from(value: InvalidCharacterError) -> Self { Self::InvalidCharacter(value) }
}

internals::impl_from_infallible!(ParseAmountError);

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseAmountError::*;

        match *self {
            OutOfRange(ref error) => write_err!(f, "amount out of range"; error),
            TooPrecise(ref error) => write_err!(f, "amount has a too high precision"; error),
            MissingDigits(ref error) => write_err!(f, "the input has too few digits"; error),
            InputTooLarge(ref error) => write_err!(f, "the input is too large"; error),
            InvalidCharacter(ref error) => write_err!(f, "invalid character in the input"; error),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseAmountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseAmountError::*;

        match *self {
            TooPrecise(ref error) => Some(error),
            InputTooLarge(ref error) => Some(error),
            OutOfRange(ref error) => Some(error),
            MissingDigits(ref error) => Some(error),
            InvalidCharacter(ref error) => Some(error),
        }
    }
}

/// Error returned when a parsed amount is too big or too small.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct OutOfRangeError {
    pub(super) is_signed: bool,
    pub(super) is_greater_than_max: bool,
}

impl OutOfRangeError {
    /// Returns the minimum and maximum allowed values for the type that was parsed.
    ///
    /// This can be used to give a hint to the user which values are allowed.
    pub fn valid_range(&self) -> (i64, u64) {
        match self.is_signed {
            true => (i64::MIN, i64::MAX as u64),
            false => (0, u64::MAX),
        }
    }

    /// Returns true if the input value was large than the maximum allowed value.
    pub fn is_above_max(&self) -> bool { self.is_greater_than_max }

    /// Returns true if the input value was smaller than the minimum allowed value.
    pub fn is_below_min(&self) -> bool { !self.is_greater_than_max }

    pub(crate) fn too_big(is_signed: bool) -> Self { Self { is_signed, is_greater_than_max: true } }

    pub(crate) fn too_small() -> Self {
        Self {
            // implied - negative() is used for the other
            is_signed: true,
            is_greater_than_max: false,
        }
    }

    pub(crate) fn negative() -> Self {
        Self {
            // implied - too_small() is used for the other
            is_signed: false,
            is_greater_than_max: false,
        }
    }
}

impl fmt::Display for OutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_greater_than_max {
            write!(f, "the amount is greater than {}", self.valid_range().1)
        } else {
            write!(f, "the amount is less than {}", self.valid_range().0)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutOfRangeError {}

impl From<OutOfRangeError> for ParseAmountError {
    fn from(value: OutOfRangeError) -> Self { ParseAmountError::OutOfRange(value) }
}

/// Error returned when the input string has higher precision than satoshis.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TooPreciseError {
    pub(super) position: usize,
}

impl fmt::Display for TooPreciseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.position {
            0 => f.write_str("the amount is less than 1 satoshi but it's not zero"),
            pos => write!(
                f,
                "the digits starting from position {} represent a sub-satoshi amount",
                pos
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooPreciseError {}

/// Error returned when the input string is too large.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InputTooLargeError {
    pub(super) len: usize,
}

impl fmt::Display for InputTooLargeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.len - INPUT_STRING_LEN_LIMIT {
            1 => write!(
                f,
                "the input is one character longer than the maximum allowed length ({})",
                INPUT_STRING_LEN_LIMIT
            ),
            n => write!(
                f,
                "the input is {} characters longer than the maximum allowed length ({})",
                n, INPUT_STRING_LEN_LIMIT
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputTooLargeError {}

/// Error returned when digits were expected in the input but there were none.
///
/// In particular, this is currently returned when the string is empty or only contains the minus sign.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MissingDigitsError {
    pub(super) kind: MissingDigitsKind,
}

impl fmt::Display for MissingDigitsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            MissingDigitsKind::Empty => f.write_str("the input is empty"),
            MissingDigitsKind::OnlyMinusSign =>
                f.write_str("there are no digits following the minus (-) sign"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingDigitsError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum MissingDigitsKind {
    Empty,
    OnlyMinusSign,
}

/// Error returned when the input contains an invalid character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCharacterError {
    pub(super) invalid_char: char,
    pub(super) position: usize,
}

impl fmt::Display for InvalidCharacterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.invalid_char {
            '.' => f.write_str("there is more than one decimal separator (dot) in the input"),
            '-' => f.write_str("there is more than one minus sign (-) in the input"),
            c => write!(
                f,
                "the character '{}' at position {} is not a valid digit",
                c, self.position
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidCharacterError {}

/// An error during amount parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseDenominationError {
    /// The denomination was unknown.
    Unknown(UnknownDenominationError),
    /// The denomination has multiple possible interpretations.
    PossiblyConfusing(PossiblyConfusingDenominationError),
}

internals::impl_from_infallible!(ParseDenominationError);

impl fmt::Display for ParseDenominationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseDenominationError::*;

        match *self {
            Unknown(ref e) => write_err!(f, "denomination parse error"; e),
            PossiblyConfusing(ref e) => write_err!(f, "denomination parse error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDenominationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseDenominationError::*;

        match *self {
            Unknown(_) | PossiblyConfusing(_) => None,
        }
    }
}

/// Error returned when the denomination is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MissingDenominationError;

/// Error returned when parsing an unknown denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownDenominationError(pub(super) InputString);

impl fmt::Display for UnknownDenominationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.unknown_variant("bitcoin denomination", f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownDenominationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned when parsing a possibly confusing denomination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PossiblyConfusingDenominationError(pub(super) InputString);

impl fmt::Display for PossiblyConfusingDenominationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: possibly confusing denomination - we intentionally do not support 'M' and 'P' so as to not confuse mega/milli and peta/pico", self.0.display_cannot_parse("bitcoin denomination"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PossiblyConfusingDenominationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
