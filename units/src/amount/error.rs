// SPDX-License-Identifier: CC0-1.0

//! Error types for bitcoin amounts.

use alloc::boxed::Box;
use core::convert::Infallible;
use core::fmt;

use internals::error::{InputString, ParseErrorContext};
use internals::write_err;

use super::INPUT_STRING_LEN_LIMIT;

/// Error returned when parsing an amount with denomination fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub(crate) ParseErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseErrorInner {
    /// Invalid amount.
    Amount(ParseAmountError),
    /// Invalid denomination.
    Denomination(ParseDenominationError),
    /// The denomination was not identified.
    MissingDenomination(MissingDenominationError),
}

impl From<Infallible> for ParseError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for ParseErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<ParseAmountError> for ParseError {
    fn from(e: ParseAmountError) -> Self { Self(ParseErrorInner::Amount(e)) }
}

impl From<ParseDenominationError> for ParseError {
    fn from(e: ParseDenominationError) -> Self { Self(ParseErrorInner::Denomination(e)) }
}

impl From<OutOfRangeError> for ParseError {
    fn from(e: OutOfRangeError) -> Self { Self(ParseErrorInner::Amount(e.into())) }
}

impl From<TooPreciseError> for ParseError {
    fn from(e: TooPreciseError) -> Self { Self(ParseErrorInner::Amount(e.into())) }
}

impl From<MissingDigitsError> for ParseError {
    fn from(e: MissingDigitsError) -> Self { Self(ParseErrorInner::Amount(e.into())) }
}

impl From<InputTooLargeError> for ParseError {
    fn from(e: InputTooLargeError) -> Self { Self(ParseErrorInner::Amount(e.into())) }
}

impl From<InvalidCharacterError> for ParseError {
    fn from(e: InvalidCharacterError) -> Self { Self(ParseErrorInner::Amount(e.into())) }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            ParseErrorInner::Amount(ref e) => write_err!(f, "invalid amount"; e),
            ParseErrorInner::Denomination(ref e) => write_err!(f, "invalid denomination"; e),
            // We consider this to not be a source because it currently doesn't contain useful info.
            ParseErrorInner::MissingDenomination(_) =>
                f.write_str("the input doesn't contain a denomination"),
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

        match &self.0 {
            ParseErrorInner::Amount(e) => e.expecting(),
            ParseErrorInner::Denomination(e) => e.expecting(),
            ParseErrorInner::MissingDenomination(_) => Box::new("an amount followed by a denomination (e.g., \"1.23 BTC\", \"500 sat\")"),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match &self.0 {
            ParseErrorInner::Amount(e) => e.help(),
            ParseErrorInner::Denomination(e) => e.help(),
            ParseErrorInner::MissingDenomination(_) => None,
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match &self.0 {
            ParseErrorInner::Amount(e) => e.change_suggestion(),
            ParseErrorInner::Denomination(e) => e.change_suggestion(),
            ParseErrorInner::MissingDenomination(_) => Some("Try adding a denomination like 'BTC', 'sat', etc."),
        }
    }

    fn note(&self) -> Option<&'static str> {
        match &self.0 {
            ParseErrorInner::Amount(e) => e.note(),
            ParseErrorInner::Denomination(e) => e.note(),
            ParseErrorInner::MissingDenomination(_) => Some("Bitcoin amounts require an explicit denomination to avoid confusion."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.0 {
            ParseErrorInner::Amount(ref e) => Some(e),
            ParseErrorInner::Denomination(ref e) => Some(e),
            // We consider this to not be a source because it currently doesn't contain useful info.
            ParseErrorInner::MissingDenomination(_) => None,
        }
    }
}

/// Error returned when parsing an amount fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAmountError(pub(crate) ParseAmountErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseAmountErrorInner {
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
    fn from(value: TooPreciseError) -> Self { Self(ParseAmountErrorInner::TooPrecise(value)) }
}

impl From<MissingDigitsError> for ParseAmountError {
    fn from(value: MissingDigitsError) -> Self { Self(ParseAmountErrorInner::MissingDigits(value)) }
}

impl From<InputTooLargeError> for ParseAmountError {
    fn from(value: InputTooLargeError) -> Self { Self(ParseAmountErrorInner::InputTooLarge(value)) }
}

impl From<InvalidCharacterError> for ParseAmountError {
    fn from(value: InvalidCharacterError) -> Self {
        Self(ParseAmountErrorInner::InvalidCharacter(value))
    }
}

impl From<Infallible> for ParseAmountError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for ParseAmountErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseAmountErrorInner as E;

        match self.0 {
            E::OutOfRange(ref error) => write_err!(f, "amount out of range"; error),
            E::TooPrecise(ref error) => write_err!(f, "amount has a too high precision"; error),
            E::MissingDigits(ref error) => write_err!(f, "the input has too few digits"; error),
            E::InputTooLarge(ref error) => write_err!(f, "the input is too large"; error),
            E::InvalidCharacter(ref error) =>
                write_err!(f, "invalid character in the input"; error),
        }
    }
}

impl ParseErrorContext for ParseAmountError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        struct ExpectingDisplay<D: fmt::Display>(D);
        impl<D: fmt::Display> fmt::Display for ExpectingDisplay<D> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        match &self.0 {
            ParseAmountErrorInner::OutOfRange(e) => e.expecting(),
            ParseAmountErrorInner::TooPrecise(e) => e.expecting(),
            ParseAmountErrorInner::MissingDigits(e) => e.expecting(),
            ParseAmountErrorInner::InputTooLarge(e) => {
                struct LimitDisplay(usize);
                impl fmt::Display for LimitDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "an amount with at most {} characters", self.0)
                    }
                }
                Box::new(LimitDisplay(e.len))
            }
            ParseAmountErrorInner::InvalidCharacter(e) => e.expecting(),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match &self.0 {
            ParseAmountErrorInner::OutOfRange(e) => e.help(),
            ParseAmountErrorInner::TooPrecise(e) => e.help(),
            ParseAmountErrorInner::MissingDigits(e) => e.help(),
            ParseAmountErrorInner::InputTooLarge(e) => {
                struct HelpDisplay(usize);
                impl fmt::Display for HelpDisplay {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "The input is too long ({} characters). Consider shortening or splitting it.", self.0)
                    }
                }
                Some(Box::new(HelpDisplay(e.len)))
            }
            ParseAmountErrorInner::InvalidCharacter(e) => e.help(),
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match &self.0 {
            ParseAmountErrorInner::OutOfRange(_) => Some("Try a value within the valid range."),
            ParseAmountErrorInner::TooPrecise(_) => Some("Round to satoshis (8 decimal places)."),
            _ => None,
        }
    }

    fn note(&self) -> Option<&'static str> {
        match &self.0 {
            ParseAmountErrorInner::TooPrecise(_) => Some("Bitcoin amounts are typically expressed in satoshis, the smallest unit (0.00000001 BTC)."),
            ParseAmountErrorInner::InputTooLarge(_) => Some("For security reasons, we limit the size of numeric input to prevent resource exhaustion."),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseAmountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseAmountErrorInner as E;

        match self.0 {
            E::TooPrecise(ref error) => Some(error),
            E::InputTooLarge(ref error) => Some(error),
            E::OutOfRange(ref error) => Some(error),
            E::MissingDigits(ref error) => Some(error),
            E::InvalidCharacter(ref error) => Some(error),
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
    pub fn valid_range(self) -> (i64, u64) {
        match self.is_signed {
            true => (i64::MIN, i64::MAX as u64),
            false => (0, u64::MAX),
        }
    }

    /// Returns true if the input value was larger than the maximum allowed value.
    pub fn is_above_max(self) -> bool { self.is_greater_than_max }

    /// Returns true if the input value was smaller than the minimum allowed value.
    pub fn is_below_min(self) -> bool { !self.is_greater_than_max }

    #[cfg(test)]
    pub(crate) fn too_big(is_signed: bool) -> Self { Self { is_signed, is_greater_than_max: true } }

    #[cfg(test)]
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

impl ParseErrorContext for OutOfRangeError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        struct RangeDisplay(i64, u64);
        impl fmt::Display for RangeDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a value between {} and {}", self.0, self.1)
            }
        }
        
        let range = self.valid_range();
        Box::new(RangeDisplay(range.0, range.1))
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay(i64, u64);
        impl fmt::Display for HelpDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "The amount {} is outside the valid range ({} to {}).", self.0 as f64, self.0, self.1)
            }
        }
        
        let range = self.valid_range();
        Some(Box::new(HelpDisplay(range.0, range.1)))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutOfRangeError {}

impl From<OutOfRangeError> for ParseAmountError {
    fn from(value: OutOfRangeError) -> Self {
        ParseAmountError(ParseAmountErrorInner::OutOfRange(value))
    }
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

impl ParseErrorContext for TooPreciseError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("an amount with at most 8 decimal places (precision up to satoshis)")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new("The provided amount has more precision than is representable."))
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
            MissingDigitsKind::Empty => f.write_str("there are no digits in the input"),
            MissingDigitsKind::OnlyMinusSign => {
                f.write_str("there are no digits following the minus (-) sign")
            },
            MissingDigitsKind::BeforeDecimal => {
                f.write_str("there are no digits before the decimal point")
            },
            MissingDigitsKind::AfterDecimal => {
                f.write_str("there are no digits after the decimal point")
            },
        }
    }
}

impl ParseErrorContext for MissingDigitsError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        struct ExpectingDisplay(MissingDigitsKind);
        impl fmt::Display for ExpectingDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    MissingDigitsKind::Empty => write!(f, "at least one digit"),
                    MissingDigitsKind::OnlyMinusSign => write!(f, "at least one digit after the minus sign"),
                    MissingDigitsKind::BeforeDecimal => write!(f, "at least one digit before the decimal point"),
                    MissingDigitsKind::AfterDecimal => write!(f, "at least one digit after the decimal point"),
                }
            }
        }
        Box::new(ExpectingDisplay(self.kind))
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay(MissingDigitsKind);
        impl fmt::Display for HelpDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    MissingDigitsKind::Empty => write!(f, "The input string was empty."),
                    MissingDigitsKind::OnlyMinusSign => write!(f, "The input string contained only a minus sign."),
                    MissingDigitsKind::BeforeDecimal => write!(f, "An amount must have at least one digit before the decimal point. Example: '0.5 BTC' not '.5 BTC'."),
                    MissingDigitsKind::AfterDecimal => write!(f, "An amount with a decimal point must have at least one digit after it. Example: '1.0 BTC' not '1. BTC'."),
                }
            }
        }
        Some(Box::new(HelpDisplay(self.kind)))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingDigitsError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum MissingDigitsKind {
    Empty,
    OnlyMinusSign,
    BeforeDecimal,
    AfterDecimal,
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

impl ParseErrorContext for InvalidCharacterError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("numeric digits (0-9), decimal separator ('.'), or sign ('-')")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        struct HelpDisplay(char, usize);
        impl fmt::Display for HelpDisplay {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "Invalid character '{}' found at position {}.", self.0, self.1)
            }
        }
        Some(Box::new(HelpDisplay(self.invalid_char, self.position)))
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match self.invalid_char {
            ',' => Some("Did you mean to use '.' as the decimal separator?"),
            '_' => Some("Remove thousands separators like '_'."),
            // Add other common mistakes if needed
            _ => None,
        }
    }

    fn note(&self) -> Option<&'static str> { None }
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

impl From<Infallible> for ParseDenominationError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for ParseDenominationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseDenominationError as E;

        match *self {
            E::Unknown(ref e) => write_err!(f, "denomination parse error"; e),
            E::PossiblyConfusing(ref e) => write_err!(f, "denomination parse error"; e),
        }
    }
}

impl ParseErrorContext for ParseDenominationError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        match self {
            ParseDenominationError::Unknown(_) => Box::new("a known denomination (e.g., \"BTC\", \"mBTC\", \"sat\")"),
            ParseDenominationError::PossiblyConfusing(_) => Box::new("an unambiguous denomination"),
        }
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        match self {
            ParseDenominationError::Unknown(_) => {
                Some(Box::new("The denomination is not recognized. Valid denominations include BTC, mBTC, μBTC, sat."))
            },
            ParseDenominationError::PossiblyConfusing(_) => {
                Some(Box::new("The denomination is ambiguous and could refer to multiple units."))
            },
        }
    }

    fn change_suggestion(&self) -> Option<&'static str> {
        match self {
            ParseDenominationError::PossiblyConfusing(_) => Some("Use standard prefixes like 'm' (milli), 'u' (micro), or full names like 'BTC', 'sat'."),
            _ => None,
        }
    }

    fn note(&self) -> Option<&'static str> {
        match self {
            ParseDenominationError::PossiblyConfusing(_) => Some("We intentionally do not support 'M' and 'P' so as to not confuse mega/milli and peta/pico."),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDenominationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseDenominationError as E;

        match *self {
            E::Unknown(_) | E::PossiblyConfusing(_) => None,
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

impl ParseErrorContext for UnknownDenominationError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("a known denomination (e.g., \"BTC\", \"mBTC\", \"sat\")")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new("Use standard denominations like 'BTC', 'mBTC', 'uBTC', 'sat'."))
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

impl ParseErrorContext for PossiblyConfusingDenominationError {
    fn expecting<'a>(&'a self) -> Box<dyn fmt::Display + 'a> {
        Box::new("an unambiguous denomination")
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        Some(Box::new("Avoid ambiguous prefixes like 'M' and 'P' which could be confused with mega/milli and peta/pico."))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PossiblyConfusingDenominationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
