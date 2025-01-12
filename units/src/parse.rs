// SPDX-License-Identifier: CC0-1.0

//! Parsing utilities.

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

use internals::error::InputString;
use internals::write_err;

/// Error with rich context returned when a string can't be parsed as an integer.
///
/// This is an extension of [`core::num::ParseIntError`], which carries the input that failed to
/// parse as well as type information. As a result it provides very informative error messages that
/// make it easier to understand the problem and correct mistakes.
///
/// Note that this is larger than the type from `core` so if it's passed through a deep call stack
/// in a performance-critical application you may want to box it or throw away the context by
/// converting to `core` type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseIntError {
    pub(crate) input: InputString,
    // for displaying - see Display impl with nice error message below
    pub(crate) bits: u8,
    // We could represent this as a single bit, but it wouldn't actually decrease the cost of moving
    // the struct because String contains pointers so there will be padding of bits at least
    // pointer_size - 1 bytes: min 1B in practice.
    pub(crate) is_signed: bool,
    pub(crate) source: core::num::ParseIntError,
}

impl fmt::Display for ParseIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let signed = if self.is_signed { "signed" } else { "unsigned" };
        write_err!(f, "{} ({}, {}-bit)", self.input.display_cannot_parse("integer"), signed, self.bits; self.source)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseIntError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.source) }
}

impl From<ParseIntError> for core::num::ParseIntError {
    fn from(value: ParseIntError) -> Self { value.source }
}

impl AsRef<core::num::ParseIntError> for ParseIntError {
    fn as_ref(&self) -> &core::num::ParseIntError { &self.source }
}

/// Not strictly necessary but serves as a lint - avoids weird behavior if someone accidentally
/// passes non-integer to the `parse()` function.
pub trait Integer:
    FromStr<Err = core::num::ParseIntError> + TryFrom<i8> + Sized + sealed::Sealed
{
}

macro_rules! impl_integer {
    ($($type:ty),* $(,)?) => {
        $(
        impl Integer for $type {}
        impl sealed::Sealed for $type {}
        )*
    }
}

impl_integer!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128);

mod sealed {
    /// Seals the extension traits.
    pub trait Sealed {}
}

/// Parses the input string as an integer returning an error carrying rich context.
///
/// If the caller owns `String` or `Box<str>` which is not used later it's better to pass it as
/// owned since it avoids allocation in error case.
pub fn int<T: Integer, S: AsRef<str> + Into<InputString>>(s: S) -> Result<T, ParseIntError> {
    s.as_ref().parse().map_err(|error| {
        ParseIntError {
            input: s.into(),
            bits: u8::try_from(core::mem::size_of::<T>() * 8).expect("max is 128 bits for u128"),
            // We detect if the type is signed by checking if -1 can be represented by it
            // this way we don't have to implement special traits and optimizer will get rid of the
            // computation.
            is_signed: T::try_from(-1i8).is_ok(),
            source: error,
        }
    })
}

/// Implements standard parsing traits for `$type` by calling `parse::int`.
///
/// Once the string is converted to an integer the infallible conversion function `fn` is used to
/// create the type `to`.
///
/// Implements:
///
/// * `FromStr`
/// * `TryFrom<&str>`
///
/// And if `alloc` feature is enabled in calling crate:
///
/// * `TryFrom<Box<str>>`
/// * `TryFrom<String>`
///
/// # Arguments
///
/// * `to` - the type converted to e.g., `impl From<&str> for $to`.
/// * `err` - the error type returned by `$inner_fn` (implies returned by `FromStr` and `TryFrom`).
/// * `fn`: The infallible conversion function to call to convert from an integer.
///
/// # Errors
///
/// If parsing the string fails then a `units::parse::ParseIntError` is returned.
#[macro_export]
#[doc(hidden)] // This is an 'internal' macro that should not be used outside of the `rust-bitcoin` crate.
macro_rules! impl_parse_str_from_int_infallible {
    ($to:ident, $inner:ident, $fn:ident) => {
        $crate::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn);
        #[cfg(feature = "alloc")]
        $crate::impl_tryfrom_str_from_int_infallible!(alloc::string::String, $to, $inner, $fn; alloc::boxed::Box<str>, $to, $inner, $fn);

        impl $crate::_export::_core::str::FromStr for $to {
            type Err = $crate::parse::ParseIntError;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                $crate::parse::int::<$inner, &str>(s).map($to::$fn)
            }
        }

    }
}

/// Implements `TryFrom<$from> for $to` using `parse::int`, mapping the output using infallible
/// conversion function `fn`.
#[macro_export]
#[doc(hidden)] // Helper macro called by `impl_parse_str_from_int_infallible`.
macro_rules! impl_tryfrom_str_from_int_infallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident);*) => {
        $(
        impl $crate::_export::_core::convert::TryFrom<$from> for $to {
            type Error = $crate::parse::ParseIntError;

            fn try_from(s: $from) -> $crate::_export::_core::result::Result<Self, Self::Error> {
                $crate::parse::int::<$inner, $from>(s).map($to::$fn)
            }
        }
        )*
    }
}

/// Implements standard parsing traits for `$type` by calling through to `$inner_fn`.
///
/// Implements:
///
/// * `FromStr`
/// * `TryFrom<&str>`
///
/// And if `alloc` feature is enabled in calling crate:
///
/// * `TryFrom<Box<str>>`
/// * `TryFrom<String>`
///
/// # Arguments
///
/// * `to` - the type converted to e.g., `impl From<&str> for $to`.
/// * `err` - the error type returned by `$inner_fn` (implies returned by `FromStr` and `TryFrom`).
/// * `inner_fn`: The fallible conversion function to call to convert from a string reference.
///
/// # Errors
///
/// All functions use the error returned by `$inner_fn`.
#[macro_export]
#[doc(hidden)] // This is an 'internal' macro that should not be used outside of the `rust-bitcoin` crate.
macro_rules! impl_parse_str {
    ($to:ty, $err:ty, $inner_fn:expr) => {
        $crate::impl_tryfrom_str!(&str, $to, $err, $inner_fn);
        #[cfg(feature = "alloc")]
        $crate::impl_tryfrom_str!(alloc::string::String, $to, $err, $inner_fn; alloc::boxed::Box<str>, $to, $err, $inner_fn);

        impl $crate::_export::_core::str::FromStr for $to {
            type Err = $err;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                $inner_fn(s)
            }
        }
    }
}

/// Implements `TryFrom<$from> for $to`.
#[macro_export]
#[doc(hidden)] // Helper macro called by `impl_parse_str`.
macro_rules! impl_tryfrom_str {
    ($($from:ty, $to:ty, $err:ty, $inner_fn:expr);*) => {
        $(
            impl $crate::_export::_core::convert::TryFrom<$from> for $to {
                type Error = $err;

                fn try_from(s: $from) -> $crate::_export::_core::result::Result<Self, Self::Error> {
                    $inner_fn(s)
                }
            }
        )*
    }
}

/// Removes the prefix `0x` (or `0X`) from a hex string.
///
/// # Errors
///
/// If the input string does not contain a prefix.
pub fn hex_remove_prefix(s: &str) -> Result<&str, PrefixedHexError> {
    if let Some(checked) = s.strip_prefix("0x") {
        Ok(checked)
    } else if let Some(checked) = s.strip_prefix("0X") {
        Ok(checked)
    } else {
        Err(MissingPrefixError::new(s).into())
    }
}

/// Checks a hex string does not have a prefix `0x` (or `0X`).
///
/// # Errors
///
/// If the input string contains a prefix.
pub fn hex_check_unprefixed(s: &str) -> Result<&str, UnprefixedHexError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        return Err(ContainsPrefixError::new(s).into());
    }
    Ok(s)
}

/// Parses a `u32` from a hex string.
///
/// Input string may or may not contain a `0x` (or `0X`) prefix.
///
/// # Errors
///
/// If the input string is not a valid hex encoding of a `u32`.
pub fn hex_u32(s: &str) -> Result<u32, ParseIntError> {
    let unchecked = hex_remove_optional_prefix(s);
    Ok(hex_u32_unchecked(unchecked)?)
}

/// Parses a `u32` from a prefixed hex string.
///
/// # Errors
///
/// - If the input string does not contain a `0x` (or `0X`) prefix.
/// - If the input string is not a valid hex encoding of a `u32`.
pub fn hex_u32_prefixed(s: &str) -> Result<u32, PrefixedHexError> {
    let checked = hex_remove_prefix(s)?;
    Ok(hex_u32_unchecked(checked)?)
}

/// Parses a `u32` from an unprefixed hex string.
///
/// # Errors
///
/// - If the input string contains a `0x` (or `0X`) prefix.
/// - If the input string is not a valid hex encoding of a `u32`.
pub fn hex_u32_unprefixed(s: &str) -> Result<u32, UnprefixedHexError> {
    let checked = hex_check_unprefixed(s)?;
    Ok(hex_u32_unchecked(checked)?)
}

/// Parses a `u32` from an unprefixed hex string without first checking for a prefix.
///
/// # Errors
///
/// - If the input string contains a `0x` (or `0X`) prefix, returns `InvalidDigit` due to the `x`.
/// - If the input string is not a valid hex encoding of a `u32`.
pub fn hex_u32_unchecked(s: &str) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s, 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: 32,
        is_signed: false,
        source: error,
    })
}

/// Parses a `u128` from a hex string.
///
/// Input string may or may not contain a `0x` (or `0X`) prefix.
///
/// # Errors
///
/// If the input string is not a valid hex encoding of a `u128`.
pub fn hex_u128(s: &str) -> Result<u128, ParseIntError> {
    let unchecked = hex_remove_optional_prefix(s);
    Ok(hex_u128_unchecked(unchecked)?)
}

/// Parses a `u128` from a hex string.
///
/// # Errors
///
/// - If the input string does not contain a `0x` (or `0X`) prefix.
/// - If the input string is not a valid hex encoding of a `u128`.
pub fn hex_u128_prefixed(s: &str) -> Result<u128, PrefixedHexError> {
    let checked = hex_remove_prefix(s)?;
    Ok(hex_u128_unchecked(checked)?)
}

/// Parses a `u128` from a hex string.
///
/// # Errors
///
/// - If the input string contains a `0x` (or `0X`) prefix.
/// - If the input string is not a valid hex encoding of a `u128`.
pub fn hex_u128_unprefixed(s: &str) -> Result<u128, UnprefixedHexError> {
    let checked = hex_check_unprefixed(s)?;
    Ok(hex_u128_unchecked(checked)?)
}

/// Parses a `u128` from an unprefixed hex string without first checking for a prefix.
///
/// # Errors
///
/// - If the input string contains a `0x` (or `0X`) prefix, returns `InvalidDigit` due to the `x`.
/// - If the input string is not a valid hex encoding of a `u128`.
pub fn hex_u128_unchecked(s: &str) -> Result<u128, ParseIntError> {
    u128::from_str_radix(s, 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: 128,
        is_signed: false,
        source: error,
    })
}

/// Strips the hex prefix off `s` if one is present.
pub(crate) fn hex_remove_optional_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("0X") {
        stripped
    } else {
        s
    }
}

/// Error returned when parsing an integer from a hex string that is supposed to contain a prefix.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrefixedHexError(PrefixedHexErrorInner);

/// Error returned when parsing an integer from a hex string that is supposed to contain a prefix.
#[derive(Debug, Clone, Eq, PartialEq)]
enum PrefixedHexErrorInner {
    /// Hex string is missing prefix.
    MissingPrefix(MissingPrefixError),
    /// Error parsing integer from hex string.
    ParseInt(ParseIntError),
}

impl From<Infallible> for PrefixedHexError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for PrefixedHexErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for PrefixedHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PrefixedHexErrorInner as E;

        match self.0 {
            E::MissingPrefix(ref e) => write_err!(f, "hex string is missing prefix"; e),
            E::ParseInt(ref e) => write_err!(f, "prefixed hex string invalid int"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrefixedHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PrefixedHexErrorInner as E;

        match self.0 {
            E::MissingPrefix(ref e) => Some(e),
            E::ParseInt(ref e) => Some(e),
        }
    }
}

impl From<MissingPrefixError> for PrefixedHexError {
    fn from(e: MissingPrefixError) -> Self { Self(PrefixedHexErrorInner::MissingPrefix(e)) }
}

impl From<ParseIntError> for PrefixedHexError {
    fn from(e: ParseIntError) -> Self { Self(PrefixedHexErrorInner::ParseInt(e)) }
}

/// Error returned when parsing an integer from a hex string that is not supposed to contain a prefix.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnprefixedHexError(UnprefixedHexErrorInner);

#[derive(Debug, Clone, Eq, PartialEq)]
enum UnprefixedHexErrorInner {
    /// Hex string contains prefix.
    ContainsPrefix(ContainsPrefixError),
    /// Error parsing integer from string.
    ParseInt(ParseIntError),
}

impl From<Infallible> for UnprefixedHexError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<Infallible> for UnprefixedHexErrorInner {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for UnprefixedHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use UnprefixedHexErrorInner as E;

        match self.0 {
            E::ContainsPrefix(ref e) => write_err!(f, "hex string is contains prefix"; e),
            E::ParseInt(ref e) => write_err!(f, "hex string parse int"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnprefixedHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use UnprefixedHexErrorInner as E;

        match self.0 {
            E::ContainsPrefix(ref e) => Some(e),
            E::ParseInt(ref e) => Some(e),
        }
    }
}

impl From<ContainsPrefixError> for UnprefixedHexError {
    fn from(e: ContainsPrefixError) -> Self { Self(UnprefixedHexErrorInner::ContainsPrefix(e)) }
}

impl From<ParseIntError> for UnprefixedHexError {
    fn from(e: ParseIntError) -> Self { Self(UnprefixedHexErrorInner::ParseInt(e)) }
}

/// Error returned when a hex string is missing a prefix (e.g. `0x`).
#[derive(Debug, Clone, Eq, PartialEq)]
struct MissingPrefixError {
    hex: InputString,
}

impl MissingPrefixError {
    /// Constructs a new error from the string with the missing prefix.
    pub(crate) fn new(hex: &str) -> Self { Self { hex: hex.into() } }
}

impl fmt::Display for MissingPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} because it is missing the '0x' prefix", self.hex.display_cannot_parse("hex"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MissingPrefixError {}

/// Error when hex string contains a prefix (e.g. 0x).
#[derive(Debug, Clone, Eq, PartialEq)]
struct ContainsPrefixError {
    hex: InputString,
}

impl ContainsPrefixError {
    /// Constructs a new error from the string that contains the prefix.
    pub(crate) fn new(hex: &str) -> Self { Self { hex: hex.into() } }
}

impl fmt::Display for ContainsPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} because it contains the '0x' prefix", self.hex.display_cannot_parse("hex"))
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContainsPrefixError {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::panic;

    use super::*;

    #[test]
    fn parse_int() {
        assert!(int::<u8, _>("1").is_ok());
        let _ = int::<i8, _>("not a number").map_err(|e| assert!(e.is_signed));
        let _ = int::<u8, _>("not a number").map_err(|e| assert!(!e.is_signed));
    }

    #[test]
    #[cfg(feature = "std")]
    fn parse_int_panic_when_populating_bits() {
        // Fields in the test type are never used
        #[allow(dead_code)]
        struct TestTypeLargerThanU128(u128, u128);
        impl_integer!(TestTypeLargerThanU128);
        impl FromStr for TestTypeLargerThanU128 {
            type Err = core::num::ParseIntError;

            fn from_str(_: &str) -> Result<Self, Self::Err> {
                "Always invalid for testing".parse::<u32>().map(|_| TestTypeLargerThanU128(0, 0))
            }
        }
        impl From<i8> for TestTypeLargerThanU128 {
            fn from(_: i8) -> Self { TestTypeLargerThanU128(0, 0) }
        }

        let result = panic::catch_unwind(|| int::<TestTypeLargerThanU128, _>("not a number"));
        assert!(result.is_err());
    }

    #[test]
    fn remove_prefix() {
        let lower = "0xhello";
        assert_eq!(hex_remove_prefix(lower).unwrap(), "hello");

        let upper = "0Xhello";
        assert_eq!(hex_remove_prefix(upper).unwrap(), "hello");

        let err = "error";
        assert!(hex_remove_prefix(err).is_err());
    }

    #[test]
    fn check_unprefixed() {
        let lower = "0xhello";
        assert!(hex_check_unprefixed(lower).is_err());

        let upper = "0Xhello";
        assert!(hex_check_unprefixed(upper).is_err());

        let valid = "hello";
        assert_eq!(hex_check_unprefixed(valid).unwrap(), "hello");
    }

    #[test]
    fn parse_u32_from_hex_prefixed() {
        let want = 171;
        let got = hex_u32("0xab").expect("failed to parse prefixed hex");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_u32_from_hex_no_prefix() {
        let want = 171;
        let got = hex_u32("ab").expect("failed to parse non-prefixed hex");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_hex_u32_prefixed() {
        let want = 171; // 0xab
        assert_eq!(hex_u32_prefixed("0xab").unwrap(), want);
        assert!(hex_u32_unprefixed("0xab").is_err());
    }

    #[test]
    fn parse_hex_u32_unprefixed() {
        let want = 171; // 0xab
        assert_eq!(hex_u32_unprefixed("ab").unwrap(), want);
        assert!(hex_u32_prefixed("ab").is_err());
    }

    #[test]
    fn parse_u128_from_hex_prefixed() {
        let want = 3_735_928_559;
        let got = hex_u128("0xdeadbeef").expect("failed to parse prefixed hex");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_u128_from_hex_no_prefix() {
        let want = 3_735_928_559;
        let got = hex_u128("deadbeef").expect("failed to parse non-prefixed hex");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_hex_u128_prefixed() {
        let want = 3_735_928_559;
        assert_eq!(hex_u128_prefixed("0xdeadbeef").unwrap(), want);
        assert!(hex_u128_unprefixed("0xdeadbeef").is_err());
    }

    #[test]
    fn parse_hex_u128_unprefixed() {
        let want = 3_735_928_559;
        assert_eq!(hex_u128_unprefixed("deadbeef").unwrap(), want);
        assert!(hex_u128_prefixed("deadbeef").is_err());
    }

    #[test]
    fn parse_u32_from_hex_unchecked_errors_on_prefix() {
        assert!(hex_u32_unchecked("0xab").is_err());
    }
}
