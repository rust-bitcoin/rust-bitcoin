// SPDX-License-Identifier: CC0-1.0

//! Parsing utilities.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

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
    pub(crate) input: String,
    // for displaying - see Display impl with nice error message below
    bits: u8,
    // We could represent this as a single bit but it wouldn't actually derease the cost of moving
    // the struct because String contains pointers so there will be padding of bits at least
    // pointer_size - 1 bytes: min 1B in practice.
    is_signed: bool,
    pub(crate) source: core::num::ParseIntError,
}

impl ParseIntError {
    /// Returns the input that was attempted to be parsed.
    pub fn input(&self) -> &str { &self.input }
}

impl fmt::Display for ParseIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let signed = if self.is_signed { "signed" } else { "unsigned" };
        let n = if self.bits == 8 { "n" } else { "" };
        write_err!(f, "failed to parse '{}' as a{} {}-bit {} integer", self.input, n, self.bits, signed; self.source)
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
pub trait Integer: FromStr<Err = core::num::ParseIntError> + TryFrom<i8> + Sized {}

macro_rules! impl_integer {
    ($($type:ty),* $(,)?) => {
        $(
        impl Integer for $type {}
        )*
    }
}

impl_integer!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128);

/// Parses the input string as an integer returning an error carrying rich context.
///
/// If the caller owns `String` or `Box<str>` which is not used later it's better to pass it as
/// owned since it avoids allocation in error case.
pub fn int<T: Integer, S: AsRef<str> + Into<String>>(s: S) -> Result<T, ParseIntError> {
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

/// Parses a `u32` from a hex string.
///
/// Input string may or may not contain a `0x` prefix.
pub fn hex_u32<S: AsRef<str> + Into<String>>(s: S) -> Result<u32, ParseIntError> {
    let stripped = strip_hex_prefix(s.as_ref());
    u32::from_str_radix(stripped, 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: 32,
        is_signed: false,
        source: error,
    })
}

/// Parses a `u128` from a hex string.
///
/// Input string may or may not contain a `0x` prefix.
pub fn hex_u128<S: AsRef<str> + Into<String>>(s: S) -> Result<u128, ParseIntError> {
    let stripped = strip_hex_prefix(s.as_ref());
    u128::from_str_radix(stripped, 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: 128,
        is_signed: false,
        source: error,
    })
}

/// Strips the hex prefix off `s` if one is present.
pub(crate) fn strip_hex_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("0X") {
        stripped
    } else {
        s
    }
}

/// Implements `TryFrom<$from> for $to` using `parse::int`, mapping the output using infallible
/// conversion function `fn`.
#[macro_export]
macro_rules! impl_tryfrom_str_from_int_infallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident);*) => {
        $(
        impl core::convert::TryFrom<$from> for $to {
            type Error = $crate::parse::ParseIntError;

            fn try_from(s: $from) -> core::result::Result<Self, Self::Error> {
                $crate::parse::int::<$inner, $from>(s).map($to::$fn)
            }
        }
        )*
    }
}

/// Implements `FromStr` and `TryFrom<{&str, String, Box<str>}> for $to` using `parse::int`, mapping
/// the output using infallible conversion function `fn`.
///
/// The `Error` type is `ParseIntError`
#[macro_export]
macro_rules! impl_parse_str_from_int_infallible {
    ($to:ident, $inner:ident, $fn:ident) => {
        #[cfg(all(feature = "alloc", not(feature = "std")))]
        $crate::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn; alloc::string::String, $to, $inner, $fn; alloc::boxed::Box<str>, $to, $inner, $fn);
        #[cfg(feature = "std")]
        $crate::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn; std::string::String, $to, $inner, $fn; std::boxed::Box<str>, $to, $inner, $fn);

        impl core::str::FromStr for $to {
            type Err = $crate::parse::ParseIntError;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                $crate::parse::int::<$inner, &str>(s).map($to::$fn)
            }
        }

    }
}

/// Implements `TryFrom<$from> for $to`.
#[macro_export]
macro_rules! impl_tryfrom_str {
    ($($from:ty, $to:ty, $err:ty, $inner_fn:expr);*) => {
        $(
            impl core::convert::TryFrom<$from> for $to {
                type Error = $err;

                fn try_from(s: $from) -> core::result::Result<Self, Self::Error> {
                    $inner_fn(s)
                }
            }
        )*
    }
}

/// Implements standard parsing traits for `$type` by calling into `$inner_fn`.
#[macro_export]
macro_rules! impl_parse_str {
    ($to:ty, $err:ty, $inner_fn:expr) => {
        $crate::impl_tryfrom_str!(&str, $to, $err, $inner_fn; String, $to, $err, $inner_fn; Box<str>, $to, $err, $inner_fn);

        impl core::str::FromStr for $to {
            type Err = $err;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                $inner_fn(s)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse_u128_from_hex_prefixed() {
        let want = 3735928559;
        let got = hex_u128("0xdeadbeef").expect("failed to parse prefixed hex");
        assert_eq!(got, want);
    }

    #[test]
    fn parse_u128_from_hex_no_prefix() {
        let want = 3735928559;
        let got = hex_u128("deadbeef").expect("failed to parse non-prefixed hex");
        assert_eq!(got, want);
    }
}
