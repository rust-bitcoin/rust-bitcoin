use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;

use bitcoin_internals::write_err;

use crate::error::impl_std_error;
use crate::prelude::*;

/// Error with rich context returned when a string can't be parsed as an integer.
///
/// This is an extension of [`core::num::ParseIntError`], which carries the input that failed to
/// parse as well as type information. As a result it provides very informative error messages that
/// make it easier to understand the problem and correct mistakes.
///
/// Note that this is larger than the type from `core` so if it's passed through a deep call stack
/// in a performance-critical application you may want to box it or throw away the context by
/// converting to `core` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseIntError {
    input: String,
    // for displaying - see Display impl with nice error message below
    bits: u8,
    // We could represent this as a single bit but it wouldn't actually derease the cost of moving
    // the struct because String contains pointers so there will be padding of bits at least
    // pointer_size - 1 bytes: min 1B in practice.
    is_signed: bool,
    source: core::num::ParseIntError,
}

impl ParseIntError {
    /// Returns the input that was attempted to be parsed.
    pub fn input(&self) -> &str { &self.input }
}

impl From<ParseIntError> for core::num::ParseIntError {
    fn from(value: ParseIntError) -> Self { value.source }
}

impl AsRef<core::num::ParseIntError> for ParseIntError {
    fn as_ref(&self) -> &core::num::ParseIntError { &self.source }
}

impl fmt::Display for ParseIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let signed = if self.is_signed { "signed" } else { "unsigned" };
        let n = if self.bits == 8 { "n" } else { "" };
        write_err!(f, "failed to parse '{}' as a{} {}-bit {} integer", self.input, n, self.bits, signed; self.source)
    }
}

/// Not strictly neccessary but serves as a lint - avoids weird behavior if someone accidentally
/// passes non-integer to the `parse()` function.
pub(crate) trait Integer:
    FromStr<Err = core::num::ParseIntError> + TryFrom<i8> + Sized
{
}

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
pub(crate) fn int<T: Integer, S: AsRef<str> + Into<String>>(s: S) -> Result<T, ParseIntError> {
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

pub(crate) fn hex_u32<S: AsRef<str> + Into<String>>(s: S) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s.as_ref(), 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: u8::try_from(core::mem::size_of::<u32>() * 8).expect("max is 32 bits for u32"),
        is_signed: u32::try_from(-1i8).is_ok(),
        source: error,
    })
}

impl_std_error!(ParseIntError, source);

/// Implements `TryFrom<$from> for $to` using `parse::int`, mapping the output using infallible
/// conversion function `fn`.
macro_rules! impl_tryfrom_str_from_int_infallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident);*) => {
        $(
        impl core::convert::TryFrom<$from> for $to {
            type Error = $crate::error::ParseIntError;

            fn try_from(s: $from) -> Result<Self, Self::Error> {
                $crate::parse::int::<$inner, $from>(s).map($to::$fn)
            }
        }
        )*
    }
}
pub(crate) use impl_tryfrom_str_from_int_infallible;

/// Implements `FromStr` and `TryFrom<{&str, String, Box<str>}> for $to` using `parse::int`, mapping
/// the output using infallible conversion function `fn`.
///
/// The `Error` type is `ParseIntError`
macro_rules! impl_parse_str_from_int_infallible {
    ($to:ident, $inner:ident, $fn:ident) => {
        $crate::parse::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn; String, $to, $inner, $fn; Box<str>, $to, $inner, $fn);

        impl core::str::FromStr for $to {
            type Err = $crate::error::ParseIntError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::parse::int::<$inner, &str>(s).map($to::$fn)
            }
        }

    }
}
pub(crate) use impl_parse_str_from_int_infallible;

/// Implements `TryFrom<$from> for $to` using `parse::int`, mapping the output using fallible
/// conversion function `fn`.
macro_rules! impl_tryfrom_str_from_int_fallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident, $err:ident);*) => {
        $(
        impl core::convert::TryFrom<$from> for $to {
            type Error = $err;

            fn try_from(s: $from) -> Result<Self, Self::Error> {
                let u = $crate::parse::int::<$inner, $from>(s)?;
                $to::$fn(u)
            }
        }
        )*
    }
}
pub(crate) use impl_tryfrom_str_from_int_fallible;

/// Implements `FromStr` and `TryFrom<{&str, String, Box<str>}> for $to` using `parse::int`, mapping
/// the output using fallible conversion function `fn`.
///
/// The `Error` type is `ParseIntError`
macro_rules! impl_parse_str_from_int_fallible {
    ($to:ident, $inner:ident, $fn:ident, $err:ident) => {
        $crate::parse::impl_tryfrom_str_from_int_fallible!(&str, $to, $inner, $fn, $err; String, $to, $inner, $fn, $err; Box<str>, $to, $inner, $fn, $err);

        impl core::str::FromStr for $to {
            type Err = $err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let u = $crate::parse::int::<$inner, &str>(s)?;
                $to::$fn(u)
            }
        }

    }
}
pub(crate) use impl_parse_str_from_int_fallible;
