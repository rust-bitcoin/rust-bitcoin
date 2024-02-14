// SPDX-License-Identifier: CC0-1.0

//! Provides a rich error type for parsing integers from strings.

use alloc::string::String;      // The whole module requires "alloc".
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
    /// The input string that caused the error.
    input: String,
    /// The source of this error.
    source: core::num::ParseIntError,

    /// For displaying - see Display impl with nice error message below
    bits: u8,

    /// We could represent this as a single bit but it wouldn't actually derease the cost of moving
    /// the struct because String contains pointers so there will be padding of bits at least
    /// pointer_size - 1 bytes: min 1B in practice.
    is_signed: bool,
}

impl ParseIntError {
    /// Returns the input that was attempted to be parsed.
    pub fn input(&self) -> &str { &self.input }

    /// Returns the `num::ParseIntError` encountered while parsing input.
    pub fn source(&self) -> &core::num::ParseIntError { &self.source }

    /// Returns the input and source error.
    pub fn into_input_source(self) -> (String, core::num::ParseIntError) {
        (self.input, self.source)
    }
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

/// Not strictly neccessary but serves as a lint - avoids weird behavior if someone accidentally
/// passes non-integer to the `parse()` function.
pub trait Integer:
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

/// Parses a hex string for a `u32` value.
pub fn hex_u32<S: AsRef<str> + Into<String>>(s: S) -> Result<u32, ParseIntError> {
    u32::from_str_radix(s.as_ref(), 16).map_err(|error| ParseIntError {
        input: s.into(),
        bits: u8::try_from(core::mem::size_of::<u32>() * 8).expect("max is 32 bits for u32"),
        is_signed: u32::try_from(-1i8).is_ok(),
        source: error,
    })
}

/// Implements `TryFrom<$from> for $to` using `units::int!()`, mapping the output using infallible
/// conversion function `fn`.
#[macro_export]
macro_rules! impl_tryfrom_str_from_int_infallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident);*) => {
        $(
        impl core::convert::TryFrom<$from> for $to {
            type Error = $crate::ParseIntError;

            fn try_from(s: $from) -> core::result::Result<Self, Self::Error> {
                $crate::parse::int::<$inner, $from>(s).map($to::$fn)
            }
        }
        )*
    }
}

/// Implements `FromStr` and `TryFrom<{&str, String, Box<str>}> for $to` using `units::int!()`,
/// mapping the output using infallible conversion function `fn`.
///
///
/// The `Error` type is `ParseIntError`.
#[macro_export]
macro_rules! impl_parse_str_from_int_infallible {
    ($to:ident, $inner:ident, $fn:ident) => {
        $crate::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn);

        #[cfg(feature = "alloc")]
        $crate::impl_tryfrom_str_from_int_infallible!(String, $to, $inner, $fn; Box<str>, $to, $inner, $fn);

        impl core::str::FromStr for $to {
            type Err = $crate::ParseIntError;

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
        $crate::impl_tryfrom_str!(&str, $to, $err, $inner_fn);

        #[cfg(feature = "alloc")]
        $crate::impl_tryfrom_str!($crate::prelude::String, $to, $err, $inner_fn; $crate::prelude::Box<str>, $to, $err, $inner_fn);

        impl core::str::FromStr for $to {
            type Err = $err;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                $inner_fn(s)
            }
        }
    }
}
