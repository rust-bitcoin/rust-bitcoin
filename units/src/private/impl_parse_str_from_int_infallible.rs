// SPDX-License-Identifier: CC0-1.0

//! Provides the `impl_parse_str_from_int_infallible` macro.

/// Implements standard parsing traits for `$type` by calling `parse::int`.
///
/// Once the string is converted to an integer the infallible conversion function `fn` is used to
/// create the type `to`.
///
/// Requires `units::parse::ParseIntError` and `core::str::FromStr` to be in scope.
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
/// All implementations error using `units::parse::ParseIntError`.
macro_rules! impl_parse_str_from_int_infallible {
    ($to:ident, $inner:ident, $fn:ident) => {
        $crate::private::impl_parse_str_from_int_infallible::impl_tryfrom_str_from_int_infallible!(&str, $to, $inner, $fn);
        #[cfg(feature = "alloc")]
        $crate::private::impl_parse_str_from_int_infallible::impl_tryfrom_str_from_int_infallible!(alloc::string::String, $to, $inner, $fn; alloc::boxed::Box<str>, $to, $inner, $fn);

        impl $crate::_export::_core::str::FromStr for $to {
            type Err = ParseIntError;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                let x = <$inner>::from_str(s).map_err(|error| ParseIntError::new(
                    s,
                    u8::try_from(core::mem::size_of::<$inner>() * 8).expect("max is 128 bits for u128"),
                    // We detect if the type is signed by checking if -1 can be represented by it
                    // this way we don't have to implement special traits and optimizer will get rid of the
                    // computation.
                    <$inner>::try_from(-1i8).is_ok(),
                    error,
                ))?;
                Ok($to::$fn(x))
            }
        }
    }
}
pub(crate) use impl_parse_str_from_int_infallible;

/// Implements `TryFrom<$from> for $to` using `parse::int` and mapping the output using `fn`.
macro_rules! impl_tryfrom_str_from_int_infallible {
    ($($from:ty, $to:ident, $inner:ident, $fn:ident);*) => {
        $(
        impl $crate::_export::_core::convert::TryFrom<$from> for $to {
            type Error = ParseIntError;

            fn try_from(s: $from) -> $crate::_export::_core::result::Result<Self, Self::Error> {
                let x = <$inner>::from_str(s.as_ref()).map_err(|error| ParseIntError::new(
                    s.as_ref(),
                    u8::try_from(core::mem::size_of::<$inner>() * 8).expect("max is 128 bits for u128"),
                    // We detect if the type is signed by checking if -1 can be represented by it
                    // this way we don't have to implement special traits and optimizer will get rid of the
                    // computation.
                    <$inner>::try_from(-1i8).is_ok(),
                    error,
                ))?;
                Ok($to::$fn(x))
            }
        }
        )*
    }
}
pub(crate) use impl_tryfrom_str_from_int_infallible;
