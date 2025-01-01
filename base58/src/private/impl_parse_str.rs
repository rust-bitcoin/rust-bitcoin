// SPDX-License-Identifier: CC0-1.0

//! Provides the `impl_parse_str` macro.

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
/// All implementations error using `$err` (expected to be the error returned by `$inner_fn`).
macro_rules! impl_parse_str {
    ($to:ty, $err:ty, $inner_fn:expr) => {
        $crate::private::impl_parse_str::impl_tryfrom_str!(&str, $to, $err, $inner_fn);
        #[cfg(feature = "alloc")]
        $crate::private::impl_parse_str::impl_tryfrom_str!(alloc::string::String, $to, $err, $inner_fn; alloc::boxed::Box<str>, $to, $err, $inner_fn);

        impl $crate::_export::_core::str::FromStr for $to {
            type Err = $err;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                $inner_fn(s)
            }
        }
    }
}
pub(crate) use impl_parse_str;

/// Implements `TryFrom<$from> for $to` by calling `inner_fn`.
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
pub(crate) use impl_tryfrom_str;
