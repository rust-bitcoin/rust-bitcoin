// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

/// Adds hex string trait impls to a bytelike type using hex.
///
/// Implements:
///
/// * `str::FromStr`
/// * `fmt::{LowerHex, UpperHex}` using `hex-conservative`.
/// * `fmt::{Display, Debug}` by calling `LowerHex`
///
/// Requires:
///
/// * [`hex-conservative`] to publicly available as `$crate::hex`.
/// * `$ty` must implement `IntoIterator<Item=Borrow<u8>>`.
///
/// (See also [`hex-conservative::fmt_hex_exact`].)
///
/// # Parameters
///
/// * `ty` - The bytelike type to implement the traits on.
/// * `$len` - The number of bytes this type has.
/// * `$reverse` - `true` if the type should be displayed backwards, `false` otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s).
///
/// [`hex-conservative`]: <https://crates.io/crates/hex-conservative>
#[cfg(feature = "hex")]
macro_rules! impl_hex_string_traits {
    ($ty:ident, $len:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for $ty<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::hex::FromHex;

                let mut bytes = <[u8; { $len }]>::from_hex(s)?;
                if $reverse {
                    bytes.reverse();
                }
                Ok(Self::from_byte_array(bytes))
            }
        }

        $crate::hex::impl_fmt_traits! {
            #[display_backward($reverse)]
            impl<$($gen: $gent),*> fmt_traits for $ty<$($gen),*> {
                const LENGTH: usize = ($len); // parens required due to rustc parser weirdness
            }
        }
    }
}
#[cfg(feature = "hex")]
pub(crate) use impl_hex_string_traits;

/// Implements `fmt::Debug` manually using hex (i.e, without using `hex-conservative`).
#[cfg(not(feature = "hex"))]
macro_rules! impl_debug_only {
    ($ty:ident, $len:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::debug_hex(self.as_byte_array(), f)
            }
        }
    }
}
#[cfg(not(feature = "hex"))]
pub(crate) use impl_debug_only;
