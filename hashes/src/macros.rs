// SPDX-License-Identifier: CC0-1.0

//! Public macros.

/// Adds trait impls to a bytelike type.
///
/// Implements:
///
/// * `str::FromStr`
/// * `fmt::{LowerHex, UpperHex}` using `hex-conservative`.
/// * `fmt::{Display, Debug}` by calling `LowerHex`
/// * `serde::{Deserialize, Serialize}`
/// * `AsRef[u8; $len]`
/// * `AsRef[u8]`
/// * `Borrow<[u8]>`
/// * `slice::SliceIndex<[u8]>`
///
/// Arguments:
///
/// * `ty` - The bytelike type to implement the traits on.
/// * `$len` - The number of bytes this type has.
/// * `$reverse` - `true` if the type should be displayed backwards, `false` otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s).
#[macro_export]
macro_rules! impl_bytelike_traits {
    ($ty:ident, $len:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for $ty<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;

            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::hex::FromHex;

                let mut bytes = <[u8; $len]>::from_hex(s)?;
                if $reverse {
                    bytes.reverse();
                }
                Ok(Self::from_byte_array(bytes))
            }
        }

        $crate::hex::impl_fmt_traits! {
            #[display_backward($reverse)]
            impl<$($gen: $gent),*> fmt_traits for $ty<$($gen),*> {
                const LENGTH: usize = $len;
            }
        }

        $crate::serde_impl!($ty, $len $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8; $len]> for $ty<$($gen),*> {
            #[inline]
            fn as_ref(&self) -> &[u8; $len] { self.as_byte_array() }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8]> for $ty<$($gen),*> {
            #[inline]
            fn as_ref(&self) -> &[u8] { &self[..] }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::borrow::Borrow<[u8]> for $ty<$($gen),*>  {
            fn borrow(&self) -> &[u8] {  &self[..] }
        }

        impl<I: $crate::_export::_core::slice::SliceIndex<[u8]> $(, $gen: $gent)*>
            $crate::_export::_core::ops::Index<I> for $ty<$($gen),*> {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    }
}
