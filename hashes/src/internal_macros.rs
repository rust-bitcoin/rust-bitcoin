// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

macro_rules! arr_newtype_fmt_impl {
    ($ty:ident, $bytes:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                let case = $crate::hex::Case::Lower;
                if <$ty<$($gen),*>>::DISPLAY_BACKWARD {
                    $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter().rev(), case)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter(), case)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::UpperHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                let case = $crate::hex::Case::Upper;
                if <$ty<$($gen),*>>::DISPLAY_BACKWARD {
                    $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter().rev(), case)
                } else {
                    $crate::hex::fmt_hex_exact!(f, $bytes, self.0.iter(), case)
                }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Display for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                $crate::_export::_core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::fmt::Debug for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                write!(f, "{:#}", self)
            }
        }
    }
}
pub(crate) use arr_newtype_fmt_impl;

/// Adds trait impls to the type called `Hash` in the current scope.
///
/// Implpements various conversion traits as well as the [`crate::Hash`] trait.
/// Arguments:
///
/// * `$bits` - number of bits this hash type has
/// * `$reverse` - `bool`  - `true` if the hash type should be displayed backwards, `false`
///    otherwise.
/// * `$gen: $gent` - generic type(s) and trait bound(s)
///
/// Restrictions on usage:
///
/// * There must be a free-standing `fn from_engine(HashEngine) -> Hash` in the scope
/// * `fn internal_new([u8; $bits / 8]) -> Self` must exist on `Hash`
/// * `fn internal_engine() -> HashEngine` must exist on `Hash`
///
/// `from_engine` obviously implements the finalization algorithm.
/// `internal_new` is required so that types with more than one field are constructible.
/// `internal_engine` is required to initialize the engine for given hash type.
macro_rules! hash_trait_impls {
    ($bits:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> Hash<$($gen),*> {
            /// Zero cost conversion between a fixed length byte array shared reference and
            /// a shared reference to this Hash type.
            pub fn from_bytes_ref(bytes: &[u8; $bits / 8]) -> &Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bits / 8]
                unsafe { &*(bytes as *const _ as *const Self) }
            }

            /// Zero cost conversion between a fixed length byte array exclusive reference and
            /// an exclusive reference to this Hash type.
            pub fn from_bytes_mut(bytes: &mut [u8; $bits / 8]) -> &mut Self {
                // Safety: Sound because Self is #[repr(transparent)] containing [u8; $bits / 8]
                unsafe { &mut *(bytes as *mut _ as *mut Self) }
            }
        }

        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for Hash<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::hex::{FromHex};

                let mut bytes = <[u8; $bits / 8]>::from_hex(s)?;
                if $reverse {
                    bytes.reverse();
                }
                Ok(Self::from_byte_array(bytes))
            }
        }

        $crate::internal_macros::arr_newtype_fmt_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
        serde_impl!(Hash $(, $gen: $gent)*);
        borrow_slice_impl!(Hash $(, $gen: $gent)*);

        impl<$($gen: $gent),*> $crate::_export::_core::convert::AsRef<[u8; $bits / 8]> for Hash<$($gen),*> {
            fn as_ref(&self) -> &[u8; $bits / 8] {
                &self.0
            }
        }

        impl<I: SliceIndex<[u8]> $(, $gen: $gent)*> Index<I> for Hash<$($gen),*> {
            type Output = I::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output {
                &self.0[index]
            }
        }
    }
}
pub(crate) use hash_trait_impls;
