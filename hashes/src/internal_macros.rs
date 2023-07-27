// SPDX-License-Identifier: CC0-1.0

//! Non-public macros

macro_rules! arr_newtype_fmt_impl {
    ($ty:ident, $bytes:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::fmt::LowerHex for $ty<$($gen),*> {
            #[inline]
            fn fmt(&self, f: &mut $crate::_export::_core::fmt::Formatter) -> $crate::_export::_core::fmt::Result {
                #[allow(unused)]
                use crate::Hash as _;
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
                #[allow(unused)]
                use crate::Hash as _;
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
            /// Displays hex forwards, regardless of how this type would display it naturally.
            ///
            /// This is mainly intended as an internal method and you shouldn't need it unless
            /// you're doing something special.
            pub fn forward_hex(&self) -> impl '_ + core::fmt::LowerHex + core::fmt::UpperHex {
                $crate::hex::DisplayHex::as_hex(&self.0)
            }

            /// Displays hex backwards, regardless of how this type would display it naturally.
            ///
            /// This is mainly intended as an internal method and you shouldn't need it unless
            /// you're doing something special.
            pub fn backward_hex(&self) -> impl '_ + core::fmt::LowerHex + core::fmt::UpperHex {
                $crate::hex::display::DisplayArray::<_, [u8; $bits / 8 * 2]>::new(self.0.iter().rev())
            }

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

        impl<$($gen: $gent),*> str::FromStr for Hash<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use $crate::hex::{FromHex, HexToBytesIter};
                use $crate::Hash;

                let inner: [u8; $bits / 8] = if $reverse {
                    FromHex::from_byte_iter(HexToBytesIter::new(s)?.rev())?
                } else {
                    FromHex::from_byte_iter(HexToBytesIter::new(s)?)?
                };
                Ok(Self::from_byte_array(inner))
            }
        }

        $crate::internal_macros::arr_newtype_fmt_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
        serde_impl!(Hash, $bits / 8 $(, $gen: $gent)*);
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

        impl<$($gen: $gent),*> crate::Hash for Hash<$($gen),*> {
            type Engine = HashEngine;
            type Bytes = [u8; $bits / 8];

            const LEN: usize = $bits / 8;
            const DISPLAY_BACKWARD: bool = $reverse;

            fn engine() -> Self::Engine {
                Self::internal_engine()
            }

            fn from_engine(e: HashEngine) -> Hash<$($gen),*> {
                from_engine(e)
            }

            fn from_slice(sl: &[u8]) -> Result<Hash<$($gen),*>, FromSliceError> {
                if sl.len() != $bits / 8 {
                    Err(FromSliceError{expected: Self::LEN, got: sl.len()})
                } else {
                    let mut ret = [0; $bits / 8];
                    ret.copy_from_slice(sl);
                    Ok(Self::internal_new(ret))
                }
            }

            fn to_byte_array(self) -> Self::Bytes {
                self.0
            }

            fn as_byte_array(&self) -> &Self::Bytes {
                &self.0
            }

            fn from_byte_array(bytes: Self::Bytes) -> Self {
                Self::internal_new(bytes)
            }

            fn all_zeros() -> Self {
                Hash::internal_new([0x00; $bits / 8])
            }
        }
    }
}
pub(crate) use hash_trait_impls;

/// Creates a type called `Hash` and implements standard interface for it.
///
/// The created type will have all standard derives, `Hash` impl and implementation of
/// `internal_engine` returning default. The created type has a single field.
///
/// Arguments:
///
/// * `$bits` - the number of bits of the hash type
/// * `$reverse` - `true` if the hash should be displayed backwards, `false` otherwise
/// * `$doc` - doc string to put on the type
/// * `$schemars` - a literal that goes into `schema_with`.
///
/// The `from_engine` free-standing function is still required with this macro. See the doc of
/// [`hash_trait_impls`].
macro_rules! hash_type {
    ($bits:expr, $reverse:expr, $doc:literal, $schemars:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "schemars", derive(crate::schemars::JsonSchema))]
        #[repr(transparent)]
        pub struct Hash(
            #[cfg_attr(feature = "schemars", schemars(schema_with = $schemars))] [u8; $bits / 8],
        );

        impl Hash {
            fn internal_new(arr: [u8; $bits / 8]) -> Self { Hash(arr) }

            fn internal_engine() -> HashEngine { Default::default() }
        }

        crate::internal_macros::hash_trait_impls!($bits, $reverse);
    };
}
pub(crate) use hash_type;
