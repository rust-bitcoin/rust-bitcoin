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
///
/// `from_engine` obviously implements the finalization algorithm.
macro_rules! hash_trait_impls {
    ($bits:expr, $reverse:expr $(, $gen:ident: $gent:ident)*) => {
        impl<$($gen: $gent),*> $crate::_export::_core::str::FromStr for Hash<$($gen),*> {
            type Err = $crate::hex::HexToArrayError;
            fn from_str(s: &str) -> $crate::_export::_core::result::Result<Self, Self::Err> {
                use $crate::{hex::{FromHex}};

                let mut bytes = <[u8; $bits / 8]>::from_hex(s)?;
                if $reverse {
                    bytes.reverse();
                }
                Ok(Self::from_byte_array(bytes))
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

        impl<$($gen: $gent),*> crate::GeneralHash for Hash<$($gen),*> {
            type Engine = HashEngine;

            fn from_engine(e: HashEngine) -> Hash<$($gen),*> { Self::from_engine(e) }
        }

        impl<$($gen: $gent),*> crate::Hash for Hash<$($gen),*> {
            type Bytes = [u8; $bits / 8];

            const LEN: usize = $bits / 8;
            const DISPLAY_BACKWARD: bool = $reverse;

            fn from_slice(sl: &[u8]) -> $crate::_export::_core::result::Result<Hash<$($gen),*>, $crate::FromSliceError> {
                Self::from_slice(sl)
            }

            fn to_byte_array(self) -> Self::Bytes { self.to_byte_array() }

            fn as_byte_array(&self) -> &Self::Bytes { self.as_byte_array() }

            fn from_byte_array(bytes: Self::Bytes) -> Self { Self::from_byte_array(bytes) }
        }
    }
}
pub(crate) use hash_trait_impls;

/// Creates a type called `Hash` and implements standard interface for it.
///
/// The created type has a single field and will have all standard derives as well as an
/// implementation of [`crate::Hash`].
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
    ($bits:expr, $reverse:expr, $doc:literal) => {
        $crate::internal_macros::hash_type_no_default!($bits, $reverse, $doc);

        impl Hash {
            /// Constructs a new engine.
            pub fn engine() -> HashEngine { Default::default() }

            /// Hashes some bytes.
            #[allow(clippy::self_named_constructors)] // Hash is a noun and a verb.
            pub fn hash(data: &[u8]) -> Self { <Self as crate::GeneralHash>::hash(data) }

            /// Hashes all the byte slices retrieved from the iterator together.
            pub fn hash_byte_chunks<B, I>(byte_slices: I) -> Self
            where
                B: AsRef<[u8]>,
                I: IntoIterator<Item = B>,
            {
                <Self as crate::GeneralHash>::hash_byte_chunks(byte_slices)
            }

            /// Hashes the entire contents of the `reader`.
            #[cfg(feature = "bitcoin-io")]
            pub fn hash_reader<R: io::BufRead>(reader: &mut R) -> Result<Self, io::Error> {
                <Self as crate::GeneralHash>::hash_reader(reader)
            }
        }
    };
}
pub(crate) use hash_type;

macro_rules! hash_type_no_default {
    ($bits:expr, $reverse:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct Hash([u8; $bits / 8]);

        impl Hash {
            const fn internal_new(arr: [u8; $bits / 8]) -> Self { Hash(arr) }

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

            /// Produces a hash from the current state of a given engine.
            pub fn from_engine(e: HashEngine) -> Hash { from_engine(e) }

            /// Copies a byte slice into a hash object.
            pub fn from_slice(
                sl: &[u8],
            ) -> $crate::_export::_core::result::Result<Hash, $crate::FromSliceError> {
                if sl.len() != $bits / 8 {
                    Err($crate::FromSliceError { expected: $bits / 8, got: sl.len() })
                } else {
                    let mut ret = [0; $bits / 8];
                    ret.copy_from_slice(sl);
                    Ok(Self::internal_new(ret))
                }
            }

            /// Returns the underlying byte array.
            pub const fn to_byte_array(self) -> [u8; $bits / 8] { self.0 }

            /// Returns a reference to the underlying byte array.
            pub const fn as_byte_array(&self) -> &[u8; $bits / 8] { &self.0 }

            /// Constructs a hash from the underlying byte array.
            pub const fn from_byte_array(bytes: [u8; $bits / 8]) -> Self {
                Self::internal_new(bytes)
            }
        }

        #[cfg(feature = "schemars")]
        impl schemars::JsonSchema for Hash {
            fn schema_name() -> alloc::string::String {
                use alloc::borrow::ToOwned;

                "Hash".to_owned()
            }

            fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
                use alloc::borrow::ToOwned;
                use alloc::boxed::Box;
                use alloc::string::String;

                let len = $bits / 8;
                let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
                schema.string = Some(Box::new(schemars::schema::StringValidation {
                    max_length: Some(len * 2),
                    min_length: Some(len * 2),
                    pattern: Some("[0-9a-fA-F]+".to_owned()),
                }));
                schema.into()
            }
        }

        crate::internal_macros::hash_trait_impls!($bits, $reverse);
    };
}
pub(crate) use hash_type_no_default;
