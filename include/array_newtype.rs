// SPDX-License-Identifier: CC0-1.0

/// Implements several string-ish traits for byte-based newtypes.
///
/// - `fmt::Display` and `str::FromStr` (using lowercase hex)
/// - `fmt::LowerHex` and `UpperHex`
/// - `fmt::Debug` (using `LowerHex`)
/// - `serde::Serialize` and `Deserialize` (using lowercase hex)
///
/// As well as an inherent `from_hex` method.
#[allow(unused_macros)]
macro_rules! impl_array_newtype_stringify {
    ($t:ident, $len:literal) => {
        impl $t {
            /// Constructs a new `Self` from a hex string.
            ///
            /// # Errors
            ///
            /// Returns an error if `s` contains invalid characters or has incorrect length. (Should be
            /// `N * 2`.)
            pub fn from_hex(s: &str) -> Result<Self, $crate::hex::DecodeFixedLengthBytesError> {
                Ok($t($crate::hex::decode_to_array(s)?))
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Upper)
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(self, f)
            }
        }

        impl core::str::FromStr for $t {
            type Err = $crate::hex::DecodeFixedLengthBytesError;
            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> { Self::from_hex(s) }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(
                &self,
                s: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(
                d: D,
            ) -> core::result::Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            use $crate::serde::de::Unexpected;

                            if let Ok(hex) = core::str::from_utf8(v) {
                                core::str::FromStr::from_str(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, hex: &str) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            core::str::FromStr::from_str(hex).map_err(E::custom)
                        }
                    }

                    d.deserialize_str(HexVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("a bytestring")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            if v.len() != $len {
                                Err(E::invalid_length(v.len(), &stringify!($len)))
                            } else {
                                let mut ret = [0; $len];
                                ret.copy_from_slice(v);
                                Ok($t(ret))
                            }
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use impl_array_newtype_stringify;

/// Implements standard array methods for a given wrapper type.
#[allow(unused_macros)]
macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:literal) => {
        impl $thing {
            /// Constructs a new `Self` by wrapping `bytes`.
            #[inline]
            pub fn from_byte_array(bytes: [u8; $len]) -> Self { Self(bytes) }

            /// Returns a reference the underlying byte array.
            #[inline]
            pub fn as_byte_array(&self) -> &[u8; $len] { &self.0 }

            /// Returns the underlying byte array.
            #[inline]
            pub fn to_byte_array(self) -> [u8; $len] {
                // We rely on `Copy` being implemented for $thing so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$thing>();

                self.0
            }

            /// Copies the underlying bytes into a new `Vec`.
            #[inline]
            pub fn to_vec(self) -> alloc::vec::Vec<u8> { self.0.to_vec() }

            /// Returns a slice of the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8] { &self.0 }

            /// Converts the object to a raw pointer.
            #[inline]
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            /// Converts the object to a mutable raw pointer.
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            /// Returns the length of the object as an array.
            #[inline]
            pub fn len(&self) -> usize { $len }

            /// Returns whether the object, as an array, is empty. Always false.
            #[inline]
            pub fn is_empty(&self) -> bool { false }
        }

        impl<'a> core::convert::From<[$ty; $len]> for $thing {
            fn from(data: [$ty; $len]) -> Self { $thing(data) }
        }

        impl<'a> core::convert::From<&'a [$ty; $len]> for $thing {
            fn from(data: &'a [$ty; $len]) -> Self { $thing(*data) }
        }

        impl<'a> core::convert::TryFrom<&'a [$ty]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [$ty]) -> core::result::Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[$ty; $len]> for $thing {
            fn as_ref(&self) -> &[$ty; $len] { &self.0 }
        }

        impl AsMut<[$ty; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        impl AsRef<[$ty]> for $thing {
            fn as_ref(&self) -> &[$ty] { &self.0 }
        }

        impl AsMut<[$ty]> for $thing {
            fn as_mut(&mut self) -> &mut [$ty] { &mut self.0 }
        }

        impl core::borrow::Borrow<[$ty; $len]> for $thing {
            fn borrow(&self) -> &[$ty; $len] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty; $len]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty; $len] { &mut self.0 }
        }

        // The following two are valid because `[T; N]: Borrow<[T]>`
        impl core::borrow::Borrow<[$ty]> for $thing {
            fn borrow(&self) -> &[$ty] { &self.0 }
        }

        impl core::borrow::BorrowMut<[$ty]> for $thing {
            fn borrow_mut(&mut self) -> &mut [$ty] { &mut self.0 }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [$ty]: core::ops::Index<I>,
        {
            type Output = <[$ty] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use impl_array_newtype;
