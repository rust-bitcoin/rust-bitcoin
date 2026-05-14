// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.
//!

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<R: $crate::io::Write + ?Sized>(
                &self,
                r: &mut R,
            ) -> core::result::Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(r)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus::encode::Error> {
                let mut r = r.take($crate::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;

macro_rules! impl_array_newtype {
    ($thing:ident, $len:literal) => {
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
                fn check_copy<T: Copy>() {}
                check_copy::<$thing>();

                self.0
            }

            /// Copies the underlying bytes into a new `Vec`.
            #[inline]
            pub fn to_vec(self) -> alloc::vec::Vec<u8> { self.0.to_vec() }

            /// Converts the object to a raw pointer.
            #[inline]
            pub fn as_ptr(&self) -> *const u8 {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            /// Converts the object to a mutable raw pointer.
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut u8 {
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

        impl core::convert::From<[u8; $len]> for $thing {
            fn from(data: [u8; $len]) -> Self { $thing(data) }
        }

        impl<'a> core::convert::From<&'a [u8; $len]> for $thing {
            fn from(data: &'a [u8; $len]) -> Self { $thing(*data) }
        }

        impl<'a> core::convert::TryFrom<&'a [u8]> for $thing {
            type Error = core::array::TryFromSliceError;

            fn try_from(data: &'a [u8]) -> core::result::Result<Self, Self::Error> {
                use core::convert::TryInto;

                Ok($thing(data.try_into()?))
            }
        }

        impl AsRef<[u8; $len]> for $thing {
            fn as_ref(&self) -> &[u8; $len] { &self.0 }
        }

        impl AsMut<[u8; $len]> for $thing {
            fn as_mut(&mut self) -> &mut [u8; $len] { &mut self.0 }
        }

        impl AsRef<[u8]> for $thing {
            fn as_ref(&self) -> &[u8] { &self.0 }
        }

        impl AsMut<[u8]> for $thing {
            fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
        }

        impl core::borrow::Borrow<[u8; $len]> for $thing {
            fn borrow(&self) -> &[u8; $len] { &self.0 }
        }

        impl core::borrow::BorrowMut<[u8; $len]> for $thing {
            fn borrow_mut(&mut self) -> &mut [u8; $len] { &mut self.0 }
        }

        impl core::borrow::Borrow<[u8]> for $thing {
            fn borrow(&self) -> &[u8] { &self.0 }
        }

        impl core::borrow::BorrowMut<[u8]> for $thing {
            fn borrow_mut(&mut self) -> &mut [u8] { &mut self.0 }
        }

        impl<I> core::ops::Index<I> for $thing
        where
            [u8]: core::ops::Index<I>,
        {
            type Output = <[u8] as core::ops::Index<I>>::Output;

            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }
    };
}
pub(crate) use impl_array_newtype;

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex
/// - core::fmt::UpperHex
/// - core::fmt::Display
/// - core::str::FromStr
macro_rules! impl_bytes_newtype {
    ($t:ident, $len:literal) => {
        impl $t {
            /// Returns a reference the underlying bytes.
            #[inline]
            pub fn as_bytes(&self) -> &[u8; $len] { &self.0 }

            /// Returns the underlying bytes.
            #[inline]
            pub fn to_bytes(self) -> [u8; $len] {
                // We rely on `Copy` being implemented for $t so conversion
                // methods use the correct Rust naming conventions.
                fn check_copy<T: Copy>() {}
                check_copy::<$t>();

                self.to_byte_array()
            }

            /// Creates `Self` from a hex string.
            pub fn from_hex(s: &str) -> Result<Self, hex::HexToArrayError> {
                Ok(Self::from_byte_array($crate::hex::FromHex::from_hex(s)?))
            }
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::hex::{display, Case};
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
            type Err = $crate::hex::HexToArrayError;
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
                    s.serialize_bytes(self.as_bytes())
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
pub(crate) use impl_bytes_newtype;

#[rustfmt::skip]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(&self, w: &mut W) -> core::result::Result<usize, $crate::io::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(r: &mut R) -> core::result::Result<Self, $crate::consensus::encode::Error> {
                use $crate::hashes::Hash;
                Ok(Self::from_byte_array(<<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}
pub(crate) use impl_hashencode;

#[rustfmt::skip]
macro_rules! impl_asref_push_bytes {
    ($($hashtype:ident),*) => {
        $(
            impl AsRef<$crate::blockdata::script::PushBytes> for $hashtype {
                fn as_ref(&self) -> &$crate::blockdata::script::PushBytes {
                    use $crate::hashes::Hash;
                    self.as_byte_array().into()
                }
            }

            impl From<$hashtype> for $crate::blockdata::script::PushBytesBuf {
                fn from(hash: $hashtype) -> Self {
                    use $crate::hashes::Hash;
                    hash.as_byte_array().into()
                }
            }
        )*
    };
}
pub(crate) use impl_asref_push_bytes;
