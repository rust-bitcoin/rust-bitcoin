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
            fn consensus_decode_from_finite_reader<R: $crate::io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::BufRead + ?Sized>(
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

                self.0
            }

            /// Creates `Self` from a hex string.
            pub fn from_hex(s: &str) -> Result<Self, hex::HexToArrayError> {
                Ok($t($crate::hex::FromHex::from_hex(s)?))
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
pub(crate) use impl_bytes_newtype;

/// Implements:
/// - `AsRef<PushBytes> for $hashtype`
/// - `From<$hashtype> for PushBytesBuf`
macro_rules! impl_hashtype_asref_push_bytes {
    ($hashtype:ident) => {
        impl AsRef<$crate::blockdata::script::PushBytes> for $hashtype {
            fn as_ref(&self) -> &$crate::blockdata::script::PushBytes {
                self.as_byte_array().into()
            }
        }

        impl From<$hashtype> for $crate::blockdata::script::PushBytesBuf {
            fn from(hash: $hashtype) -> Self { hash.as_byte_array().into() }
        }
    };
}
pub(crate) use impl_hashtype_asref_push_bytes;

/// Implements a new type that wraps a hash type, providing private functions for hashing.
///
/// Requires `hashes::{Hash, HashEngine}` to be in scope.
#[rustfmt::skip]
macro_rules! impl_hashtype_wrapper {
    ($hashtype:ident, $hash:path) => {
        #[allow(unused)] // Not all functions are used by every new hash type.
        impl $hashtype {
            /// Creates this wrapper type from the inner hash type.
            #[inline]
            pub fn from_raw_hash(inner: $hash) -> Self { Self(inner) }

            /// Returns the inner hash (sha256, sh256d etc.).
            #[inline]
            pub fn to_raw_hash(self) -> $hash { self.0 }

            /// Returns a reference to the inner hash (sha256, sh256d etc.).
            #[inline]
            pub fn as_raw_hash(&self) -> &$hash { &self.0 }

            /// Constructs a hash from the underlying byte array.
            #[inline]
            pub fn from_byte_array(bytes: <$hash as hashes::Hash>::Bytes) -> Self {
                Self(<$hash as hashes::Hash>::from_byte_array(bytes))
            }

            /// Returns the underlying byte array.
            #[inline]
            pub fn to_byte_array(self) -> <$hash as hashes::Hash>::Bytes { self.0.to_byte_array() }

            /// Returns a reference to the underlying byte array.
            #[inline]
            pub fn as_byte_array(&self) -> &<$hash as hashes::Hash>::Bytes { self.0.as_byte_array() }

            /// Returns an all zero hash.
            ///
            /// An all zeros hash is a made up construct because there is not a known input that can
            /// create it, however it is used in various places in Bitcoin e.g., the Bitcoin genesis
            /// block's previous blockhash and the coinbase transaction's outpoint txid.
            #[inline]
            pub fn all_zeros() -> Self { Self(<$hash as hashes::Hash>::all_zeros()) }

            /// Constructs a new engine.
            pub(crate) fn engine() -> <$hash as hashes::Hash>::Engine { <$hash as hashes::Hash>::Engine::default() }

            /// Produces a hash from the current state of a given engine.
            pub(crate) fn from_engine(e: <$hash as hashes::Hash>::Engine) -> Self { Self(<$hash as hashes::Hash>::from_engine(e)) }

            /// Copies a byte slice into a hash object.
            pub(crate) fn from_slice(sl: &[u8]) -> Result<Self, hashes::FromSliceError> {
                Ok(Self(<$hash as hashes::Hash>::from_slice(sl)?))
            }

            /// Hashes some bytes.
            pub(crate) fn hash(data: &[u8]) -> Self {
                let mut engine = Self::engine();
                engine.input(data);
                Self::from_engine(engine)
            }
        }

        hashes::serde_impl!($hashtype, <$hash as hashes::Hash>::LEN);
        hashes::borrow_slice_impl!($hashtype);

        impl core::fmt::Debug for $hashtype {
            #[inline]
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}", self)
            }
        }

        impl core::convert::AsRef<[u8; <$hash as hashes::Hash>::LEN]> for $hashtype {
            #[inline]
            fn as_ref(&self) -> &[u8; <$hash as hashes::Hash>::LEN] {
                AsRef::<[u8; <$hash as hashes::Hash>::LEN]>::as_ref(&self.0)
            }
        }

        impl<I: core::slice::SliceIndex<[u8]>> core::ops::Index<I> for $hashtype {
            type Output = I::Output;
            #[inline]
            fn index(&self, index: I) -> &Self::Output { &self.0[index] }
        }

        impl core::convert::From<$hash> for $hashtype {
            #[inline]
            fn from(inner: $hash) -> Self { Self(inner) }
        }

        impl core::convert::From<$hashtype> for $hash {
            #[inline]
            fn from(hashtype: $hashtype) -> Self { hashtype.0 }
        }
    }
}
pub(crate) use impl_hashtype_wrapper;

/// Adds hexadecimal formatting implementations to `$hashtype`.
#[rustfmt::skip]
macro_rules! impl_hashtype_hex_fmt {
    ($display_hash:path, $len:expr, $hashtype:ident, $inner:path) => {
        impl core::str::FromStr for $hashtype {
            type Err = hex::HexToArrayError;

            fn from_str(s: &str) -> core::result::Result<$hashtype, Self::Err> {
                use hex::FromHex;

                let mut bytes = <[u8; $len]>::from_hex(s)?;
                if matches!($display_hash, $crate::DisplayHash::Backwards) {
                    bytes.reverse();
                };

                Ok($hashtype(<$inner as hashes::Hash>::from_byte_array(bytes)))
            }
        }

        impl core::fmt::LowerHex for $hashtype {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let case = hex::Case::Lower;
                match $display_hash {
                    $crate::DisplayHash::Backwards => {
                        hex::fmt_hex_exact!(f, $len, self.as_byte_array().iter().rev(), case)
                    }
                    $crate::DisplayHash::Forwards => {
                        hex::fmt_hex_exact!(f, $len, self.as_byte_array().iter(), case)
                    }
                }
            }
        }

        impl core::fmt::UpperHex for $hashtype {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                let case = hex::Case::Upper;
                match $display_hash {
                    $crate::DisplayHash::Backwards => {
                        hex::fmt_hex_exact!(f, $len, self.as_byte_array().iter().rev(), case)
                    }
                    $crate::DisplayHash::Forwards => {
                        hex::fmt_hex_exact!(f, $len, self.as_byte_array().iter(), case)
                    }
                }
            }
        }

        impl core::fmt::Display for $hashtype {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                core::fmt::LowerHex::fmt(&self, f)
            }
        }
    };
}
pub(crate) use impl_hashtype_hex_fmt;

/// Implements `consenus::{Decodable, Encodable}` for `$hashtype`.
///
/// Requires the traits to be in scope.
#[rustfmt::skip]
macro_rules! impl_hashtype_encode {
    ($hashtype:ident, $inner:ty) => {
        impl $crate::consensus::Encodable for $hashtype {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(&self, w: &mut W) -> core::result::Result<usize, $crate::io::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $hashtype {
            fn consensus_decode<R: $crate::io::BufRead + ?Sized>(r: &mut R) -> core::result::Result<Self, $crate::consensus::encode::Error> {
                Ok(Self(<$inner>::consensus_decode(r)?))
            }
        }
    };
}
pub(crate) use impl_hashtype_encode;
