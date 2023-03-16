// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
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
            ) -> Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(r)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                use crate::io::Read as _;
                let mut r = r.take($crate::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(r.by_ref())?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;

/// Marks the function const in Rust 1.46.0
macro_rules! maybe_const_fn {
    ($(#[$attr:meta])* $vis:vis fn $name:ident($($args:tt)*) -> $ret:ty $body:block) => {
        #[cfg(rust_v_1_46)]
        $(#[$attr])*
        $vis const fn $name($($args)*) -> $ret $body

        #[cfg(not(rust_v_1_46))]
        $(#[$attr])*
        $vis fn $name($($args)*) -> $ret $body
    }
}
pub(crate) use maybe_const_fn;
// We use test_macros module to keep things organised, re-export everything for ease of use.
#[cfg(test)]
pub(crate) use test_macros::*;

#[cfg(test)]
mod test_macros {

    macro_rules! hex (($hex:expr) => (<Vec<u8> as hashes::hex::FromHex>::from_hex($hex).unwrap()));
    pub(crate) use hex;
}

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex
/// - core::fmt::UpperHex
/// - core::fmt::Display
/// - core::str::FromStr
/// - hashes::hex::FromHex
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
        }

        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use bitcoin_internals::hex::{display, Case};
                display::fmt_hex_exact!(f, $len, &self.0, Case::Lower)
            }
        }

        impl core::fmt::UpperHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use bitcoin_internals::hex::{display, Case};
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

        impl $crate::hashes::hex::FromHex for $t {
            fn from_byte_iter<I>(iter: I) -> Result<Self, $crate::hashes::hex::Error>
            where
                I: core::iter::Iterator<Item = Result<u8, $crate::hashes::hex::Error>>
                    + core::iter::ExactSizeIterator
                    + core::iter::DoubleEndedIterator,
            {
                if iter.len() == $len {
                    let mut ret = [0; $len];
                    for (n, byte) in iter.enumerate() {
                        ret[n] = byte?;
                    }
                    Ok($t(ret))
                } else {
                    Err($crate::hashes::hex::Error::InvalidLength(2 * $len, 2 * iter.len()))
                }
            }
        }

        impl core::str::FromStr for $t {
            type Err = $crate::hashes::hex::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::hashes::hex::FromHex::from_hex(s)
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(&self[..])
                }
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
                if d.is_human_readable() {
                    struct HexVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for HexVisitor {
                        type Value = $t;

                        fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                            f.write_str("an ASCII hex string")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            use $crate::serde::de::Unexpected;

                            if let Ok(hex) = core::str::from_utf8(v) {
                                $crate::hashes::hex::FromHex::from_hex(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $crate::hashes::hex::FromHex::from_hex(v).map_err(E::custom)
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

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
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
