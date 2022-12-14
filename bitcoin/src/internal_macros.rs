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
// We use test_macros module to keep things organised, re-export everything for ease of use.
#[cfg(test)]
pub(crate) use test_macros::*;

#[cfg(test)]
mod test_macros {
    use crate::hex::FromHex;
    use crate::PublicKey;

    /// Trait used to create a value from hex string for testing purposes.
    pub(crate) trait TestFromHex {
        /// Produces the value from hex.
        ///
        /// ## Panics
        ///
        /// The function panics if the hex or the value is invalid.
        fn test_from_hex(hex: &str) -> Self;
    }

    impl<T: FromHex> TestFromHex for T {
        fn test_from_hex(hex: &str) -> Self { Self::from_hex(hex).unwrap() }
    }

    impl TestFromHex for PublicKey {
        fn test_from_hex(hex: &str) -> Self {
            PublicKey::from_slice(&Vec::from_hex(hex).unwrap()).unwrap()
        }
    }

    macro_rules! hex (($hex:literal) => (Vec::from_hex($hex).unwrap()));
    pub(crate) use hex;

    macro_rules! hex_into {
        ($hex:expr) => {
            $crate::internal_macros::hex_into!(_, $hex)
        };
        ($type:ty, $hex:expr) => {
            <$type as $crate::internal_macros::TestFromHex>::test_from_hex($hex)
        };
    }
    pub(crate) use hex_into;

    // Script is commonly used in places where inference may fail
    macro_rules! hex_script (($hex:expr) => ($crate::internal_macros::hex_into!($crate::Script, $hex)));
    pub(crate) use hex_script;

    // For types that can't use TestFromHex due to coherence rules or reversed hex
    macro_rules! hex_from_slice {
        ($hex:expr) => {
            $crate::internal_macros::hex_from_slice!(_, $hex)
        };
        ($type:ty, $hex:expr) => {
            <$type>::from_slice(
                &<$crate::prelude::Vec<u8> as $crate::hex::FromHex>::from_hex($hex)
                    .unwrap(),
            )
            .unwrap()
        };
    }
    pub(crate) use hex_from_slice;
}

/// Implements several traits for byte-based newtypes.
/// Implements:
/// - core::fmt::LowerHex (implies hex::ToHex)
/// - core::fmt::Display
/// - core::str::FromStr
/// - hex::FromHex
macro_rules! impl_bytes_newtype {
    ($t:ident, $len:literal) => {
        impl core::fmt::LowerHex for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                for &ch in self.0.iter() {
                    write!(f, "{:02x}", ch)?;
                }
                Ok(())
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

        impl $crate::hex::FromHex for $t {
            fn from_byte_iter<I>(iter: I) -> Result<Self, $crate::hex::Error>
            where
                I: core::iter::Iterator<Item = Result<u8, $crate::hex::Error>>
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
                    Err($crate::hex::Error::InvalidLength(2 * $len, 2 * iter.len()))
                }
            }
        }

        impl core::str::FromStr for $t {
            type Err = $crate::hex::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::hex::FromHex::from_hex(s)
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.serialize_str(&$crate::hex::ToHex::to_hex(self))
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
                                $crate::hex::FromHex::from_hex(hex).map_err(E::custom)
                            } else {
                                return Err(E::invalid_value(Unexpected::Bytes(v), &self));
                            }
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $crate::hex::FromHex::from_hex(v).map_err(E::custom)
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
