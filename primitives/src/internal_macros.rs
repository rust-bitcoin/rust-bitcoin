// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.

#[cfg(feature = "consensus-encoding-unbuffered-io")]
macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::consensus_encoding_unbuffered_io::Encodable for $thing {
            #[inline]
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(w)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus_encoding_unbuffered_io::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus_encoding_unbuffered_io::Error> {
                Ok($thing {
                    $($field: $crate::consensus_encoding_unbuffered_io::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, $crate::consensus_encoding_unbuffered_io::Error> {
                let mut r = r.take(internals::ToU64::to_u64($crate::consensus_encoding_unbuffered_io::MAX_VEC_SIZE));
                Ok($thing {
                    $($field: $crate::consensus_encoding_unbuffered_io::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
#[cfg(feature = "consensus-encoding-unbuffered-io")]
pub(crate) use impl_consensus_encoding;

#[rustfmt::skip]
#[cfg(feature = "consensus-encoding-unbuffered-io")]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::consensus_encoding_unbuffered_io::Encodable for $hashtype {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(&self, w: &mut W) -> core::result::Result<usize, $crate::io::Error> {
                self.as_byte_array().consensus_encode(w)
            }
        }

        impl $crate::consensus_encoding_unbuffered_io::Decodable for $hashtype {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(r: &mut R) -> core::result::Result<Self, $crate::consensus_encoding_unbuffered_io::Error> {
                Ok(Self::from_byte_array(<<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}
#[cfg(feature = "consensus-encoding-unbuffered-io")]
pub(crate) use impl_hashencode;
