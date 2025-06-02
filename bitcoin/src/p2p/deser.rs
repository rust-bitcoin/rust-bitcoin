use crate::consensus::encode::WriteExt;
use crate::io::Write;

pub(crate) fn consensus_encode_with_size<W: Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    Ok(w.emit_compact_size(data.len())? + w.emit_slice(data)?)
}

pub(crate) fn parse_failed_error(msg: &'static str) -> crate::consensus::encode::Error {
    crate::consensus::encode::Error::Parse(crate::consensus::encode::ParseError::ParseFailed(msg))
}

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::consensus::Encodable for $thing {
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
                let mut r = r.take(internals::ToU64::to_u64($crate::consensus::encode::MAX_VEC_SIZE));
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;

macro_rules! impl_vec_wrapper {
    ($wrapper: ident, $type: ty) => {
        impl crate::consensus::encode::Encodable for $wrapper {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let mut len = 0;
                len += w.emit_compact_size(self.0.len())?;
                for c in self.0.iter() {
                    len += c.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl crate::consensus::encode::Decodable for $wrapper {
            #[inline]
            fn consensus_decode_from_finite_reader<R: io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$wrapper, crate::consensus::encode::Error> {
                let len = r.read_compact_size()?;
                // Do not allocate upfront more items than if the sequence of type
                // occupied roughly quarter a block. This should never be the case
                // for normal data, but even if that's not true - `push` will just
                // reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_capacity = crate::consensus::encode::MAX_VEC_SIZE / 4 / core::mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok($wrapper(ret))
            }
        }
    };
}

pub(crate) use impl_vec_wrapper;
