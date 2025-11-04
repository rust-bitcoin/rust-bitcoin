#[cfg(feature = "std")]
use bitcoin::consensus::encode::WriteExt;
#[cfg(feature = "std")]
use io::Write;

#[cfg(feature = "std")]
pub(crate) fn consensus_encode_with_size<W: Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    Ok(w.emit_compact_size(data.len())? + w.emit_slice(data)?)
}

pub(crate) fn parse_failed_error(msg: &'static str) -> bitcoin::consensus::encode::Error {
    bitcoin::consensus::encode::Error::Parse(bitcoin::consensus::encode::ParseError::ParseFailed(
        msg,
    ))
}

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl bitcoin::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<W: io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(w)?;)+
                Ok(len)
            }
        }

        impl bitcoin::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, bitcoin::consensus::encode::Error> {
                Ok($thing {
                    $($field: bitcoin::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, bitcoin::consensus::encode::Error> {
                let mut r = io::Read::take(r, internals::ToU64::to_u64(bitcoin::consensus::encode::MAX_VEC_SIZE));
                Ok($thing {
                    $($field: bitcoin::consensus::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;

#[cfg(feature = "std")]
macro_rules! impl_vec_wrapper {
    ($wrapper: ident, $type: ty) => {
        impl bitcoin::consensus::encode::Encodable for $wrapper {
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

        impl bitcoin::consensus::encode::Decodable for $wrapper {
            #[inline]
            fn consensus_decode_from_finite_reader<R: io::BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$wrapper, bitcoin::consensus::encode::Error> {
                let len = r.read_compact_size()?;
                // Limit the initial vec allocation to at most 8,000 bytes, which is
                // sufficient for most use cases. We don't allocate more space upfront
                // than this, since `len` is an untrusted allocation capacity. If the
                // vector does overflow the initial capacity `push` will just reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_init_capacity = 8000 / core::mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_init_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok($wrapper(ret))
            }
        }
    };
}

#[cfg(feature = "std")]
pub(crate) use impl_vec_wrapper;
