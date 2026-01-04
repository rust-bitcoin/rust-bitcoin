// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Connection Bloom filtering network messages.
//!
//! This module describes BIP-0037 Connection Bloom filtering network messages.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::{encode, Decodable, Encodable, ReadExt};
use encoding::{ByteVecDecoder, BytesEncoder, CompactSizeEncoder, Encoder2};
use internals::write_err;
use io::{BufRead, Write};

use crate::consensus::impl_consensus_encoding;

/// `filterload` message sets the current bloom filter
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterLoad {
    /// The filter itself
    pub filter: Vec<u8>,
    /// The number of hash functions to use
    pub hash_funcs: u32,
    /// A random value
    pub tweak: u32,
    /// Controls how matched items are added to the filter
    pub flags: BloomFlags,
}

impl_consensus_encoding!(FilterLoad, filter, hash_funcs, tweak, flags);

/// Bloom filter update flags
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BloomFlags {
    /// Never update the filter with outpoints.
    None,
    /// Always update the filter with outpoints.
    All,
    /// Only update the filter with outpoints if it is P2PK or P2MS
    PubkeyOnly,
}

impl Encodable for BloomFlags {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[match self {
            Self::None => 0,
            Self::All => 1,
            Self::PubkeyOnly => 2,
        }])?;
        Ok(1)
    }
}

impl Decodable for BloomFlags {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0 => Self::None,
            1 => Self::All,
            2 => Self::PubkeyOnly,
            _ => return Err(crate::consensus::parse_failed_error("unknown bloom flag")),
        })
    }
}

/// `filteradd` message updates the current filter with new data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterAdd {
    /// The data element to add to the current filter.
    pub data: Vec<u8>,
}

encoding::encoder_newtype! {
    /// The encoder of the [`FilterAdd`] message.
    pub struct FilterAddEncoder<'e>(Encoder2<CompactSizeEncoder, BytesEncoder<'e>>);
}

impl encoding::Encodable for FilterAdd {
    type Encoder<'e> = FilterAddEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterAddEncoder(
            Encoder2::new(
                CompactSizeEncoder::new(self.data.len()),
                BytesEncoder::without_length_prefix(&self.data)
            )
        )
    }
}

type FilterAddInnerDecoder = ByteVecDecoder;

/// The decoder for the [`FilterAdd`] message.
pub struct FilterAddDecoder(FilterAddInnerDecoder);

impl encoding::Decoder for FilterAddDecoder {
    type Output = FilterAdd;
    type Error = FilterAddDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterAddDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let data = self.0.end().map_err(FilterAddDecoderError)?;
        Ok(FilterAdd { data })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for FilterAdd {
    type Decoder = FilterAddDecoder;

    fn decoder() -> Self::Decoder {
        FilterAddDecoder(FilterAddInnerDecoder::new())
    }
}

/// An error decoding a [`FilterAdd`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterAddDecoderError(<FilterAddInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for FilterAddDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FilterAddDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filteradd error"; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FilterAddDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(FilterAdd, data);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BloomFlags {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::None),
            1 => Ok(Self::All),
            _ => Ok(Self::PubkeyOnly),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterAdd {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { data: Vec::<u8>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterLoad {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter: Vec::<u8>::arbitrary(u)?,
            hash_funcs: u.arbitrary()?,
            tweak: u.arbitrary()?,
            flags: u.arbitrary()?,
        })
    }
}
