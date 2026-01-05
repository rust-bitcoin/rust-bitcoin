// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP-0157 Client Side Block Filtering network messages.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayDecoder, ArrayEncoder, ByteVecDecoder, BytesEncoder, CompactSizeEncoder, Decoder2, Decoder3, Encoder2, Encoder3};
use hashes::{sha256d, HashEngine};
use internals::write_err;
use primitives::{block::{BlockHashDecoder, BlockHashEncoder}, BlockHash};
use units::{block::{BlockHeightDecoder, BlockHeightEncoder}, BlockHeight};

use crate::consensus::impl_consensus_encoding;

hashes::hash_newtype! {
    /// Filter hash, as defined in BIP-0157.
    pub struct FilterHash(pub sha256d::Hash);
    /// Filter header, as defined in BIP-0157.
    pub struct FilterHeader(pub sha256d::Hash);
}

hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes the filter header from a filter hash and previous filter header.
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous_filter_header.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

#[rustfmt::skip]
macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl bitcoin::consensus::Encodable for $hashtype {
            fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, w: &mut W) -> core::result::Result<usize, bitcoin::io::Error> {
                self.as_byte_array().consensus_encode(w)
            }
        }

        impl bitcoin::consensus::Decodable for $hashtype {
            fn consensus_decode<R: bitcoin::io::BufRead + ?Sized>(r: &mut R) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
                Ok(Self::from_byte_array(<<$hashtype as hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}

impl_hashencode!(FilterHash);
impl_hashencode!(FilterHeader);

encoding::encoder_newtype! {
    /// Encoder type for [`FilterHash`].
    pub struct FilterHashEncoder(ArrayEncoder<32>);
}

impl encoding::Encodable for FilterHash {
    type Encoder<'e> = FilterHashEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHashEncoder(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

encoding::encoder_newtype! {
    /// Encoder type for [`FilterHeader`].
    pub struct FilterHeaderEncoder(ArrayEncoder<32>);
}

impl encoding::Encodable for FilterHeader {
    type Encoder<'e> = FilterHeaderEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHeaderEncoder(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

type HashInnerDecoder = ArrayDecoder<32>;

/// Decoder for the [`FilterHash`] type.
pub struct FilterHashDecoder(HashInnerDecoder);

impl encoding::Decoder for FilterHashDecoder {
    type Output = FilterHash;
    type Error = FilterHashDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHashDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let arr = self.0.end().map_err(FilterHashDecoderError)?;
        Ok(FilterHash::from_byte_array(arr))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for FilterHash {
    type Decoder = FilterHashDecoder;

    fn decoder() -> Self::Decoder {
        FilterHashDecoder(ArrayDecoder::new())
    }
}

/// Errors occuring when decoding a [`FilterHash`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHashDecoderError(<HashInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for FilterHashDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FilterHashDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filterhash error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FilterHashDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Decoder for the [`FilterHeader`] type.
pub struct FilterHeaderDecoder(HashInnerDecoder);

impl encoding::Decoder for FilterHeaderDecoder {
    type Output = FilterHeader;
    type Error = FilterHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(FilterHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let arr = self.0.end().map_err(FilterHeaderDecoderError)?;
        Ok(FilterHeader::from_byte_array(arr))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for FilterHeader {
    type Decoder = FilterHeaderDecoder;

    fn decoder() -> Self::Decoder {
        FilterHeaderDecoder(ArrayDecoder::new())
    }
}

/// Errors occuring when decoding a [`FilterHash`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterHeaderDecoderError(<HashInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for FilterHeaderDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for FilterHeaderDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filterheader error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FilterHeaderDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_byte_array(u.arbitrary()?))
    }
}

/// getcfilters message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFilters {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: BlockHeight,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

encoding::encoder_newtype! {
    /// Encoder type for the [`GetCFilters`] message.
    pub struct GetCFiltersEncoder(Encoder3<ArrayEncoder<1>, BlockHeightEncoder, BlockHashEncoder>);
}

impl encoding::Encodable for GetCFilters {
    type Encoder<'e> = GetCFiltersEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFiltersEncoder(
            Encoder3::new(
                ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
                self.start_height.encoder(),
                self.stop_hash.encoder()
            )
        )
    }
}

type GetCFiltersInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHeightDecoder, BlockHashDecoder>;

/// Decoder type for the [`GetCFilters`] message.
pub struct GetCFiltersDecoder(GetCFiltersInnerDecoder);

impl encoding::Decoder for GetCFiltersDecoder {
    type Output = GetCFilters;
    type Error = GetCFiltersDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(GetCFiltersDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (ty, start_height, stop_hash) = self.0.end().map_err(GetCFiltersDecoderError)?;
        Ok(GetCFilters {
            filter_type: u8::from_le_bytes(ty),
            start_height,
            stop_hash
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for GetCFilters {
    type Decoder = GetCFiltersDecoder;

    fn decoder() -> Self::Decoder {
        GetCFiltersDecoder(
            Decoder3::new(
                ArrayDecoder::new(),
                BlockHeightDecoder::new(),
                BlockHashDecoder::new()
            )
        )
    }
}

/// Errors occuring when decoding a [`GetCFilters`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFiltersDecoderError(<GetCFiltersInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for GetCFiltersDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetCFiltersDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfilters error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetCFiltersDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(GetCFilters, filter_type, start_height, stop_hash);

/// cfilter message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFilter {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// Block hash of the Bitcoin block for which the filter is being returned
    pub block_hash: BlockHash,
    /// The serialized compact filter for this block
    pub filter: Vec<u8>,
}

encoding::encoder_newtype! {
    /// Encoder type for a [`CFilter`] message.
    pub struct CFilterEncoder<'e>(
        Encoder3<
            ArrayEncoder<1>,
            BlockHashEncoder,
            Encoder2<CompactSizeEncoder, BytesEncoder<'e>>,
        >
    );
}

impl encoding::Encodable for CFilter {
    type Encoder<'e> = CFilterEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFilterEncoder(
            Encoder3::new(
                ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
                self.block_hash.encoder(),
                Encoder2::new(
                    CompactSizeEncoder::new(self.filter.len()),
                    BytesEncoder::without_length_prefix(&self.filter)
                )
            )
        )
    }
}

type CFilterInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHashDecoder, ByteVecDecoder>;

/// Decoder type for a [`CFilter`] message.
pub struct CFilterDecoder(CFilterInnerDecoder);

impl encoding::Decoder for CFilterDecoder {
    type Output = CFilter;
    type Error = CFilterDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(CFilterDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (ty, block_hash, filter) = self.0.end().map_err(CFilterDecoderError)?;
        Ok(CFilter {
            filter_type: u8::from_le_bytes(ty),
            block_hash,
            filter,
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for CFilter {
    type Decoder = CFilterDecoder;

    fn decoder() -> Self::Decoder {
        CFilterDecoder(
            Decoder3::new(ArrayDecoder::new(), BlockHashDecoder::new(), ByteVecDecoder::new())
        )
    }
}

/// Errors occuring when decoding a [`CFilter`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFilterDecoderError(<CFilterInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for CFilterDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for CFilterDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "cfilter error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CFilterDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(CFilter, filter_type, block_hash, filter);

/// getcfheaders message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFHeaders {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: BlockHeight,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

encoding::encoder_newtype! {
    /// Encoder type for the [`GetCFHeaders`] message.
    pub struct GetCFHeadersEncoder(Encoder3<ArrayEncoder<1>, BlockHeightEncoder, BlockHashEncoder>);
}

impl encoding::Encodable for GetCFHeaders {
    type Encoder<'e> = GetCFHeadersEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFHeadersEncoder(
            Encoder3::new(
                ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
                self.start_height.encoder(),
                self.stop_hash.encoder()
            )
        )
    }
}

type GetCFHeadersInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHeightDecoder, BlockHashDecoder>;

/// Decoder type for the [`GetCFHeaders`] message.
pub struct GetCFHeadersDecoder(GetCFHeadersInnerDecoder);

impl encoding::Decoder for GetCFHeadersDecoder {
    type Output = GetCFHeaders;
    type Error = GetCFHeadersDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(GetCFHeadersDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (ty, start_height, stop_hash) = self.0.end().map_err(GetCFHeadersDecoderError)?;
        Ok(GetCFHeaders {
            filter_type: u8::from_le_bytes(ty),
            start_height,
            stop_hash
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for GetCFHeaders {
    type Decoder = GetCFHeadersDecoder;

    fn decoder() -> Self::Decoder {
        GetCFHeadersDecoder(
            Decoder3::new(
                ArrayDecoder::new(),
                BlockHeightDecoder::new(),
                BlockHashDecoder::new()
            )
        )
    }
}

/// Errors occuring when decoding a [`GetCFHeaders`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFHeadersDecoderError(<GetCFHeadersInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for GetCFHeadersDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetCFHeadersDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfheaders error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetCFHeadersDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(GetCFHeaders, filter_type, start_height, stop_hash);

/// cfheaders message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFHeaders {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
    /// The filter header preceding the first block in the requested range
    pub previous_filter_header: FilterHeader,
    /// The filter hashes for each block in the requested range
    pub filter_hashes: Vec<FilterHash>,
}
impl_consensus_encoding!(CFHeaders, filter_type, stop_hash, previous_filter_header, filter_hashes);

/// getcfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

encoding::encoder_newtype! {
    /// Encoder type for the [`GetCFCheckpt`] message.
    pub struct GetCFCheckptEncoder(Encoder2<ArrayEncoder<1>, BlockHashEncoder>);
}

impl encoding::Encodable for GetCFCheckpt {
    type Encoder<'e> = GetCFCheckptEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFCheckptEncoder(
            Encoder2::new(
                ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
                self.stop_hash.encoder()
            )
        )
    }
}

type GetCFCheckptInnerDecoder = Decoder2<ArrayDecoder<1>, BlockHashDecoder>;

/// Decoder type for a [`GetCFCheckpt`] message.
pub struct GetCFCheckptDecoder(GetCFCheckptInnerDecoder);

impl encoding::Decoder for GetCFCheckptDecoder {
    type Output = GetCFCheckpt;
    type Error = GetCFCheckptDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(GetCFCheckptDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (ty, stop_hash) = self.0.end().map_err(GetCFCheckptDecoderError)?;
        Ok(GetCFCheckpt {
            filter_type: u8::from_le_bytes(ty),
            stop_hash
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for GetCFCheckpt {
    type Decoder = GetCFCheckptDecoder;

    fn decoder() -> Self::Decoder {
        GetCFCheckptDecoder(
            Decoder2::new(ArrayDecoder::new(), BlockHashDecoder::new())
        )
    }
}

/// Errors occuring when decoding a [`GetCFCheckpt`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFCheckptDecoderError(<GetCFCheckptInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for GetCFCheckptDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetCFCheckptDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfcheckpt error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetCFCheckptDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(GetCFCheckpt, filter_type, stop_hash);

/// cfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
    /// The filter headers at intervals of 1,000
    pub filter_headers: Vec<FilterHeader>,
}
impl_consensus_encoding!(CFCheckpt, filter_type, stop_hash, filter_headers);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFilters {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            start_height: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFilter {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            block_hash: u.arbitrary()?,
            filter: Vec::<u8>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFHeaders {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            start_height: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFHeaders {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
            previous_filter_header: u.arbitrary()?,
            filter_hashes: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetCFCheckpt {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { filter_type: u.arbitrary()?, stop_hash: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CFCheckpt {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            filter_type: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
            filter_headers: Vec::<FilterHeader>::arbitrary(u)?,
        })
    }
}
