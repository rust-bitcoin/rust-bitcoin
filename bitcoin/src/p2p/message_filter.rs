// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP157 Client Side Block Filtering network messages.
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;
#[cfg(feature = "encoding")]
use core::fmt;

use crate::bip158::{FilterHash, FilterHeader};
#[cfg(feature = "encoding")]
use crate::bip158::{FilterHeaderDecoder, FilterHeaderEncoder};
use crate::blockdata::block::BlockHash;
use crate::internal_macros::impl_consensus_encoding;
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;

/// getcfilters message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFilters {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: u32,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFilters, filter_type, start_height, stop_hash);

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFilters`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFiltersEncoder<'e>(
        encoding::Encoder3<encoding::ArrayEncoder<1>, encoding::ArrayEncoder<4>, crate::blockdata::block::BlockHashEncoder<'e>>
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for GetCFilters {
    type Encoder<'e> = GetCFiltersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFiltersEncoder::new(encoding::Encoder3::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            encoding::ArrayEncoder::without_length_prefix(self.start_height.to_le_bytes()),
            self.stop_hash.encoder(),
        ))
    }
}

#[cfg(feature = "encoding")]
type GetCFiltersInnerDecoder = encoding::Decoder3<
    encoding::ArrayDecoder<1>,
    encoding::ArrayDecoder<4>,
    crate::blockdata::block::BlockHashDecoder,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for the [`GetCFilters`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFiltersDecoder(GetCFiltersInnerDecoder);

    fn end(
        result: Result<<GetCFiltersInnerDecoder as encoding::Decoder>::Output, <GetCFiltersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFilters, GetCFiltersDecoderError> {
        let (ty, start_height, stop_hash) = result.map_err(GetCFiltersDecoderError)?;
        Ok(GetCFilters {
            filter_type: u8::from_le_bytes(ty),
            start_height: u32::from_le_bytes(start_height),
            stop_hash,
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for GetCFilters {
    type Decoder = GetCFiltersDecoder;
}

/// Errors occurring when decoding a [`GetCFilters`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFiltersDecoderError(
    pub(crate) <GetCFiltersInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for GetCFiltersDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for GetCFiltersDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfilters error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for GetCFiltersDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

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
impl_consensus_encoding!(CFilter, filter_type, block_hash, filter);

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// Encoder type for a [`CFilter`] message.
    #[derive(Debug, Clone)]
    pub struct CFilterEncoder<'e>(
        encoding::Encoder3<
            encoding::ArrayEncoder<1>,
            crate::blockdata::block::BlockHashEncoder<'e>,
            encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for CFilter {
    type Encoder<'e> = CFilterEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFilterEncoder::new(encoding::Encoder3::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.block_hash.encoder(),
            encoding::Encoder2::new(
                encoding::CompactSizeEncoder::new(self.filter.len()),
                encoding::BytesEncoder::without_length_prefix(&self.filter),
            ),
        ))
    }
}

#[cfg(feature = "encoding")]
type CFilterInnerDecoder = encoding::Decoder3<
    encoding::ArrayDecoder<1>,
    crate::blockdata::block::BlockHashDecoder,
    encoding::ByteVecDecoder,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`CFilter`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFilterDecoder(CFilterInnerDecoder);

    fn end(
        result: Result<<CFilterInnerDecoder as encoding::Decoder>::Output, <CFilterInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<CFilter, CFilterDecoderError> {
        let (ty, block_hash, filter) = result.map_err(CFilterDecoderError)?;
        Ok(CFilter { filter_type: u8::from_le_bytes(ty), block_hash, filter })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for CFilter {
    type Decoder = CFilterDecoder;
}

/// Errors occurring when decoding a [`CFilter`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFilterDecoderError(pub(crate) <CFilterInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for CFilterDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for CFilterDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "cfilter error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for CFilterDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// getcfheaders message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFHeaders {
    /// Byte identifying the type of filter being returned
    pub filter_type: u8,
    /// The height of the first block in the requested range
    pub start_height: u32,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFHeaders, filter_type, start_height, stop_hash);

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFHeaders`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFHeadersEncoder<'e>(
        encoding::Encoder3<encoding::ArrayEncoder<1>, encoding::ArrayEncoder<4>, crate::blockdata::block::BlockHashEncoder<'e>>
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for GetCFHeaders {
    type Encoder<'e> = GetCFHeadersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFHeadersEncoder::new(encoding::Encoder3::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            encoding::ArrayEncoder::without_length_prefix(self.start_height.to_le_bytes()),
            self.stop_hash.encoder(),
        ))
    }
}

#[cfg(feature = "encoding")]
type GetCFHeadersInnerDecoder = encoding::Decoder3<
    encoding::ArrayDecoder<1>,
    encoding::ArrayDecoder<4>,
    crate::blockdata::block::BlockHashDecoder,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for the [`GetCFHeaders`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFHeadersDecoder(GetCFHeadersInnerDecoder);

    fn end(
        result: Result<<GetCFHeadersInnerDecoder as encoding::Decoder>::Output, <GetCFHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFHeaders, GetCFHeadersDecoderError> {
        let (ty, start_height, stop_hash) = result.map_err(GetCFHeadersDecoderError)?;
        Ok(GetCFHeaders {
            filter_type: u8::from_le_bytes(ty),
            start_height: u32::from_le_bytes(start_height),
            stop_hash,
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for GetCFHeaders {
    type Decoder = GetCFHeadersDecoder;
}

/// Errors occurring when decoding a [`GetCFHeaders`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFHeadersDecoderError(
    pub(crate) <GetCFHeadersInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for GetCFHeadersDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for GetCFHeadersDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfheaders error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for GetCFHeadersDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

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

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// Encoder type for a [`CFHeaders`] message.
    #[derive(Debug, Clone)]
    pub struct CFHeadersEncoder<'e>(
        encoding::Encoder4<
            encoding::ArrayEncoder<1>,
            crate::blockdata::block::BlockHashEncoder<'e>,
            FilterHeaderEncoder<'e>,
            encoding::Encoder2<encoding::CompactSizeEncoder, encoding::SliceEncoder<'e, FilterHash>>,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for CFHeaders {
    type Encoder<'e> = CFHeadersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFHeadersEncoder::new(encoding::Encoder4::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
            self.previous_filter_header.encoder(),
            encoding::Encoder2::new(
                encoding::CompactSizeEncoder::new(self.filter_hashes.len()),
                encoding::SliceEncoder::without_length_prefix(&self.filter_hashes),
            ),
        ))
    }
}

#[cfg(feature = "encoding")]
type CFHeadersInnerDecoder = encoding::Decoder4<
    encoding::ArrayDecoder<1>,
    crate::blockdata::block::BlockHashDecoder,
    FilterHeaderDecoder,
    encoding::VecDecoder<FilterHash>,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`CFHeaders`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFHeadersDecoder(CFHeadersInnerDecoder);

    fn end(
        result: Result<<CFHeadersInnerDecoder as encoding::Decoder>::Output, <CFHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<CFHeaders, CFHeadersDecoderError> {
        let (ty, stop_hash, previous_filter_header, filter_hashes) = result.map_err(CFHeadersDecoderError)?;
        Ok(CFHeaders {
            filter_type: u8::from_le_bytes(ty),
            stop_hash,
            previous_filter_header,
            filter_hashes,
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for CFHeaders {
    type Decoder = CFHeadersDecoder;
}

/// Errors occurring when decoding a [`CFHeaders`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFHeadersDecoderError(pub(crate) <CFHeadersInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for CFHeadersDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for CFHeadersDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "cfheaders error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for CFHeadersDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// getcfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}
impl_consensus_encoding!(GetCFCheckpt, filter_type, stop_hash);

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFCheckpt`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFCheckptEncoder<'e>(
        encoding::Encoder2<encoding::ArrayEncoder<1>, crate::blockdata::block::BlockHashEncoder<'e>>
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for GetCFCheckpt {
    type Encoder<'e> = GetCFCheckptEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFCheckptEncoder::new(encoding::Encoder2::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
        ))
    }
}

#[cfg(feature = "encoding")]
type GetCFCheckptInnerDecoder =
    encoding::Decoder2<encoding::ArrayDecoder<1>, crate::blockdata::block::BlockHashDecoder>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`GetCFCheckpt`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFCheckptDecoder(GetCFCheckptInnerDecoder);

    fn end(
        result: Result<<GetCFCheckptInnerDecoder as encoding::Decoder>::Output, <GetCFCheckptInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFCheckpt, GetCFCheckptDecoderError> {
        let (ty, stop_hash) = result.map_err(GetCFCheckptDecoderError)?;
        Ok(GetCFCheckpt { filter_type: u8::from_le_bytes(ty), stop_hash })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for GetCFCheckpt {
    type Decoder = GetCFCheckptDecoder;
}

/// Errors occurring when decoding a [`GetCFCheckpt`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCFCheckptDecoderError(
    pub(crate) <GetCFCheckptInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for GetCFCheckptDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for GetCFCheckptDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "getcfcheckpt error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for GetCFCheckptDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

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

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// Encoder type for a [`CFCheckpt`] message.
    #[derive(Debug, Clone)]
    pub struct CFCheckptEncoder<'e>(
        encoding::Encoder3<
            encoding::ArrayEncoder<1>,
            crate::blockdata::block::BlockHashEncoder<'e>,
            encoding::Encoder2<encoding::CompactSizeEncoder, encoding::SliceEncoder<'e, FilterHeader>>,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for CFCheckpt {
    type Encoder<'e> = CFCheckptEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFCheckptEncoder::new(encoding::Encoder3::new(
            encoding::ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
            encoding::Encoder2::new(
                encoding::CompactSizeEncoder::new(self.filter_headers.len()),
                encoding::SliceEncoder::without_length_prefix(&self.filter_headers),
            ),
        ))
    }
}

#[cfg(feature = "encoding")]
type CFCheckptInnerDecoder = encoding::Decoder3<
    encoding::ArrayDecoder<1>,
    crate::blockdata::block::BlockHashDecoder,
    encoding::VecDecoder<FilterHeader>,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for a [`CFCheckpt`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFCheckptDecoder(CFCheckptInnerDecoder);

    fn end(
        result: Result<<CFCheckptInnerDecoder as encoding::Decoder>::Output, <CFCheckptInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<CFCheckpt, CFCheckptDecoderError> {
        let (ty, stop_hash, filter_headers) = result.map_err(CFCheckptDecoderError)?;
        Ok(CFCheckpt { filter_type: u8::from_le_bytes(ty), stop_hash, filter_headers })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for CFCheckpt {
    type Decoder = CFCheckptDecoder;
}

/// Errors occurring when decoding a [`CFCheckpt`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFCheckptDecoderError(pub(crate) <CFCheckptInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for CFCheckptDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for CFCheckptDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "cfcheckpt error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for CFCheckptDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}
