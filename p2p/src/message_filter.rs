// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Client Side Block Filtering network messages.
//!
//! This module describes BIP-0157 Client Side Block Filtering network messages.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, Decoder2, Decoder3, Decoder4, Encoder2, Encoder3,
    Encoder4, PrefixedBytesEncoder, PrefixedSliceEncoder, VecDecoder,
};
use hashes::{sha256d, HashEngine};
use primitives::block::{BlockHashDecoder, BlockHashEncoder};
use primitives::BlockHash;
use units::block::{BlockHeightDecoder, BlockHeightEncoder};
use units::BlockHeight;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    CFCheckptDecoderError, CFHeadersDecoderError, CFilterDecoderError, FilterHashDecoderError,
    FilterHeaderDecoderError, GetCFCheckptDecoderError, GetCFHeadersDecoderError,
    GetCFiltersDecoderError,
};

hashes::hash_newtype! {
    /// Filter hash, as defined in BIP-0157.
    pub struct FilterHash(pub sha256d::Hash);
    /// Filter header, as defined in BIP-0157.
    pub struct FilterHeader(pub sha256d::Hash);
}

hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(FilterHash, FilterHeader);

impl FilterHash {
    /// Computes the filter header from a filter hash and previous filter header.
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous_filter_header.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FilterHash`].
    #[derive(Debug, Clone)]
    pub struct FilterHashEncoder<'e>(ArrayEncoder<32>);
}

impl encoding::Encode for FilterHash {
    type Encoder<'e> = FilterHashEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHashEncoder::new(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder type for [`FilterHeader`].
    #[derive(Debug, Clone)]
    pub struct FilterHeaderEncoder<'e>(ArrayEncoder<32>);
}

impl encoding::Encode for FilterHeader {
    type Encoder<'e> = FilterHeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterHeaderEncoder::new(ArrayEncoder::without_length_prefix(self.to_byte_array()))
    }
}

type HashInnerDecoder = ArrayDecoder<32>;

crate::decoder_newtype! {
    /// Decoder for the [`FilterHash`] type.
    #[derive(Debug, Default, Clone)]
    pub struct FilterHashDecoder(HashInnerDecoder);

    fn end(
        result: Result<[u8; 32], encoding::UnexpectedEofError>
    ) -> Result<FilterHash, FilterHashDecoderError> {
        let arr = result.map_err(FilterHashDecoderError)?;
        Ok(FilterHash::from_byte_array(arr))
    }
}

impl encoding::Decode for FilterHash {
    type Decoder = FilterHashDecoder;
}

crate::decoder_newtype! {
    /// Decoder for the [`FilterHeader`] type.
    #[derive(Debug, Default, Clone)]
    pub struct FilterHeaderDecoder(HashInnerDecoder);

    fn end(
        result: Result<[u8; 32], encoding::UnexpectedEofError>
    ) -> Result<FilterHeader, FilterHeaderDecoderError> {
        let arr = result.map_err(FilterHeaderDecoderError)?;
        Ok(FilterHeader::from_byte_array(arr))
    }
}

impl encoding::Decode for FilterHeader {
    type Decoder = FilterHeaderDecoder;
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

encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFilters`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFiltersEncoder<'e>(Encoder3<ArrayEncoder<1>, BlockHeightEncoder<'e>, BlockHashEncoder<'e>>);
}

impl encoding::Encode for GetCFilters {
    type Encoder<'e> = GetCFiltersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFiltersEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.start_height.encoder(),
            self.stop_hash.encoder(),
        ))
    }
}

type GetCFiltersInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHeightDecoder, BlockHashDecoder>;

crate::decoder_newtype! {
    /// Decoder type for the [`GetCFilters`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFiltersDecoder(GetCFiltersInnerDecoder);

    fn end(
        result: Result<([u8; 1], BlockHeight, BlockHash), <GetCFiltersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFilters, GetCFiltersDecoderError> {
        let (ty, start_height, stop_hash) = result.map_err(GetCFiltersDecoderError)?;
        Ok(GetCFilters { filter_type: u8::from_le_bytes(ty), start_height, stop_hash })
    }
}

impl encoding::Decode for GetCFilters {
    type Decoder = GetCFiltersDecoder;
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

encoding::encoder_newtype_exact! {
    /// Encoder type for a [`CFilter`] message.
    #[derive(Debug, Clone)]
    pub struct CFilterEncoder<'e>(
        Encoder3<
            ArrayEncoder<1>,
            BlockHashEncoder<'e>,
            PrefixedBytesEncoder<'e>,
        >
    );
}

impl encoding::Encode for CFilter {
    type Encoder<'e>
        = CFilterEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFilterEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.block_hash.encoder(),
            PrefixedBytesEncoder::new(&self.filter),
        ))
    }
}

type CFilterInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHashDecoder, ByteVecDecoder>;

crate::decoder_newtype! {
    /// Decoder type for a [`CFilter`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFilterDecoder(CFilterInnerDecoder);

    fn end(
        result: Result<([u8; 1], BlockHash, Vec<u8>), <CFilterInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<CFilter, CFilterDecoderError> {
        let (ty, block_hash, filter) = result.map_err(CFilterDecoderError)?;
        Ok(CFilter { filter_type: u8::from_le_bytes(ty), block_hash, filter })
    }
}

impl encoding::Decode for CFilter {
    type Decoder = CFilterDecoder;
}

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

encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFHeaders`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFHeadersEncoder<'e>(Encoder3<ArrayEncoder<1>, BlockHeightEncoder<'e>, BlockHashEncoder<'e>>);
}

impl encoding::Encode for GetCFHeaders {
    type Encoder<'e> = GetCFHeadersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFHeadersEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.start_height.encoder(),
            self.stop_hash.encoder(),
        ))
    }
}

type GetCFHeadersInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHeightDecoder, BlockHashDecoder>;

crate::decoder_newtype! {
    /// Decoder type for the [`GetCFHeaders`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFHeadersDecoder(GetCFHeadersInnerDecoder);

    fn end(
        result: Result<([u8; 1], BlockHeight, BlockHash), <GetCFHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFHeaders, GetCFHeadersDecoderError> {
        let (ty, start_height, stop_hash) = result.map_err(GetCFHeadersDecoderError)?;
        Ok(GetCFHeaders { filter_type: u8::from_le_bytes(ty), start_height, stop_hash })
    }
}

impl encoding::Decode for GetCFHeaders {
    type Decoder = GetCFHeadersDecoder;
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

encoding::encoder_newtype! {
    /// Encoder type for a [`CFHeaders`] message.
    #[derive(Debug, Clone)]
    pub struct CFHeadersEncoder<'e>(
        Encoder4<
            ArrayEncoder<1>,
            BlockHashEncoder<'e>,
            FilterHeaderEncoder<'e>,
            PrefixedSliceEncoder<'e, FilterHash>
        >
    );
}

impl encoding::Encode for CFHeaders {
    type Encoder<'e> = CFHeadersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFHeadersEncoder::new(Encoder4::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
            self.previous_filter_header.encoder(),
            PrefixedSliceEncoder::new(&self.filter_hashes),
        ))
    }
}

type CFHeadersInnerDecoder =
    Decoder4<ArrayDecoder<1>, BlockHashDecoder, FilterHeaderDecoder, VecDecoder<FilterHash>>;

crate::decoder_newtype! {
    /// Decoder type for a [`CFHeaders`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFHeadersDecoder(CFHeadersInnerDecoder);

    fn end(
        result: Result<
            <CFHeadersInnerDecoder as encoding::Decoder>::Output,
            <CFHeadersInnerDecoder as encoding::Decoder>::Error,
        >
    ) -> Result<CFHeaders, CFHeadersDecoderError> {
        let (ty, stop_hash, previous_filter_header, filter_hashes) =
            result.map_err(CFHeadersDecoderError)?;
        Ok(CFHeaders {
            filter_type: u8::from_le_bytes(ty),
            stop_hash,
            previous_filter_header,
            filter_hashes,
        })
    }
}

impl encoding::Decode for CFHeaders {
    type Decoder = CFHeadersDecoder;
}

/// getcfcheckpt message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetCFCheckpt {
    /// Filter type for which headers are requested
    pub filter_type: u8,
    /// The hash of the last block in the requested range
    pub stop_hash: BlockHash,
}

encoding::encoder_newtype_exact! {
    /// Encoder type for the [`GetCFCheckpt`] message.
    #[derive(Debug, Clone)]
    pub struct GetCFCheckptEncoder<'e>(Encoder2<ArrayEncoder<1>, BlockHashEncoder<'e>>);
}

impl encoding::Encode for GetCFCheckpt {
    type Encoder<'e> = GetCFCheckptEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetCFCheckptEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
        ))
    }
}

type GetCFCheckptInnerDecoder = Decoder2<ArrayDecoder<1>, BlockHashDecoder>;

crate::decoder_newtype! {
    /// Decoder type for a [`GetCFCheckpt`] message.
    #[derive(Debug, Default, Clone)]
    pub struct GetCFCheckptDecoder(GetCFCheckptInnerDecoder);

    fn end(
        result: Result<([u8; 1], BlockHash), <GetCFCheckptInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetCFCheckpt, GetCFCheckptDecoderError> {
        let (ty, stop_hash) = result.map_err(GetCFCheckptDecoderError)?;
        Ok(GetCFCheckpt { filter_type: u8::from_le_bytes(ty), stop_hash })
    }
}

impl encoding::Decode for GetCFCheckpt {
    type Decoder = GetCFCheckptDecoder;
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

encoding::encoder_newtype! {
    /// Encoder type for a [`CFCheckpt`] message.
    #[derive(Debug, Clone)]
    pub struct CFCheckptEncoder<'e>(
        Encoder3<
            ArrayEncoder<1>,
            BlockHashEncoder<'e>,
            PrefixedSliceEncoder<'e, FilterHeader>
        >
    );
}

impl encoding::Encode for CFCheckpt {
    type Encoder<'e>
        = CFCheckptEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        CFCheckptEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.filter_type.to_le_bytes()),
            self.stop_hash.encoder(),
            PrefixedSliceEncoder::new(&self.filter_headers),
        ))
    }
}

type CFCheckptInnerDecoder = Decoder3<ArrayDecoder<1>, BlockHashDecoder, VecDecoder<FilterHeader>>;

crate::decoder_newtype! {
    /// Decoder type for a [`CFCheckpt`] message.
    #[derive(Debug, Default, Clone)]
    pub struct CFCheckptDecoder(CFCheckptInnerDecoder);

    fn end(
        result: Result<([u8; 1], BlockHash, Vec<FilterHeader>), <CFCheckptInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<CFCheckpt, CFCheckptDecoderError> {
        let (ty, stop_hash, filter_headers) = result.map_err(CFCheckptDecoderError)?;
        Ok(CFCheckpt { filter_type: u8::from_le_bytes(ty), stop_hash, filter_headers })
    }
}

impl encoding::Decode for CFCheckpt {
    type Decoder = CFCheckptDecoder;
}

/// Error types for client side block filtering messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// Errors occurring when decoding a [`FilterHash`] message.
    ///
    /// [`FilterHash`]: super::FilterHash
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterHashDecoderError(
        pub(super) <super::HashInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`FilterHeader`] message.
    ///
    /// [`FilterHeader`]: super::FilterHeader
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FilterHeaderDecoderError(
        pub(super) <super::HashInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`GetCFilters`] message.
    ///
    /// [`GetCFilters`]: super::GetCFilters
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GetCFiltersDecoderError(
        pub(super) <super::GetCFiltersInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`CFilter`] message.
    ///
    /// [`CFilter`]: super::CFilter
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CFilterDecoderError(
        pub(super) <super::CFilterInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`GetCFHeaders`] message.
    ///
    /// [`GetCFHeaders`]: super::GetCFHeaders
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GetCFHeadersDecoderError(
        pub(super) <super::GetCFHeadersInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`CFHeaders`] message.
    ///
    /// [`CFHeaders`]: super::CFHeaders
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CFHeadersDecoderError(
        pub(super) <super::CFHeadersInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for CFHeadersDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for CFHeadersDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "cfheaders error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CFHeadersDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// Errors occurring when decoding a [`GetCFCheckpt`] message.
    ///
    /// [`GetCFCheckpt`]: super::GetCFCheckpt
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GetCFCheckptDecoderError(
        pub(super) <super::GetCFCheckptInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// Errors occurring when decoding a [`CFCheckpt`] message.
    ///
    /// [`CFCheckpt`]: super::CFCheckpt
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CFCheckptDecoderError(
        pub(super) <super::CFCheckptInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for CFCheckptDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for CFCheckptDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "cfcheckpt error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CFCheckptDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

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
