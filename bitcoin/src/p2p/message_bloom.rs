// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Connection Bloom filtering network messages.
//!
//! This module describes BIP37 Connection Bloom filtering network messages.
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;
#[cfg(feature = "encoding")]
use core::fmt;
#[cfg(feature = "encoding")]
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, BytesEncoder, CompactSizeEncoder, Decoder4,
    Encoder2, Encoder3,
};

use io::{Read, Write};

use crate::consensus::{encode, Decodable, Encodable, ReadExt};
use crate::internal_macros::impl_consensus_encoding;
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;

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

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`FilterLoad`] message.
    #[derive(Debug, Clone)]
    pub struct FilterLoadEncoder<'e>(
        Encoder2<
            Encoder2<CompactSizeEncoder, BytesEncoder<'e>>,
            Encoder3<
                ArrayEncoder<4>,
                ArrayEncoder<4>,
                BloomFlagsEncoder<'e>,
            >,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for FilterLoad {
    type Encoder<'e> = FilterLoadEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterLoadEncoder::new(Encoder2::new(
            Encoder2::new(
                CompactSizeEncoder::new(self.filter.len()),
                BytesEncoder::without_length_prefix(&self.filter),
            ),
            Encoder3::new(
                ArrayEncoder::without_length_prefix(self.hash_funcs.to_le_bytes()),
                ArrayEncoder::without_length_prefix(self.tweak.to_le_bytes()),
                self.flags.encoder(),
            ),
        ))
    }
}

#[cfg(feature = "encoding")]
type FilterLoadInnerDecoder =
    Decoder4<ByteVecDecoder, ArrayDecoder<4>, ArrayDecoder<4>, BloomFlagsDecoder>;


#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`FilterLoad`] message.
    #[derive(Debug, Default, Clone)]
    pub struct FilterLoadDecoder(FilterLoadInnerDecoder);

    fn end(
        result: Result<
            <FilterLoadInnerDecoder as encoding::Decoder>::Output,
            <FilterLoadInnerDecoder as encoding::Decoder>::Error,
        >
    ) -> Result<FilterLoad, FilterLoadDecoderError> {
        let (filter, hash_funcs, tweak, flags) = result.map_err(FilterLoadDecoderError)?;
        Ok(FilterLoad {
            filter,
            hash_funcs: u32::from_le_bytes(hash_funcs),
            tweak: u32::from_le_bytes(tweak),
            flags,
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for FilterLoad {
    type Decoder = FilterLoadDecoder;
}

/// An error occurring when decoding a [`FilterLoad`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterLoadDecoderError(
    pub(crate) <FilterLoadInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for FilterLoadDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for FilterLoadDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filterload error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for FilterLoadDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

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

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for [`BloomFlags`].
    #[derive(Debug, Clone)]
    pub struct BloomFlagsEncoder<'e>(ArrayEncoder<1>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for BloomFlags {
    type Encoder<'e> = BloomFlagsEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        BloomFlagsEncoder::new(ArrayEncoder::without_length_prefix([match self {
            Self::None => 0,
            Self::All => 1,
            Self::PubkeyOnly => 2,
        }]))
    }
}

#[cfg(feature = "encoding")]
type BloomFlagsInnerDecoder = ArrayDecoder<1>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for [`BloomFlags`].
    #[derive(Debug, Default, Clone)]
    pub struct BloomFlagsDecoder(BloomFlagsInnerDecoder);

    fn map_push_bytes_err(err: encoding::UnexpectedEofError) -> BloomFlagsDecoderError {
        BloomFlagsDecoderError::Decoder(err)
    }

    fn end(
        result: Result<[u8; 1], encoding::UnexpectedEofError>
    ) -> Result<BloomFlags, BloomFlagsDecoderError> {
        let bloom_flag_arr = result.map_err(BloomFlagsDecoderError::Decoder)?;
        let bloom_flag = u8::from_le_bytes(bloom_flag_arr);
        Ok(match bloom_flag {
            0 => BloomFlags::None,
            1 => BloomFlags::All,
            2 => BloomFlags::PubkeyOnly,
            flag => return Err(BloomFlagsDecoderError::UnknownFlag(flag)),
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for BloomFlags {
    type Decoder = BloomFlagsDecoder;
}

/// An error occurring when decoding a [`BloomFlags`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloomFlagsDecoderError {
    /// Inner decoder error.
    Decoder(<BloomFlagsInnerDecoder as encoding::Decoder>::Error),
    /// The flag is not known.
    UnknownFlag(u8),
}

#[cfg(feature = "encoding")]
impl From<Infallible> for BloomFlagsDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for BloomFlagsDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(err) => write_err!(f, "bloomflags error"; err),
            Self::UnknownFlag(flag) => write!(f, "unknown bloomflag {}", flag),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for BloomFlagsDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(err) => Some(err),
            Self::UnknownFlag(_) => None,
        }
    }
}

impl Encodable for BloomFlags {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&[match self {
            BloomFlags::None => 0,
            BloomFlags::All => 1,
            BloomFlags::PubkeyOnly => 2,
        }])?;
        Ok(1)
    }
}

impl Decodable for BloomFlags {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(match r.read_u8()? {
            0 => BloomFlags::None,
            1 => BloomFlags::All,
            2 => BloomFlags::PubkeyOnly,
            _ => return Err(encode::Error::ParseFailed("unknown bloom flag")),
        })
    }
}

/// `filteradd` message updates the current filter with new data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterAdd {
    /// The data element to add to the current filter.
    pub data: Vec<u8>,
}

impl_consensus_encoding!(FilterAdd, data);

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder of the [`FilterAdd`] message.
    #[derive(Debug, Clone)]
    pub struct FilterAddEncoder<'e>(Encoder2<CompactSizeEncoder, BytesEncoder<'e>>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for FilterAdd {
    type Encoder<'e> = FilterAddEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        FilterAddEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.data.len()),
            BytesEncoder::without_length_prefix(&self.data),
        ))
    }
}

#[cfg(feature = "encoding")]
type FilterAddInnerDecoder = encoding::ByteVecDecoder;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`FilterAdd`] message.
    #[derive(Debug, Default, Clone)]
    pub struct FilterAddDecoder(FilterAddInnerDecoder);

    fn end(
        result: Result<Vec<u8>, encoding::ByteVecDecoderError>
    ) -> Result<FilterAdd, FilterAddDecoderError> {
        let data = result.map_err(FilterAddDecoderError)?;
        Ok(FilterAdd { data })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for FilterAdd {
    type Decoder = FilterAddDecoder;
}

/// An error decoding a [`FilterAdd`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterAddDecoderError(pub(crate) <FilterAddInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for FilterAddDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for FilterAddDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "filteradd error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for FilterAddDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}
