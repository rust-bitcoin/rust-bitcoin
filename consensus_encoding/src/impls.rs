// SPDX-License-Identifier: CC0-1.0

//! Core impls for standard primitives and collections.

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::decode::decoders::{ArrayDecoder, MapDecoder};
#[cfg(feature = "alloc")]
use crate::decode::decoders::{ByteVecDecoder, VecDecoder};
use crate::encode::encoders::ArrayRefEncoder;
#[cfg(feature = "alloc")]
use crate::encode::encoders::{BytesEncoder, Encoder2, SliceEncoder};
#[cfg(feature = "alloc")]
use crate::error::ByteVecDecoderError;
#[cfg(feature = "alloc")]
use crate::{CompactSizeEncoder, Decoder};
use crate::{Decodable, Encodable};

type MapArrayDecoder<T, const N: usize> = MapDecoder<ArrayDecoder<N>, T>;

fn id<const N: usize>(bytes: [u8; N]) -> [u8; N] { bytes }
fn u8_from_le(bytes: [u8; 1]) -> u8 { bytes[0] }
fn i8_from_le(bytes: [u8; 1]) -> i8 { bytes[0] as i8 }
fn bool_from_byte(bytes: [u8; 1]) -> bool { bytes[0] != 0 }

macro_rules! impl_int {
    ($ty:ty, $len:literal) => {
        impl Encodable for $ty {
            type Encoder<'e>
                = crate::ArrayEncoder<$len>
            where
                Self: 'e;

            #[inline]
            fn encoder(&self) -> Self::Encoder<'_> {
                crate::ArrayEncoder::without_length_prefix(self.to_le_bytes())
            }
        }

        impl Decodable for $ty {
            type Decoder = MapArrayDecoder<$ty, $len>;

            #[inline]
            fn decoder() -> Self::Decoder {
                MapArrayDecoder::new(ArrayDecoder::new(), <$ty>::from_le_bytes)
            }
        }
    };
}

impl Encodable for u8 {
    type Encoder<'e>
        = crate::ArrayEncoder<1>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> { crate::ArrayEncoder::without_length_prefix([*self]) }
}

impl Decodable for u8 {
    type Decoder = MapArrayDecoder<u8, 1>;

    #[inline]
    fn decoder() -> Self::Decoder { MapArrayDecoder::new(ArrayDecoder::new(), u8_from_le) }
}

impl Encodable for i8 {
    type Encoder<'e>
        = crate::ArrayEncoder<1>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        crate::ArrayEncoder::without_length_prefix([*self as u8])
    }
}

impl Decodable for i8 {
    type Decoder = MapArrayDecoder<i8, 1>;

    #[inline]
    fn decoder() -> Self::Decoder { MapArrayDecoder::new(ArrayDecoder::new(), i8_from_le) }
}

impl_int!(u16, 2);
impl_int!(u32, 4);
impl_int!(u64, 8);
impl_int!(i16, 2);
impl_int!(i32, 4);
impl_int!(i64, 8);

impl Encodable for bool {
    type Encoder<'e>
        = crate::ArrayEncoder<1>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        crate::ArrayEncoder::without_length_prefix([u8::from(*self)])
    }
}

impl Decodable for bool {
    type Decoder = MapArrayDecoder<bool, 1>;

    #[inline]
    fn decoder() -> Self::Decoder { MapArrayDecoder::new(ArrayDecoder::new(), bool_from_byte) }
}

impl<const N: usize> Encodable for [u8; N] {
    type Encoder<'e>
        = ArrayRefEncoder<'e, N>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> { ArrayRefEncoder::without_length_prefix(self) }
}

impl<const N: usize> Decodable for [u8; N] {
    type Decoder = MapArrayDecoder<[u8; N], N>;

    #[inline]
    fn decoder() -> Self::Decoder { MapArrayDecoder::new(ArrayDecoder::new(), id::<N>) }
}

#[cfg(feature = "alloc")]
impl<T: Encodable> Encodable for Vec<T> {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, SliceEncoder<'e, T>>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.len()),
            SliceEncoder::without_length_prefix(self.as_slice()),
        )
    }
}

#[cfg(feature = "alloc")]
impl<T: Decodable> Decodable for Vec<T> {
    type Decoder = VecDecoder<T>;

    #[inline]
    fn decoder() -> Self::Decoder { VecDecoder::new() }
}

#[cfg(feature = "alloc")]
impl Encodable for String {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, BytesEncoder<'e>>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.len()),
            BytesEncoder::without_length_prefix(self.as_bytes()),
        )
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringDecoderError {
    /// Error decoding the underlying bytes.
    Bytes(ByteVecDecoderError),
    /// Decoded bytes were not valid UTF-8.
    InvalidUtf8,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for StringDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bytes(e) => write!(f, "string decoder error: {}", e),
            Self::InvalidUtf8 => write!(f, "string decoder error: invalid UTF-8"),
        }
    }
}

#[cfg(all(feature = "alloc", feature = "std"))]
impl std::error::Error for StringDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bytes(e) => Some(e),
            Self::InvalidUtf8 => None,
        }
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct StringDecoder(ByteVecDecoder);

#[cfg(feature = "alloc")]
impl StringDecoder {
    /// Constructs a new string decoder.
    pub const fn new() -> Self { Self(ByteVecDecoder::new()) }
}

#[cfg(feature = "alloc")]
impl Default for StringDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "alloc")]
impl Decoder for StringDecoder {
    type Output = String;
    type Error = StringDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(StringDecoderError::Bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        String::from_utf8(self.0.end().map_err(StringDecoderError::Bytes)?)
            .map_err(|_| StringDecoderError::InvalidUtf8)
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for String {
    type Decoder = StringDecoder;

    #[inline]
    fn decoder() -> Self::Decoder { StringDecoder::new() }
}

#[cfg(feature = "alloc")]
impl Encodable for Cow<'static, str> {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, BytesEncoder<'e>>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.len()),
            BytesEncoder::without_length_prefix(self.as_bytes()),
        )
    }
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct StaticCowStringDecoder(StringDecoder);

#[cfg(feature = "alloc")]
impl StaticCowStringDecoder {
    /// Constructs a new decoder.
    pub const fn new() -> Self { Self(StringDecoder::new()) }
}

#[cfg(feature = "alloc")]
impl Default for StaticCowStringDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "alloc")]
impl Decoder for StaticCowStringDecoder {
    type Output = Cow<'static, str>;
    type Error = StringDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Cow::Owned) }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "alloc")]
impl Decodable for Cow<'static, str> {
    type Decoder = StaticCowStringDecoder;

    #[inline]
    fn decoder() -> Self::Decoder { StaticCowStringDecoder::new() }
}
