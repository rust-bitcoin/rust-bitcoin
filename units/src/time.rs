// SPDX-License-Identifier: CC0-1.0

//! A UNIX timestamp used as the Bitcoin block time.
//!
//! Also known as Epoch Time - January 1, 1970.
//!
//! This differs from other UNIX timestamps in that we only use non-negative values. The Epoch
//! pre-dates Bitcoin so timestamps before this are not useful for block timestamps.

#[cfg(feature = "encoding")]
use core::convert::Infallible;
#[cfg(feature = "encoding")]
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "encoding")]
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod encapsulate {
    /// A Bitcoin block timestamp.
    ///
    /// > Each block contains a Unix time timestamp. In addition to serving as a source of variation for
    /// > the block hash, they also make it more difficult for an adversary to manipulate the block chain.
    /// >
    /// > A timestamp is accepted as valid if it is greater than the median timestamp of previous 11
    /// > blocks, and less than the network-adjusted time + 2 hours. "Network-adjusted time" is the
    /// > median of the timestamps returned by all nodes connected to you. As a result block timestamps
    /// > are not exactly accurate, and they do not need to be. Block times are accurate only to within
    /// > an hour or two.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Block_timestamp>
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BlockTime(u32);

    impl BlockTime {
        /// Constructs a new [`BlockTime`] from an unsigned 32 bit integer value.
        #[inline]
        pub const fn from_u32(t: u32) -> Self { Self(t) }

        /// Returns the inner `u32` value.
        #[inline]
        pub const fn to_u32(self) -> u32 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::BlockTime;

impl From<u32> for BlockTime {
    #[inline]
    fn from(t: u32) -> Self { Self::from_u32(t) }
}

impl From<BlockTime> for u32 {
    #[inline]
    fn from(t: BlockTime) -> Self { t.to_u32() }
}

#[cfg(feature = "serde")]
impl Serialize for BlockTime {
    #[inline]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        u32::serialize(&self.to_u32(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for BlockTime {
    #[inline]
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_u32(u32::deserialize(d)?))
    }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`BlockTime`] type.
    pub struct BlockTimeEncoder<'e>(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for BlockTime {
    type Encoder<'e> = BlockTimeEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockTimeEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_u32().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`BlockTime`] type.
#[cfg(feature = "encoding")]
pub struct BlockTimeDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl Default for BlockTimeDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl BlockTimeDecoder {
    /// Constructs a new [`BlockTime`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for BlockTimeDecoder {
    type Output = BlockTime;
    type Error = BlockTimeDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(BlockTimeDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let t = u32::from_le_bytes(self.0.end().map_err(BlockTimeDecoderError)?);
        Ok(BlockTime::from_u32(t))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for BlockTime {
    type Decoder = BlockTimeDecoder;
    fn decoder() -> Self::Decoder { BlockTimeDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `BlockTime`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTimeDecoderError(encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for BlockTimeDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for BlockTimeDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "block time decoder error"; self.0)
    }
}

#[cfg(all(feature = "std", feature = "encoding"))]
impl std::error::Error for BlockTimeDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTime {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let t: u32 = u.arbitrary()?;
        Ok(Self::from(t))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "encoding")]
    use encoding::Decoder as _;
    #[cfg(all(feature = "encoding", feature = "alloc"))]
    use encoding::UnexpectedEofError;

    use super::*;

    #[test]
    fn block_time_round_trip() {
        let t = BlockTime::from(1_742_979_600); // 26 Mar 2025 9:00 UTC
        assert_eq!(u32::from(t), 1_742_979_600);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn block_time_serde_round_trip() {
        let t = BlockTime::from(1_765_364_400); // 10 Dec 2025 11:00 UTC

        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "1765364400"); // ASCII number representation

        let roundtrip = serde_json::from_str::<BlockTime>(&json).unwrap();
        assert_eq!(t, roundtrip);
    }

    #[test]
    #[cfg(all(feature = "encoding", feature = "alloc"))]
    fn block_time_decoding_error() {
        let bytes = [0xb0, 0x52, 0x39]; // 3 bytes is an EOF error

        let mut decoder = BlockTimeDecoder::default();
        assert!(decoder.push_bytes(&mut bytes.as_slice()).unwrap());

        let error = decoder.end().unwrap_err();
        assert!(matches!(error, BlockTimeDecoderError(UnexpectedEofError { .. })));
    }
}
