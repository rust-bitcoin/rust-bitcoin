// SPDX-License-Identifier: CC0-1.0

//!
//! BIP-0152  Compact Blocks network messages

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::consensus::impl_consensus_encoding;
use encoding::{ArrayDecoder, ArrayEncoder, Decoder2, Encoder2};
use internals::write_err;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be sent compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}

encoding::encoder_newtype! {
    /// Encoder type for the [`SendCmpct`] message.
    pub struct SendCmpctEncoder<'e>(Encoder2<ArrayEncoder<1>, ArrayEncoder<8>>);
}

impl encoding::Encodable for SendCmpct {
    type Encoder<'e> = SendCmpctEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        SendCmpctEncoder::new(
            Encoder2::new(
                ArrayEncoder::without_length_prefix([u8::from(self.send_compact)]),
                ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            )
        )
    }
}

type SendCmpctInnerDecoder = Decoder2<ArrayDecoder<1>, ArrayDecoder<8>>;

/// Decoder type for the [`SendCmpct`] message.
pub struct SendCmpctDecoder(SendCmpctInnerDecoder);

impl encoding::Decoder for SendCmpctDecoder {
    type Output = SendCmpct;
    type Error = SendCmpctDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(SendCmpctDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (send_cmpct, version) = self.0.end().map_err(SendCmpctDecoderError)?;
        let send_compact = u8::from_le_bytes(send_cmpct) != 0;
        Ok(SendCmpct {
            send_compact,
            version: u64::from_le_bytes(version),
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for SendCmpct {
    type Decoder = SendCmpctDecoder;

    fn decoder() -> Self::Decoder {
        SendCmpctDecoder(
            Decoder2::new(ArrayDecoder::new(), ArrayDecoder::new())
        )
    }
}

/// Errors occuring when decoding a [`SendCmpct`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendCmpctDecoderError(<SendCmpctInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for SendCmpctDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SendCmpctDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "sendcmpct error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendCmpctDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(SendCmpct, send_compact, version);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendCmpct {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { send_compact: u.arbitrary()?, version: u.arbitrary()? })
    }
}
