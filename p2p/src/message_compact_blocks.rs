// SPDX-License-Identifier: CC0-1.0

//!
//! BIP-0152  Compact Blocks network messages

use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::consensus::impl_consensus_encoding;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be sent compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}
impl_consensus_encoding!(SendCmpct, send_compact, version);

encoding::encoder_newtype! {
    /// The encoder for the [`SendCmpct`] type.
    pub struct SendCmpctEncoder<'e>(encoding::Encoder2<
        encoding::ArrayEncoder<1>,
        encoding::ArrayEncoder<8>
    >);
}

impl encoding::Encodable for SendCmpct {
    type Encoder<'e>
        = SendCmpctEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        SendCmpctEncoder::new(encoding::Encoder2::new(
            encoding::ArrayEncoder::without_length_prefix([u8::from(self.send_compact)]),
            encoding::ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
        ))
    }
}

type SendCmpctInnerDecoder =
    encoding::Decoder2<encoding::ArrayDecoder<1>, encoding::ArrayDecoder<8>>;

/// The Decoder for [`SendCmpct`].
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
        let (send_compact, version) = self.0.end().map_err(SendCmpctDecoderError)?;
        let send_compact = send_compact[0] != 0;
        let version = u64::from_le_bytes(version);
        Ok(SendCmpct { send_compact, version })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for SendCmpct {
    type Decoder = SendCmpctDecoder;
    fn decoder() -> Self::Decoder {
        SendCmpctDecoder(encoding::Decoder2::new(
            encoding::ArrayDecoder::<1>::new(),
            encoding::ArrayDecoder::<8>::new(),
        ))
    }
}

/// An error consensus decoding a [`SendCmpctDecoderError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendCmpctDecoderError(<SendCmpctInnerDecoder as encoding::Decoder>::Error);
impl From<Infallible> for SendCmpctDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SendCmpctDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        internals::write_err!(f, "address decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SendCmpctDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendCmpct {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { send_compact: u.arbitrary()?, version: u.arbitrary()? })
    }
}
