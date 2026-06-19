// SPDX-License-Identifier: CC0-1.0

//!
//! BIP-0152  Compact Blocks network messages

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ArrayDecoder, ArrayEncoder, Decoder2, Encoder2};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::SendCmpctDecoderError;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be sent compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}

encoding::encoder_newtype_exact! {
    /// Encoder type for the [`SendCmpct`] message.
    #[derive(Debug, Clone)]
    pub struct SendCmpctEncoder<'e>(Encoder2<ArrayEncoder<1>, ArrayEncoder<8>>);
}

impl encoding::Encode for SendCmpct {
    type Encoder<'e> = SendCmpctEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        SendCmpctEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix([u8::from(self.send_compact)]),
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
        ))
    }
}

type SendCmpctInnerDecoder = Decoder2<ArrayDecoder<1>, ArrayDecoder<8>>;

crate::decoder_newtype! {
    /// Decoder type for the [`SendCmpct`] message.
    #[derive(Debug, Default, Clone)]
    pub struct SendCmpctDecoder(SendCmpctInnerDecoder);

    fn end(
        result: Result<([u8; 1], [u8; 8]), <SendCmpctInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<SendCmpct, SendCmpctDecoderError> {
        let (send_cmpct, version) = result.map_err(SendCmpctDecoderError)?;
        let send_compact = u8::from_le_bytes(send_cmpct) != 0;
        Ok(SendCmpct { send_compact, version: u64::from_le_bytes(version) })
    }
}

impl encoding::Decode for SendCmpct {
    type Decoder = SendCmpctDecoder;
}

/// Error types for [`SendCmpct`] messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// Errors occurring when decoding a [`SendCmpct`] message.
    ///
    /// [`SendCmpct`]: super::SendCmpct
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SendCmpctDecoderError(
        pub(super) <super::SendCmpctInnerDecoder as encoding::Decoder>::Error,
    );

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
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SendCmpct {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { send_compact: u.arbitrary()?, version: u.arbitrary()? })
    }
}
