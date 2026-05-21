// SPDX-License-Identifier: CC0-1.0

//! Messages related to [Erlay transaction announcements](https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki#user-content-sendtxrcncl).

use encoding::{ArrayDecoder, ArrayEncoder, Decoder2, Encoder2};

use crate::message_erlay::error::SendTxRcnClDecoderError;

/// Announce support for the transaction reconciliation protocol.
///
/// Note that this message should be [sent before
/// verack](https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki#sendtxrcncl).
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, PartialOrd, Ord)]
pub struct SendTxRcnCl {
    // Transaction reconciliation protocol version.
    version: u32,
    /// Salt used in short ID computation.
    pub salt: u64,
}

impl SendTxRcnCl {
    /// Version one of the protocol.
    pub const VERSION_ONE: u32 = 1;

    /// Build a new announcement for erlay with salt.
    pub fn from_salt(salt: u64) -> Self { Self { version: Self::VERSION_ONE, salt } }

    /// Get the transaction reconciliation protocol version.
    pub fn version(&self) -> u32 { self.version }
}

encoding::encoder_newtype_exact! {
    /// The encoder for a [`SendTxRcnCl`] message.
    #[derive(Debug, Clone)]
    pub struct SendTxRcnClEncoder<'e>(Encoder2<ArrayEncoder<4>, ArrayEncoder<8>>);
}

impl encoding::Encode for SendTxRcnCl {
    type Encoder<'e>
        = SendTxRcnClEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        SendTxRcnClEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            ArrayEncoder::without_length_prefix(self.salt.to_le_bytes()),
        ))
    }
}

type SendTxRcnClInnerDecoder = Decoder2<ArrayDecoder<4>, ArrayDecoder<8>>;

crate::decoder_newtype! {
    /// The decoder for a [`SendTxRcnCl`] message.
    #[derive(Debug, Default, Clone)]
    pub struct SendTxRcnClDecoder(SendTxRcnClInnerDecoder);

    fn end(result: Result<([u8; 4], [u8; 8]), <SendTxRcnClInnerDecoder as encoding::Decoder>::Error>) -> Result<SendTxRcnCl, SendTxRcnClDecoderError> {
        let (version, salt) = result.map_err(SendTxRcnClDecoderError)?;
        Ok(SendTxRcnCl { version: u32::from_le_bytes(version), salt: u64::from_le_bytes(salt) })
    }
    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for SendTxRcnCl {
    type Decoder = SendTxRcnClDecoder;
}

/// Error types for erlay messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// An error occurring when decoding a [`SendTxRcnCl`](super) message.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SendTxRcnClDecoderError(
        pub(super) <super::SendTxRcnClInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for SendTxRcnClDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for SendTxRcnClDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "sendtxrcncl error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for SendTxRcnClDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}
