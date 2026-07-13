// SPDX-License-Identifier: CC0-1.0

//!
//! BIP152  Compact Blocks network messages
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;
#[cfg(feature = "encoding")]
use core::fmt;

#[cfg(feature = "encoding")]
use encoding::{ArrayDecoder, ArrayEncoder, Decoder2, Encoder2};

use crate::bip152;
use crate::internal_macros::impl_consensus_encoding;
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;

/// sendcmpct message
#[derive(PartialEq, Eq, Clone, Debug, Copy, PartialOrd, Ord, Hash)]
pub struct SendCmpct {
    /// Request to be send compact blocks.
    pub send_compact: bool,
    /// Compact Blocks protocol version number.
    pub version: u64,
}

impl crate::consensus::Encodable for SendCmpct {
    #[inline]
    fn consensus_encode<R: crate::io::Write + ?Sized>(
        &self,
        r: &mut R,
    ) -> core::result::Result<usize, crate::io::Error> {
        let mut len = 0;
        len += self.send_compact.consensus_encode(r)?;
        len += self.version.consensus_encode(r)?;
        Ok(len)
    }
}

impl crate::consensus::Decodable for SendCmpct {
    #[inline]
    fn consensus_decode<R: crate::io::Read + ?Sized>(
        r: &mut R,
    ) -> core::result::Result<Self, crate::consensus::encode::Error> {
        let send_compact: u8 = crate::consensus::Decodable::consensus_decode(r)?;
        let version = crate::consensus::Decodable::consensus_decode(r)?;

        if send_compact == 1 || send_compact == 0 {
            let send_compact = send_compact != 0;
            Ok(SendCmpct { send_compact, version })
        } else {
            Err(crate::consensus::encode::Error::ParseFailed("first byte was not 0 or 1"))
        }
    }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// Encoder type for the [`SendCmpct`] message.
    #[derive(Debug, Clone)]
    pub struct SendCmpctEncoder<'e>(Encoder2<ArrayEncoder<1>, ArrayEncoder<8>>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for SendCmpct {
    type Encoder<'e> = SendCmpctEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        SendCmpctEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix([u8::from(self.send_compact)]),
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
        ))
    }
}

#[cfg(feature = "encoding")]
type SendCmpctInnerDecoder = Decoder2<ArrayDecoder<1>, ArrayDecoder<8>>;

#[cfg(feature = "encoding")]
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

#[cfg(feature = "encoding")]
impl encoding::Decode for SendCmpct {
    type Decoder = SendCmpctDecoder;
}

/// Errors occurring when decoding a [`SendCmpct`] message.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendCmpctDecoderError(
    pub(crate) <SendCmpctInnerDecoder as encoding::Decoder>::Error
);

#[cfg(feature = "encoding")]
impl From<Infallible> for SendCmpctDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for SendCmpctDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "sendcmpct error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for SendCmpctDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// cmpctblock message
///
/// Note that the rules for validation before relaying compact blocks is
/// different from headers and regular block messages. Thus, you shouldn't use
/// compact blocks when relying on an upstream full node to have validated data
/// being forwarded to you.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct CmpctBlock {
    /// The Compact Block.
    pub compact_block: bip152::HeaderAndShortIds,
}
impl_consensus_encoding!(CmpctBlock, compact_block);

/// getblocktxn message
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct GetBlockTxn {
    /// The block transactions request.
    pub txs_request: bip152::BlockTransactionsRequest,
}
impl_consensus_encoding!(GetBlockTxn, txs_request);

/// blocktxn message
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTxn {
    /// The requested block transactions.
    pub transactions: bip152::BlockTransactions,
}
impl_consensus_encoding!(BlockTxn, transactions);
