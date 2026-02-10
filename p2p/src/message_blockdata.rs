// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blockdata network messages.
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.

use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use encoding::{
    ArrayDecoder, ArrayEncoder, CompactSizeEncoder, Decoder2, Decoder3, Encoder2, Encoder3,
    SliceEncoder, VecDecoder,
};
use internals::write_err;
use io::{BufRead, Write};
use primitives::block::{BlockHashDecoder, BlockHashEncoder};
use primitives::transaction::{Txid, Wtxid};
use primitives::BlockHash;

use crate::consensus::impl_consensus_encoding;
use crate::{ProtocolVersion, ProtocolVersionDecoder, ProtocolVersionEncoder};

/// An inventory item.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// Error --- these inventories can be ignored.
    /// While a 32 byte hash is expected over the wire, the value is meaningless.
    Error([u8; 32]),
    /// Transaction
    Transaction(Txid),
    /// Block
    Block(BlockHash),
    /// Compact Block
    CompactBlock(BlockHash),
    /// Witness Transaction by Wtxid
    WTx(Wtxid),
    /// Witness Transaction
    WitnessTransaction(Txid),
    /// Witness Block
    WitnessBlock(BlockHash),
    /// Unknown inventory type
    Unknown {
        /// The inventory item type.
        inv_type: u32,
        /// The hash of the inventory item
        hash: [u8; 32],
    },
}

impl Inventory {
    /// Returns the item value represented as a SHA256-d hash.
    ///
    /// Returns [None] only for [`Inventory::Error`] who's hash value is meaningless.
    pub fn network_hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::Error(_) => None,
            Self::Transaction(t) => Some(t.to_byte_array()),
            Self::Block(b) => Some(b.to_byte_array()),
            Self::CompactBlock(b) => Some(b.to_byte_array()),
            Self::WTx(t) => Some(t.to_byte_array()),
            Self::WitnessTransaction(t) => Some(t.to_byte_array()),
            Self::WitnessBlock(b) => Some(b.to_byte_array()),
            Self::Unknown { hash, .. } => Some(*hash),
        }
    }
}

impl Encodable for Inventory {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        macro_rules! encode_inv {
            ($code:expr, $item:expr) => {
                u32::consensus_encode(&$code, w)? + $item.consensus_encode(w)?
            };
        }
        Ok(match *self {
            Self::Error(ref e) => encode_inv!(0, e),
            Self::Transaction(ref t) => encode_inv!(1, t),
            Self::Block(ref b) => encode_inv!(2, b),
            Self::CompactBlock(ref b) => encode_inv!(4, b),
            Self::WTx(ref w) => encode_inv!(5, w),
            Self::WitnessTransaction(ref t) => encode_inv!(0x4000_0001, t),
            Self::WitnessBlock(ref b) => encode_inv!(0x4000_0002, b),
            Self::Unknown { inv_type: t, hash: ref d } => encode_inv!(t, d),
        })
    }
}

impl Decodable for Inventory {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let inv_type: u32 = Decodable::consensus_decode(r)?;
        Ok(match inv_type {
            0 => Self::Error(Decodable::consensus_decode(r)?),
            1 => Self::Transaction(Decodable::consensus_decode(r)?),
            2 => Self::Block(Decodable::consensus_decode(r)?),
            4 => Self::CompactBlock(Decodable::consensus_decode(r)?),
            5 => Self::WTx(Decodable::consensus_decode(r)?),
            0x4000_0001 => Self::WitnessTransaction(Decodable::consensus_decode(r)?),
            0x4000_0002 => Self::WitnessBlock(Decodable::consensus_decode(r)?),
            tp => Self::Unknown { inv_type: tp, hash: Decodable::consensus_decode(r)? },
        })
    }
}

encoding::encoder_newtype! {
    /// The encoder for the [`Inventory`] type.
    pub struct InventoryEncoder<'e>(Encoder2<ArrayEncoder<4>, ArrayEncoder<32>>);
}

impl encoding::Encodable for Inventory {
    type Encoder<'e> = InventoryEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        let (prefix, bytes) = match *self {
            Self::Error(e) => (0, e),
            Self::Transaction(t) => (1, t.to_byte_array()),
            Self::Block(b) => (2, b.to_byte_array()),
            Self::CompactBlock(b) => (4, b.to_byte_array()),
            Self::WTx(w) => (5, w.to_byte_array()),
            Self::WitnessTransaction(t) => (0x4000_0001, t.to_byte_array()),
            Self::WitnessBlock(b) => (0x4000_0002, b.to_byte_array()),
            Self::Unknown { inv_type: t, hash: d } => (t, d),
        };
        InventoryEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix(prefix.to_le_bytes()),
            ArrayEncoder::without_length_prefix(bytes),
        ))
    }
}

type InventoryInnerDecoder = Decoder2<ArrayDecoder<4>, ArrayDecoder<32>>;

/// The decoder for the [`Inventory`] type.
pub struct InventoryDecoder(InventoryInnerDecoder);

impl encoding::Decoder for InventoryDecoder {
    type Output = Inventory;
    type Error = InventoryDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(InventoryDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (ty, inv) = self.0.end().map_err(InventoryDecoderError)?;
        let inv_type = u32::from_le_bytes(ty);
        Ok(match inv_type {
            0 => Self::Output::Error(inv),
            1 => Self::Output::Transaction(Txid::from_byte_array(inv)),
            2 => Self::Output::Block(BlockHash::from_byte_array(inv)),
            4 => Self::Output::CompactBlock(BlockHash::from_byte_array(inv)),
            5 => Self::Output::WTx(Wtxid::from_byte_array(inv)),
            0x4000_0001 => Self::Output::WitnessTransaction(Txid::from_byte_array(inv)),
            0x4000_0002 => Self::Output::WitnessBlock(BlockHash::from_byte_array(inv)),
            tp => Self::Output::Unknown { inv_type: tp, hash: inv },
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for Inventory {
    type Decoder = InventoryDecoder;
    fn decoder() -> Self::Decoder {
        InventoryDecoder(Decoder2::new(ArrayDecoder::<4>::new(), ArrayDecoder::<32>::new()))
    }
}

/// An error consensus decoding an [`Inventory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDecoderError(<InventoryInnerDecoder as encoding::Decoder>::Error);

impl From<Infallible> for InventoryDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for InventoryDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "inventory error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InventoryDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

// Some simple messages

/// The `getblocks` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetBlocksMessage {
    /// The protocol version
    pub version: ProtocolVersion,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the block to stop at, or zero to just fetch the maximum 500 blocks
    pub stop_hash: BlockHash,
}

/// The `getheaders` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetHeadersMessage {
    /// The protocol version
    pub version: ProtocolVersion,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the header to stop at, or zero to just fetch the maximum 2000 headers
    pub stop_hash: BlockHash,
}

type GetBlocksOrHeadersInnerEncoder<'e> = Encoder3<
    ProtocolVersionEncoder<'e>,
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, BlockHash>>,
    BlockHashEncoder<'e>,
>;

encoding::encoder_newtype! {
    /// The encoder for [`GetBlocksMessage`].
    pub struct GetBlocksEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

encoding::encoder_newtype! {
    /// The encoder for [`GetHeadersMessage`].
    pub struct GetHeadersEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

impl encoding::Encodable for GetHeadersMessage {
    type Encoder<'e>
        = GetHeadersEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetHeadersEncoder::new(Encoder3::new(
            self.version.encoder(),
            Encoder2::new(
                CompactSizeEncoder::new(self.locator_hashes.len()),
                SliceEncoder::without_length_prefix(&self.locator_hashes),
            ),
            self.stop_hash.encoder(),
        ))
    }
}

impl encoding::Encodable for GetBlocksMessage {
    type Encoder<'e>
        = GetBlocksEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetBlocksEncoder::new(Encoder3::new(
            self.version.encoder(),
            Encoder2::new(
                CompactSizeEncoder::new(self.locator_hashes.len()),
                SliceEncoder::without_length_prefix(&self.locator_hashes),
            ),
            self.stop_hash.encoder(),
        ))
    }
}

type GetBlocksOrHeadersInnerDecoder =
    Decoder3<ProtocolVersionDecoder, VecDecoder<BlockHash>, BlockHashDecoder>;

/// Decoder type for [`GetBlocksMessage`].
pub struct GetBlocksMessageDecoder(GetBlocksOrHeadersInnerDecoder);

/// Decoder type for [`GetHeadersMessage`].
pub struct GetHeadersMessageDecoder(GetBlocksOrHeadersInnerDecoder);

impl encoding::Decoder for GetHeadersMessageDecoder {
    type Output = GetHeadersMessage;
    type Error = GetHeadersMessageDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(GetHeadersMessageDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (version, locator_hashes, stop_hash) =
            self.0.end().map_err(GetHeadersMessageDecoderError)?;
        Ok(GetHeadersMessage { version, locator_hashes, stop_hash })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decoder for GetBlocksMessageDecoder {
    type Output = GetBlocksMessage;
    type Error = GetBlocksMessageDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(GetBlocksMessageDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (version, locator_hashes, stop_hash) =
            self.0.end().map_err(GetBlocksMessageDecoderError)?;
        Ok(GetBlocksMessage { version, locator_hashes, stop_hash })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for GetBlocksMessage {
    type Decoder = GetBlocksMessageDecoder;
    fn decoder() -> Self::Decoder {
        GetBlocksMessageDecoder(Decoder3::new(
            ProtocolVersionDecoder::new(),
            VecDecoder::<BlockHash>::new(),
            BlockHashDecoder::new(),
        ))
    }
}

impl encoding::Decodable for GetHeadersMessage {
    type Decoder = GetHeadersMessageDecoder;
    fn decoder() -> Self::Decoder {
        GetHeadersMessageDecoder(Decoder3::new(
            ProtocolVersionDecoder::new(),
            VecDecoder::<BlockHash>::new(),
            BlockHashDecoder::new(),
        ))
    }
}

/// An error consensus decoding a [`GetBlocksMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocksMessageDecoderError(
    <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
);

impl From<Infallible> for GetBlocksMessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetBlocksMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "getblocks decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetBlocksMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// An error consensus decoding a [`GetHeadersMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMessageDecoderError(
    <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
);

impl From<Infallible> for GetHeadersMessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for GetHeadersMessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "getheaders decoder error"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetHeadersMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash);

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetHeadersMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: u.arbitrary()?,
            locator_hashes: Vec::<BlockHash>::arbitrary(u)?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetBlocksMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: u.arbitrary()?,
            locator_hashes: Vec::<BlockHash>::arbitrary(u)?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Inventory {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=7)? {
            0 => Ok(Self::Error(u.arbitrary()?)),
            1 => Ok(Self::Transaction(u.arbitrary()?)),
            2 => Ok(Self::Block(u.arbitrary()?)),
            3 => Ok(Self::CompactBlock(u.arbitrary()?)),
            4 => Ok(Self::WTx(u.arbitrary()?)),
            5 => Ok(Self::WitnessTransaction(u.arbitrary()?)),
            6 => Ok(Self::WitnessBlock(u.arbitrary()?)),
            _ => Ok(Self::Unknown { inv_type: u.arbitrary()?, hash: u.arbitrary()? }),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use hex::hex;

    use super::*;

    #[test]
    fn getblocks_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetBlocksMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn getheaders_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetHeadersMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(serialize(&real_decode), from_sat);
    }
}
