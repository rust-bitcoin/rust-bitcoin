// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blockdata network messages.
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;

#[cfg(feature = "encoding")]
use encoding::{
    ArrayDecoder, ArrayEncoder, Decoder2, Decoder3, Encoder2, Encoder3, PrefixedSliceEncoder,
    VecDecoder,
};
use hashes::{sha256d, Hash as _};
use io::{Read, Write};

use crate::blockdata::block::BlockHash;
#[cfg(feature = "encoding")]
use crate::blockdata::block::{BlockHashDecoder, BlockHashEncoder};
use crate::blockdata::transaction::{Txid, Wtxid};
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::internal_macros::impl_consensus_encoding;
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;
use crate::p2p;

/// An inventory item.
#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, PartialOrd, Ord)]
pub enum Inventory {
    /// Error --- these inventories can be ignored.
    ///
    /// This variant is never produced by decoding. Use [`is_error()`](Self::is_error)
    /// instead to check if a decoded item represents an error.
    ///
    /// When deserializing type 0 inventory items from the wire, they are decoded as
    /// `Unknown { inv_type: 0, .. }` instead. This variant exists for backwards
    /// compatibility in case calling code constructs it directly (e.g.,
    /// `NetworkMessage::Inv(vec![Inventory::Error])`).
    Error,
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
    /// Return the item value represented as a SHA256-d hash.
    ///
    /// This always returns `Some`, never `None` even for the `Error` variant.
    /// The `Option` return type remains for backwards compatibility.
    pub fn network_hash(&self) -> Option<[u8; 32]> {
        match self {
            // The hash of the Error varient is meaningless, but should always be sent.
            Inventory::Error => Some([0; 32]),
            Inventory::Transaction(t) => Some(t.to_byte_array()),
            Inventory::Block(b) => Some(b.to_byte_array()),
            Inventory::CompactBlock(b) => Some(b.to_byte_array()),
            Inventory::WTx(t) => Some(t.to_byte_array()),
            Inventory::WitnessTransaction(t) => Some(t.to_byte_array()),
            Inventory::WitnessBlock(b) => Some(b.to_byte_array()),
            Inventory::Unknown { hash, .. } => Some(*hash),
        }
    }

    /// Returns true if this is an Error inventory item (type 0).
    ///
    /// Error items are internally represented as `Unknown { inv_type: 0, .. }`
    /// to enable symmetric encoding/decoding while maintaining backwards compatibility.
    pub fn is_error(&self) -> bool {
        matches!(self, Inventory::Error | Inventory::Unknown { inv_type: 0, .. })
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
            Inventory::Error => encode_inv!(0, sha256d::Hash::all_zeros()),
            Inventory::Transaction(ref t) => encode_inv!(1, t),
            Inventory::Block(ref b) => encode_inv!(2, b),
            Inventory::CompactBlock(ref b) => encode_inv!(4, b),
            Inventory::WTx(w) => encode_inv!(5, w),
            Inventory::WitnessTransaction(ref t) => encode_inv!(0x40000001, t),
            Inventory::WitnessBlock(ref b) => encode_inv!(0x40000002, b),
            Inventory::Unknown { inv_type: t, hash: ref d } => encode_inv!(t, d),
        })
    }
}

impl Decodable for Inventory {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let inv_type: u32 = Decodable::consensus_decode(r)?;
        Ok(match inv_type {
            0 => Inventory::Unknown { inv_type: 0, hash: Decodable::consensus_decode(r)? },
            1 => Inventory::Transaction(Decodable::consensus_decode(r)?),
            2 => Inventory::Block(Decodable::consensus_decode(r)?),
            4 => Inventory::CompactBlock(Decodable::consensus_decode(r)?),
            5 => Inventory::WTx(Decodable::consensus_decode(r)?),
            0x40000001 => Inventory::WitnessTransaction(Decodable::consensus_decode(r)?),
            0x40000002 => Inventory::WitnessBlock(Decodable::consensus_decode(r)?),
            tp => Inventory::Unknown { inv_type: tp, hash: Decodable::consensus_decode(r)? },
        })
    }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Inventory`] type.
    #[derive(Debug, Clone)]
    pub struct InventoryEncoder<'e>(Encoder2<ArrayEncoder<4>, ArrayEncoder<32>>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Inventory {
    type Encoder<'e> = InventoryEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        let (prefix, bytes) = match *self {
            Self::Error => (0, sha256d::Hash::all_zeros().to_byte_array()),
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

#[cfg(feature = "encoding")]
type InventoryInnerDecoder = Decoder2<ArrayDecoder<4>, ArrayDecoder<32>>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`Inventory`] type.
    #[derive(Debug, Default, Clone)]
    pub struct InventoryDecoder(InventoryInnerDecoder);

    fn end(
        result: Result<([u8; 4], [u8; 32]), <InventoryInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Inventory, InventoryDecoderError> {
        let (ty, inv) = result.map_err(InventoryDecoderError)?;
        let inv_type = u32::from_le_bytes(ty);
        Ok(match inv_type {
            0 => Self::Output::Unknown { inv_type: 0, hash: inv },
            1 => Self::Output::Transaction(Txid::from_byte_array(inv)),
            2 => Self::Output::Block(BlockHash::from_byte_array(inv)),
            4 => Self::Output::CompactBlock(BlockHash::from_byte_array(inv)),
            5 => Self::Output::WTx(Wtxid::from_byte_array(inv)),
            0x4000_0001 => Self::Output::WitnessTransaction(Txid::from_byte_array(inv)),
            0x4000_0002 => Self::Output::WitnessBlock(BlockHash::from_byte_array(inv)),
            tp => Self::Output::Unknown { inv_type: tp, hash: inv },
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Inventory {
    type Decoder = InventoryDecoder;
}

/// An error consensus decoding an [`Inventory`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDecoderError(
    pub(crate) <InventoryInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for InventoryDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl core::fmt::Display for InventoryDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_err!(f, "inventory error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for InventoryDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

// Some simple messages

/// The `getblocks` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetBlocksMessage {
    /// The protocol version
    pub version: u32,
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
    pub version: u32,
    /// Locator hashes --- ordered newest to oldest. The remote peer will
    /// reply with its longest known chain, starting from a locator hash
    /// if possible and block 1 otherwise.
    pub locator_hashes: Vec<BlockHash>,
    /// References the header to stop at, or zero to just fetch the maximum 2000 headers
    pub stop_hash: BlockHash,
}

impl GetBlocksMessage {
    /// Construct a new `getblocks` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetBlocksMessage {
        GetBlocksMessage { version: p2p::PROTOCOL_VERSION, locator_hashes, stop_hash }
    }
}

impl_consensus_encoding!(GetBlocksMessage, version, locator_hashes, stop_hash);

impl GetHeadersMessage {
    /// Construct a new `getheaders` message
    pub fn new(locator_hashes: Vec<BlockHash>, stop_hash: BlockHash) -> GetHeadersMessage {
        GetHeadersMessage { version: p2p::PROTOCOL_VERSION, locator_hashes, stop_hash }
    }
}

impl_consensus_encoding!(GetHeadersMessage, version, locator_hashes, stop_hash);

#[cfg(feature = "encoding")]
type GetBlocksOrHeadersInnerEncoder<'e> =
    Encoder3<ArrayEncoder<4>, PrefixedSliceEncoder<'e, BlockHash>, BlockHashEncoder<'e>>;

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for [`GetBlocksMessage`].
    #[derive(Debug, Clone)]
    pub struct GetBlocksEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for [`GetHeadersMessage`].
    #[derive(Debug, Clone)]
    pub struct GetHeadersEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

#[cfg(feature = "encoding")]
impl encoding::Encode for GetHeadersMessage {
    type Encoder<'e> = GetHeadersEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetHeadersEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            PrefixedSliceEncoder::new(&self.locator_hashes),
            self.stop_hash.encoder(),
        ))
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for GetBlocksMessage {
    type Encoder<'e> = GetBlocksEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetBlocksEncoder::new(Encoder3::new(
            ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
            PrefixedSliceEncoder::new(&self.locator_hashes),
            self.stop_hash.encoder(),
        ))
    }
}

#[cfg(feature = "encoding")]
type GetBlocksOrHeadersInnerDecoder =
    Decoder3<ArrayDecoder<4>, VecDecoder<BlockHash>, BlockHashDecoder>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for [`GetBlocksMessage`].
    #[derive(Debug, Default, Clone)]
    pub struct GetBlocksMessageDecoder(GetBlocksOrHeadersInnerDecoder);

    fn end(
        result: Result<([u8; 4], Vec<BlockHash>, BlockHash), <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetBlocksMessage, GetBlocksMessageDecoderError> {
        let (version, locator_hashes, stop_hash) =
            result.map_err(GetBlocksMessageDecoderError)?;
        Ok(GetBlocksMessage { version: u32::from_le_bytes(version), locator_hashes, stop_hash })
    }
}

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// Decoder type for [`GetHeadersMessage`].
    #[derive(Debug, Default, Clone)]
    pub struct GetHeadersMessageDecoder(GetBlocksOrHeadersInnerDecoder);

    fn end(
        result: Result<([u8; 4], Vec<BlockHash>, BlockHash), <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetHeadersMessage, GetHeadersMessageDecoderError> {
        let (version, locator_hashes, stop_hash) =
            result.map_err(GetHeadersMessageDecoderError)?;
        Ok(GetHeadersMessage { version: u32::from_le_bytes(version), locator_hashes, stop_hash })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for GetBlocksMessage {
    type Decoder = GetBlocksMessageDecoder;
}

#[cfg(feature = "encoding")]
impl encoding::Decode for GetHeadersMessage {
    type Decoder = GetHeadersMessageDecoder;
}

/// An error consensus decoding a [`GetBlocksMessage`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocksMessageDecoderError(
    pub(crate) <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for GetBlocksMessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl core::fmt::Display for GetBlocksMessageDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_err!(f, "getblocks decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for GetBlocksMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}


/// An error consensus decoding a [`GetHeadersMessage`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMessageDecoderError(
    pub(crate) <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
);

#[cfg(feature = "encoding")]
impl From<Infallible> for GetHeadersMessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl core::fmt::Display for GetHeadersMessageDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write_err!(f, "getheaders decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for GetHeadersMessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;
    use hex::test_hex_unwrap as hex;

    use super::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn getblocks_message_test() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetBlocksMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Hash::all_zeros());

        assert_eq!(serialize(&real_decode), from_sat);
    }

    #[test]
    fn inventory_error_is_error_test() {
        assert!(Inventory::Error.is_error());
        assert!(Inventory::Unknown { inv_type: 0, hash: [0u8; 32] }.is_error());
        assert!(!Inventory::Unknown { inv_type: 1, hash: [0u8; 32] }.is_error());
    }

    #[test]
    fn getheaders_message_test() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetHeadersMessage, _> = deserialize(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version, 70002);
        assert_eq!(real_decode.locator_hashes.len(), 1);
        assert_eq!(serialize(&real_decode.locator_hashes[0]), genhash);
        assert_eq!(real_decode.stop_hash, Hash::all_zeros());

        assert_eq!(serialize(&real_decode), from_sat);
    }
}
