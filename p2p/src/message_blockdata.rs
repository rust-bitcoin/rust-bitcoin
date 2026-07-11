// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blockdata network messages.
//!
//! This module describes network messages which are used for passing
//! Bitcoin data (blocks and transactions) around.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    ArrayDecoder, ArrayEncoder, Decoder2, Decoder3, Encoder2, Encoder3, PrefixedSliceEncoder,
    VecDecoder,
};
use primitives::block::{BlockHashDecoder, BlockHashEncoder};
use primitives::transaction::{Txid, Wtxid};
use primitives::BlockHash;

use crate::{ProtocolVersion, ProtocolVersionDecoder, ProtocolVersionEncoder};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    BlockLocatorDecoderError, GetBlocksMessageDecoderError, GetHeadersMessageDecoderError,
    InventoryDecoderError,
};

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

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Inventory`] type.
    #[derive(Debug, Clone)]
    pub struct InventoryEncoder<'e>(Encoder2<ArrayEncoder<4>, ArrayEncoder<32>>);
}

impl encoding::Encode for Inventory {
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
}

impl encoding::Decode for Inventory {
    type Decoder = InventoryDecoder;
}

/// A block locator.
///
/// Maximum number of hashes in a block locator, matching Bitcoin Core's `MAX_LOCATOR_SZ`.
pub const MAX_LOCATOR_HASHES: usize = 101;

/// An ordered list of block hashes from newest to oldest. Used in `getblocks` and
/// `getheaders` messages to help a peer find the most recent common block.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct BlockLocator(Vec<BlockHash>);

impl BlockLocator {
    /// Returns the locator hashes, ordered newest to oldest.
    pub fn hashes(&self) -> &[BlockHash] { &self.0 }

    /// Constructs a block locator for the given chain tip.
    ///
    /// `get_ancestor(h)` must return the block hash at height `h` on the best chain.
    ///
    /// # Errors
    ///
    /// Returns an error if `get_ancestor` returns an error.
    pub fn build<F, E>(tip_height: u32, mut get_ancestor: F) -> Result<Self, E>
    where
        F: FnMut(u32) -> Result<BlockHash, E>,
    {
        let mut hashes = Vec::with_capacity(MAX_LOCATOR_HASHES);
        let mut step: u32 = 1;
        let mut height = tip_height;

        loop {
            hashes.push(get_ancestor(height)?);
            if height == 0 || hashes.len() >= MAX_LOCATOR_HASHES {
                break;
            }
            height = height.saturating_sub(step);
            if hashes.len() > 10 {
                step = step.saturating_mul(2);
            }
        }

        Ok(Self(hashes))
    }
}

impl From<Vec<BlockHash>> for BlockLocator {
    fn from(hashes: Vec<BlockHash>) -> Self { Self(hashes) }
}

impl From<BlockLocator> for Vec<BlockHash> {
    fn from(locator: BlockLocator) -> Self { locator.0 }
}

type BlockLocatorInnerEncoder<'e> = PrefixedSliceEncoder<'e, BlockHash>;

encoding::encoder_newtype! {
    /// The encoder for [`BlockLocator`].
    #[derive(Debug, Clone)]
    pub struct BlockLocatorEncoder<'e>(BlockLocatorInnerEncoder<'e>);
}

impl encoding::Encode for BlockLocator {
    type Encoder<'e> = BlockLocatorEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        BlockLocatorEncoder::new(PrefixedSliceEncoder::new(&self.0))
    }
}

type BlockLocatorInnerDecoder = VecDecoder<BlockHash>;

crate::decoder_newtype! {
    /// The decoder for the [`BlockLocator`] type.
    #[derive(Debug, Clone)]
    pub struct BlockLocatorDecoder(BlockLocatorInnerDecoder);

    /// Creates a new decoder.
    pub fn new() -> Self { Self(VecDecoder::<BlockHash>::new()) }

    fn end(
        result: Result<Vec<BlockHash>, <BlockLocatorInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<BlockLocator, BlockLocatorDecoderError> {
        result.map(BlockLocator).map_err(BlockLocatorDecoderError)
    }
}

impl encoding::Decode for BlockLocator {
    type Decoder = BlockLocatorDecoder;
}

// Some simple messages

/// The `getblocks` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetBlocksMessage {
    /// The protocol version
    pub version: ProtocolVersion,
    /// Block locator --- ordered newest to oldest.
    pub locator_hashes: BlockLocator,
    /// References the block to stop at, or zero to just fetch the maximum 500 blocks
    pub stop_hash: BlockHash,
}

/// The `getheaders` message
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetHeadersMessage {
    /// The protocol version
    pub version: ProtocolVersion,
    /// Block locator --- ordered newest to oldest.
    pub locator_hashes: BlockLocator,
    /// References the header to stop at, or zero to just fetch the maximum 2000 headers
    pub stop_hash: BlockHash,
}

type GetBlocksOrHeadersInnerEncoder<'e> =
    Encoder3<ProtocolVersionEncoder<'e>, BlockLocatorEncoder<'e>, BlockHashEncoder<'e>>;

encoding::encoder_newtype! {
    /// The encoder for [`GetBlocksMessage`].
    #[derive(Debug, Clone)]
    pub struct GetBlocksEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

encoding::encoder_newtype! {
    /// The encoder for [`GetHeadersMessage`].
    #[derive(Debug, Clone)]
    pub struct GetHeadersEncoder<'e>(GetBlocksOrHeadersInnerEncoder<'e>);
}

impl encoding::Encode for GetHeadersMessage {
    type Encoder<'e>
        = GetHeadersEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetHeadersEncoder::new(Encoder3::new(
            self.version.encoder(),
            self.locator_hashes.encoder(),
            self.stop_hash.encoder(),
        ))
    }
}

impl encoding::Encode for GetBlocksMessage {
    type Encoder<'e>
        = GetBlocksEncoder<'e>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        GetBlocksEncoder::new(Encoder3::new(
            self.version.encoder(),
            self.locator_hashes.encoder(),
            self.stop_hash.encoder(),
        ))
    }
}

type GetBlocksOrHeadersInnerDecoder =
    Decoder3<ProtocolVersionDecoder, BlockLocatorDecoder, BlockHashDecoder>;

crate::decoder_newtype! {
    /// Decoder type for [`GetBlocksMessage`].
    #[derive(Debug, Default, Clone)]
    pub struct GetBlocksMessageDecoder(GetBlocksOrHeadersInnerDecoder);

    fn end(
        result: Result<(ProtocolVersion, BlockLocator, BlockHash), <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetBlocksMessage, GetBlocksMessageDecoderError> {
        let (version, locator_hashes, stop_hash) =
            result.map_err(GetBlocksMessageDecoderError)?;
        Ok(GetBlocksMessage { version, locator_hashes, stop_hash })
    }
}

crate::decoder_newtype! {
    /// Decoder type for [`GetHeadersMessage`].
    #[derive(Debug, Default, Clone)]
    pub struct GetHeadersMessageDecoder(GetBlocksOrHeadersInnerDecoder);

    fn end(
        result: Result<(ProtocolVersion, BlockLocator, BlockHash), <GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<GetHeadersMessage, GetHeadersMessageDecoderError> {
        let (version, locator_hashes, stop_hash) =
            result.map_err(GetHeadersMessageDecoderError)?;
        Ok(GetHeadersMessage { version, locator_hashes, stop_hash })
    }
}

impl encoding::Decode for GetBlocksMessage {
    type Decoder = GetBlocksMessageDecoder;
}

impl encoding::Decode for GetHeadersMessage {
    type Decoder = GetHeadersMessageDecoder;
}

/// Error types for blockdata messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// An error consensus decoding an [`Inventory`].
    ///
    /// [`Inventory`]: super::Inventory
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InventoryDecoderError(
        pub(super) <super::InventoryInnerDecoder as encoding::Decoder>::Error,
    );

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

    /// An error consensus decoding a [`BlockLocator`].
    ///
    /// [`BlockLocator`]: super::BlockLocator
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BlockLocatorDecoderError(
        pub(super) <super::BlockLocatorInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for BlockLocatorDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for BlockLocatorDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "block locator error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for BlockLocatorDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error consensus decoding a [`GetBlocksMessage`].
    ///
    /// [`GetBlocksMessage`]: super::GetBlocksMessage
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GetBlocksMessageDecoderError(
        pub(super) <super::GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
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
    ///
    /// [`GetHeadersMessage`]: super::GetHeadersMessage
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GetHeadersMessageDecoderError(
        pub(super) <super::GetBlocksOrHeadersInnerDecoder as encoding::Decoder>::Error,
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
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockLocator {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from(Vec::<BlockHash>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetHeadersMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: u.arbitrary()?,
            locator_hashes: u.arbitrary()?,
            stop_hash: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for GetBlocksMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            version: u.arbitrary()?,
            locator_hashes: u.arbitrary()?,
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
    use hex::hex;

    use super::*;

    #[test]
    fn getblocks_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetBlocksMessage, _> = encoding::decode_from_slice(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.hashes().len(), 1);
        assert_eq!(encoding::encode_to_vec(&real_decode.locator_hashes.hashes()[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(encoding::encode_to_vec(&real_decode), from_sat);
    }

    #[test]
    fn getheaders_message() {
        let from_sat = hex!("72110100014a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b0000000000000000000000000000000000000000000000000000000000000000");
        let genhash = hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        let decode: Result<GetHeadersMessage, _> = encoding::decode_from_slice(&from_sat);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.version.0, 70002);
        assert_eq!(real_decode.locator_hashes.hashes().len(), 1);
        assert_eq!(encoding::encode_to_vec(&real_decode.locator_hashes.hashes()[0]), genhash);
        assert_eq!(real_decode.stop_hash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);

        assert_eq!(encoding::encode_to_vec(&real_decode), from_sat);
    }
}
