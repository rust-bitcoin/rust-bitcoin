// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network messages.
//!
//! This module defines the `NetworkMessage` and `V1NetworkMessage` types that
//! are used for (de)serializing Bitcoin objects for transmission on the network.

use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::{cmp, fmt, mem};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::encode::{self, Decodable, Encodable, ReadExt, WriteExt};
use encoding::{
    self, ArrayDecoder, ArrayEncoder, BytesEncoder, CompactSizeEncoder, Decoder2, Encoder2,
    SliceEncoder, VecDecoder,
};
use hashes::{sha256d, HashEngine};
use internals::ToU64 as _;
use io::{self, BufRead, Read, Write};
use primitives::block::{self, HeaderDecoder, HeaderEncoder};
use primitives::transaction;
use units::FeeRate;

use self::error::V1NetworkMessageDecoderErrorInner;
use crate::address::{AddrV1Message, AddrV2Message};
use crate::consensus::{impl_consensus_encoding, impl_vec_wrapper};
use crate::merkle_tree::MerkleBlock;
use crate::{
    bip152, message_blockdata, message_bloom, message_compact_blocks, message_filter,
    message_network, Magic,
};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    AddrPayloadDecoderError, AddrV2PayloadDecoderError, CommandStringDecoderError,
    CommandStringError, HeadersMessageDecoderError, InventoryPayloadDecoderError,
    NetworkHeaderDecoderError, PingDecoderError, PongDecoderError,
    V1MessageHeaderDecoderError, V1NetworkMessageDecoderError, V2NetworkMessageDecoderError
};

/// The maximum number of [`super::message_blockdata::Inventory`] items in an `inv` message.
///
/// This limit is not currently enforced by this implementation.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum size, in bytes, of an encoded message
/// This by necessity should be larger than `MAX_VEC_SIZE`
pub const MAX_MSG_SIZE: usize = 5_000_000;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl CommandString {
    /// Converts `&'static str` to `CommandString`
    ///
    /// This is more efficient for string literals than non-static conversions because it avoids
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if, and only if, the string is
    /// larger than 12 characters in length.
    pub fn try_from_static(s: &'static str) -> Result<Self, CommandStringError> {
        Self::try_from_static_cow(s.into())
    }

    fn try_from_static_cow(cow: Cow<'static, str>) -> Result<Self, CommandStringError> {
        if cow.len() > 12 {
            Err(CommandStringError { cow })
        } else {
            Ok(Self(cow))
        }
    }
}

impl TryFrom<String> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.into())
    }
}

impl TryFrom<Box<str>> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(String::from(value).into())
    }
}

impl<'a> TryFrom<&'a str> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.to_owned().into())
    }
}

impl core::str::FromStr for CommandString {
    type Err = CommandStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_static_cow(s.to_owned().into())
    }
}

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str(self.0.as_ref()) }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str { self.0.as_ref() }
}

impl Encodable for CommandString {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        debug_assert!(strbytes.len() <= 12);
        rawbytes[..strbytes.len()].copy_from_slice(strbytes);
        rawbytes.consensus_encode(w)
    }
}

impl Decodable for CommandString {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(r)?;

        // Find the last non-null byte and trim null padding from the end
        let trimmed = &rawbytes[..rawbytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)];

        if !trimmed.is_ascii() {
            return Err(crate::consensus::parse_failed_error("Command string must be ASCII"));
        }

        Ok(Self(Cow::Owned(unsafe { String::from_utf8_unchecked(trimmed.to_vec()) })))
    }
}

impl encoding::Encode for CommandString {
    type Encoder<'e> = CommandStringEncoder;

    fn encoder(&self) -> Self::Encoder<'_> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        debug_assert!(strbytes.len() <= 12);
        rawbytes[..strbytes.len()].copy_from_slice(strbytes);
        CommandStringEncoder::without_length_prefix(rawbytes)
    }
}

impl encoding::Decode for CommandString {
    type Decoder = CommandStringDecoder;

    fn decoder() -> Self::Decoder { CommandStringDecoder { inner: encoding::ArrayDecoder::new() } }
}

/// Encoder for the [`CommandString`] type
// We can't use the [`encoder_newtype!`] macro due to the lifetime conflicting
// when constructing the encoder in `V1NetworkMessage`.
#[derive(Debug, Clone)]
pub struct CommandStringEncoder(encoding::ArrayEncoder<12>);

impl CommandStringEncoder {
    /// Constructs an encoder which encodes the command string with no length prefix.
    pub const fn without_length_prefix(arr: [u8; 12]) -> Self {
        Self(encoding::ArrayEncoder::without_length_prefix(arr))
    }
}

impl encoding::Encoder for CommandStringEncoder {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    #[inline]
    fn advance(&mut self) -> bool { self.0.advance() }
}

impl encoding::ExactSizeEncoder for CommandStringEncoder {
    #[inline]
    fn len(&self) -> usize { self.0.len() }
}

/// Decoder for [`CommandString`].
#[derive(Debug, Clone)]
pub struct CommandStringDecoder {
    inner: encoding::ArrayDecoder<12>,
}

impl encoding::Decoder for CommandStringDecoder {
    type Output = CommandString;
    type Error = CommandStringDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes).map_err(CommandStringDecoderError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let rawbytes = self.inner.end().map_err(CommandStringDecoderError::UnexpectedEof)?;
        // Trim null padding from the end.
        let trimmed =
            rawbytes.iter().rposition(|&b| b != 0).map_or(&rawbytes[..0], |i| &rawbytes[..=i]);

        if !trimmed.is_ascii() {
            return Err(CommandStringDecoderError::NotAscii);
        }

        Ok(CommandString(Cow::Owned(unsafe { String::from_utf8_unchecked(trimmed.to_vec()) })))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// A Network message using the v1 p2p protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1NetworkMessage {
    magic: Magic,
    payload: NetworkMessage,
    payload_len: u32,
    checksum: [u8; 4],
}

/// A v1 message header used to describe the incoming payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1MessageHeader {
    /// The network magic, a unique 4 byte sequence.
    pub magic: Magic,
    /// The "command" used to describe the payload.
    pub command: CommandString,
    /// The length of the payload.
    pub length: u32,
    /// A checksum to the aforementioned data.
    pub checksum: [u8; 4],
}

impl encoding::Encode for V1MessageHeader {
    type Encoder<'e>
        = V1MessageHeaderEncoder<'e>
    where
        Self: 'e;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> {
        let enc = encoding::Encoder4::new(
            self.magic.encoder(),
            self.command.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.length.to_le_bytes()),
            encoding::ArrayEncoder::without_length_prefix(self.checksum),
        );

        V1MessageHeaderEncoder::new(enc)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`V1MessageHeader`] type.
    #[derive(Debug, Clone)]
    pub struct V1MessageHeaderEncoder<'e>(
        encoding::Encoder4<
            crate::MagicEncoder<'e>,
            CommandStringEncoder,
            encoding::ArrayEncoder<4>,
            encoding::ArrayEncoder<4>
    >);
}

type V1MessageHeaderInnerDecoder = encoding::Decoder4<
    encoding::ArrayDecoder<4>,
    CommandStringDecoder,
    encoding::ArrayDecoder<4>,
    encoding::ArrayDecoder<4>,
>;

/// The Decoder for `V1MessageHeader`
#[derive(Debug, Clone)]
pub struct V1MessageHeaderDecoder(V1MessageHeaderInnerDecoder);

impl encoding::Decoder for V1MessageHeaderDecoder {
    type Output = V1MessageHeader;
    type Error = V1MessageHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(V1MessageHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (magic, command, length, checksum) =
            self.0.end().map_err(V1MessageHeaderDecoderError)?;
        Ok(V1MessageHeader {
            magic: Magic(magic),
            command,
            length: u32::from_le_bytes(length),
            checksum,
        })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for V1MessageHeader {
    type Decoder = V1MessageHeaderDecoder;
    fn decoder() -> Self::Decoder {
        V1MessageHeaderDecoder(encoding::Decoder4::new(
            encoding::ArrayDecoder::<4>::new(),
            CommandString::decoder(),
            encoding::ArrayDecoder::<4>::new(),
            encoding::ArrayDecoder::<4>::new(),
        ))
    }
}

impl_consensus_encoding!(V1MessageHeader, magic, command, length, checksum);

/// A Network message using the v2 p2p protocol defined in BIP-0324.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2NetworkMessage {
    payload: NetworkMessage,
}

/// A list of inventory items.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InventoryPayload(pub Vec<message_blockdata::Inventory>);

encoding::encoder_newtype! {
    /// The encoder for an [`InventoryPayload`].
    #[derive(Debug, Clone)]
    pub struct InventoryPayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, message_blockdata::Inventory>>);
}

impl encoding::Encode for InventoryPayload {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, SliceEncoder<'e, message_blockdata::Inventory>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        )
    }
}

type InventoryInnerDecoder = VecDecoder<message_blockdata::Inventory>;

/// Decoder type for [`InventoryPayload`].
#[derive(Debug, Clone)]
pub struct InventoryPayloadDecoder(InventoryInnerDecoder);

impl encoding::Decoder for InventoryPayloadDecoder {
    type Output = InventoryPayload;
    type Error = InventoryPayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(InventoryPayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(InventoryPayload(self.0.end().map_err(InventoryPayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for InventoryPayload {
    type Decoder = InventoryPayloadDecoder;
    fn decoder() -> Self::Decoder {
        InventoryPayloadDecoder(VecDecoder::<message_blockdata::Inventory>::new())
    }
}

/// A list of legacy p2p address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrPayload(pub Vec<AddrV1Message>);

encoding::encoder_newtype! {
    /// The encoder for an [`AddrPayload`].
    #[derive(Debug, Clone)]
    pub struct AddrPayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV1Message>>);
}

impl encoding::Encode for AddrPayload {
    type Encoder<'e> = AddrPayloadEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AddrPayloadEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        ))
    }
}

type AddrPayloadInnerDecoder = VecDecoder<AddrV1Message>;

/// Decoder type for [`AddrPayload`].
#[derive(Debug, Clone)]
pub struct AddrPayloadDecoder(AddrPayloadInnerDecoder);

impl encoding::Decoder for AddrPayloadDecoder {
    type Output = AddrPayload;
    type Error = AddrPayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrPayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(AddrPayload(self.0.end().map_err(AddrPayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for AddrPayload {
    type Decoder = AddrPayloadDecoder;
    fn decoder() -> Self::Decoder { AddrPayloadDecoder(VecDecoder::new()) }
}

/// A list of v2 address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrV2Payload(pub Vec<AddrV2Message>);

encoding::encoder_newtype! {
    /// The encoder for an [`AddrV2Payload`].
    #[derive(Debug, Clone)]
    pub struct AddrV2PayloadEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV2Message>>);
}

impl encoding::Encode for AddrV2Payload {
    type Encoder<'e>
        = Encoder2<CompactSizeEncoder, SliceEncoder<'e, AddrV2Message>>
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        )
    }
}

type AddrV2PayloadInnerDecoder = VecDecoder<AddrV2Message>;

/// Decoder type for [`AddrV2Payload`].
#[derive(Debug, Clone)]
pub struct AddrV2PayloadDecoder(AddrV2PayloadInnerDecoder);

impl encoding::Decoder for AddrV2PayloadDecoder {
    type Output = AddrV2Payload;
    type Error = AddrV2PayloadDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrV2PayloadDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        Ok(AddrV2Payload(self.0.end().map_err(AddrV2PayloadDecoderError)?))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for AddrV2Payload {
    type Decoder = AddrV2PayloadDecoder;
    fn decoder() -> Self::Decoder { AddrV2PayloadDecoder(VecDecoder::new()) }
}

impl_vec_wrapper!(InventoryPayload, message_blockdata::Inventory);
impl_vec_wrapper!(AddrPayload, AddrV1Message);
impl_vec_wrapper!(AddrV2Payload, AddrV2Message);

/// The `feefilter` message, wrapper around [`FeeRate`] for P2P wire format encoding.
///
/// This message is used to inform peers about the minimum fee rate for transactions
/// that should be relayed which is defined in [BIP-0133].
///
/// [BIP-0133]: <https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki>
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeeFilter(FeeRate);

impl FeeFilter {
    /// Constructs a new `FeeFilter` from a [`FeeRate`].
    pub const fn new(fee_rate: FeeRate) -> Self { Self(fee_rate) }

    /// Returns the inner [`FeeRate`].
    pub const fn fee_rate(self) -> FeeRate { self.0 }
}

impl From<FeeRate> for FeeFilter {
    fn from(fee_rate: FeeRate) -> Self { Self(fee_rate) }
}

impl From<FeeFilter> for FeeRate {
    fn from(filter: FeeFilter) -> Self { filter.0 }
}

impl bitcoin::consensus::encode::Encodable for FeeFilter {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        use encoding::Encoder;
        let mut encoder = encoding::Encode::encoder(self);
        loop {
            w.write_all(encoder.current_chunk())?;
            if !encoder.advance() {
                break;
            }
        }
        Ok(8)
    }
}

impl bitcoin::consensus::encode::Decodable for FeeFilter {
    fn consensus_decode<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        use encoding::Decoder;

        let mut decoder = <Self as encoding::Decode>::decoder();
        let mut buffer = [0u8; 8];

        r.read_exact(&mut buffer)?;

        let mut slice = &buffer[..];
        decoder.push_bytes(&mut slice).map_err(|_| {
            bitcoin::consensus::encode::Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "insufficient data for FeeFilter",
            ))
        })?;

        decoder.end().map_err(|_| {
            bitcoin::consensus::encode::Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "insufficient data for FeeFilter",
            ))
        })
    }
}

encoding::encoder_newtype_exact! {
    /// Encoder for [`FeeFilter`] type.
    #[derive(Debug, Clone)]
    pub struct FeeFilterEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encode for FeeFilter {
    type Encoder<'e> = FeeFilterEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        // Encode as sat/kvB in little-endian (BIP 133 wire format).
        let kvb = self.0.to_sat_per_kvb_ceil();
        FeeFilterEncoder::new(encoding::ArrayEncoder::without_length_prefix(kvb.to_le_bytes()))
    }
}

/// Decoder for [`FeeFilter`] type.
#[derive(Debug, Clone)]
pub struct FeeFilterDecoder(encoding::ArrayDecoder<8>);

impl FeeFilterDecoder {
    /// Constructs a new [`FeeFilter`] decoder.
    pub fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

impl Default for FeeFilterDecoder {
    fn default() -> Self { Self::new() }
}

impl encoding::Decoder for FeeFilterDecoder {
    type Output = FeeFilter;
    type Error = encoding::UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let array = self.0.end()?;
        let kvb = u64::from_le_bytes(array);

        // BIP-0133 specifies feefilter as int64_t (signed), but negative values and values
        // exceeding u32::MAX are invalid for fee rates. We saturate both cases to FeeRate::MAX.
        let fee_rate = kvb.try_into().ok().map_or(FeeRate::MAX, FeeRate::from_sat_per_kvb);

        Ok(FeeFilter(fee_rate))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for FeeFilter {
    type Decoder = FeeFilterDecoder;

    fn decoder() -> Self::Decoder { FeeFilterDecoder::new() }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FeeFilter {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=3)?;
        match choice {
            0 => Ok(Self(FeeRate::MIN)),
            1 => Ok(Self(FeeRate::BROADCAST_MIN)),
            2 => Ok(Self(FeeRate::DUST)),
            _ => Ok(Self(FeeRate::from_sat_per_kvb(u.int_in_range(0..=u32::MAX)?))),
        }
    }
}

/// Serializer for Ping
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ping(u64);

impl Ping {
    /// Constructs a new [`Ping`] message from nonce.
    pub fn new(nonce: u64) -> Self { Self(nonce) }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Ping`] type.
    #[derive(Debug, Clone)]
    pub struct PingEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encode for Ping {
    type Encoder<'e>
        = PingEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        let nonce = encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes());
        PingEncoder::new(nonce)
    }
}

/// The Decoder for [`Ping`]
#[derive(Debug, Clone)]
pub struct PingDecoder(encoding::ArrayDecoder<8>);

impl encoding::Decoder for PingDecoder {
    type Output = Ping;
    type Error = PingDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(PingDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let nonce = self.0.end().map_err(PingDecoderError)?;
        Ok(Ping(u64::from_le_bytes(nonce)))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for Ping {
    type Decoder = PingDecoder;
    fn decoder() -> Self::Decoder { PingDecoder(encoding::ArrayDecoder::<8>::new()) }
}

/// Serializer for Pong
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pong(u64);

impl Pong {
    /// Construct a response [`Pong`] given a received [`Ping`].
    pub fn from_ping(ping: &Ping) -> Self {
        let nonce = ping.0;
        Self(nonce)
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Pong`] type.
    #[derive(Debug, Clone)]
    pub struct PongEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encode for Pong {
    type Encoder<'e>
        = PongEncoder<'e>
    where
        Self: 'e;
    fn encoder(&self) -> Self::Encoder<'_> {
        let nonce = encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes());
        PongEncoder::new(nonce)
    }
}

/// The Decoder for [`Pong`]
#[derive(Debug, Clone)]
pub struct PongDecoder(encoding::ArrayDecoder<8>);

impl encoding::Decoder for PongDecoder {
    type Output = Pong;
    type Error = PongDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(PongDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let nonce = self.0.end().map_err(PongDecoderError)?;
        Ok(Pong(u64::from_le_bytes(nonce)))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for Pong {
    type Decoder = PongDecoder;
    fn decoder() -> Self::Decoder { PongDecoder(encoding::ArrayDecoder::<8>::new()) }
}

/// A Network message payload. Proper documentation is available at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(AddrPayload),
    /// `inv`
    Inv(InventoryPayload),
    /// `getdata`
    GetData(InventoryPayload),
    /// `notfound`
    NotFound(InventoryPayload),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(transaction::Transaction),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(HeadersMessage),
    /// `sendheaders`
    SendHeaders,
    /// `getaddr`
    GetAddr,
    /// `ping`
    Ping(Ping),
    /// `pong`
    Pong(Pong),
    /// `merkleblock`
    MerkleBlock(MerkleBlock),
    /// BIP-0037 `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// BIP-0037 `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// BIP-0037 `filterclear`
    FilterClear,
    /// BIP-0157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP-0157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP-0157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP-0157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP-0157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP-0157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// BIP-0152 sendcmpct
    SendCmpct(message_compact_blocks::SendCmpct),
    /// BIP-0152 cmpctblock
    CmpctBlock(bip152::HeaderAndShortIds),
    /// BIP-0152 getblocktxn
    GetBlockTxn(bip152::BlockTransactionsRequest),
    /// BIP-0152 blocktxn
    BlockTxn(bip152::BlockTransactions),
    /// `alert`
    Alert(message_network::Alert),
    /// `reject`
    Reject(message_network::Reject),
    /// `feefilter`
    FeeFilter(FeeFilter),
    /// `wtxidrelay`
    WtxidRelay,
    /// `addrv2`
    AddrV2(AddrV2Payload),
    /// `sendaddrv2`
    SendAddrV2,

    /// Any other message.
    Unknown {
        /// The command of this message.
        command: CommandString,
        /// The payload of this message.
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        match *self {
            Self::Version(_) => "version",
            Self::Verack => "verack",
            Self::Addr(_) => "addr",
            Self::Inv(_) => "inv",
            Self::GetData(_) => "getdata",
            Self::NotFound(_) => "notfound",
            Self::GetBlocks(_) => "getblocks",
            Self::GetHeaders(_) => "getheaders",
            Self::MemPool => "mempool",
            Self::Tx(_) => "tx",
            Self::Block(_) => "block",
            Self::Headers(_) => "headers",
            Self::SendHeaders => "sendheaders",
            Self::GetAddr => "getaddr",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::MerkleBlock(_) => "merkleblock",
            Self::FilterLoad(_) => "filterload",
            Self::FilterAdd(_) => "filteradd",
            Self::FilterClear => "filterclear",
            Self::GetCFilters(_) => "getcfilters",
            Self::CFilter(_) => "cfilter",
            Self::GetCFHeaders(_) => "getcfheaders",
            Self::CFHeaders(_) => "cfheaders",
            Self::GetCFCheckpt(_) => "getcfcheckpt",
            Self::CFCheckpt(_) => "cfcheckpt",
            Self::SendCmpct(_) => "sendcmpct",
            Self::CmpctBlock(_) => "cmpctblock",
            Self::GetBlockTxn(_) => "getblocktxn",
            Self::BlockTxn(_) => "blocktxn",
            Self::Alert(_) => "alert",
            Self::Reject(_) => "reject",
            Self::FeeFilter(_) => "feefilter",
            Self::WtxidRelay => "wtxidrelay",
            Self::AddrV2(_) => "addrv2",
            Self::SendAddrV2 => "sendaddrv2",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// Returns the `CommandString` for the message command.
    ///
    /// # Panics
    ///
    /// Panics if the command string is invalid (should never happen for valid message types).
    pub fn command(&self) -> CommandString {
        match *self {
            Self::Unknown { command: ref c, .. } => c.clone(),
            _ => CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands"),
        }
    }
}

impl V1NetworkMessage {
    /// Constructs a new [`V1NetworkMessage`]
    ///
    /// # Panics
    ///
    /// Panics if the payload length exceeds `u32::MAX`.
    pub fn new(magic: Magic, payload: NetworkMessage) -> Self {
        let (bytes_hashed, checksum) = sha2_checksum(&payload);
        let payload_len = u32::try_from(bytes_hashed).expect("network message use u32 as length");
        Self { magic, payload, payload_len, checksum }
    }

    /// Consumes the [`V1NetworkMessage`] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage { self.payload }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage { &self.payload }

    /// Magic bytes to identify the network these messages are meant for
    pub fn magic(&self) -> &Magic { &self.magic }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Returns the `CommandString` for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

impl V2NetworkMessage {
    /// Constructs a new [`V2NetworkMessage`].
    pub fn new(payload: NetworkMessage) -> Self { Self { payload } }

    /// Consumes the [`V2NetworkMessage`] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage { self.payload }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage { &self.payload }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [`NetworkMessage::Unknown`],
    /// regardless of the actual command in the unknown message.
    /// Use the [`Self::command`] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Returns the `CommandString` for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

impl Encodable for NetworkMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            Self::Version(ref dat) => dat.consensus_encode(writer),
            Self::Addr(ref dat) => dat.consensus_encode(writer),
            Self::Inv(ref dat) => dat.consensus_encode(writer),
            Self::GetData(ref dat) => dat.consensus_encode(writer),
            Self::NotFound(ref dat) => dat.consensus_encode(writer),
            Self::GetBlocks(ref dat) => dat.consensus_encode(writer),
            Self::GetHeaders(ref dat) => dat.consensus_encode(writer),
            Self::Tx(ref dat) => dat.consensus_encode(writer),
            Self::Block(ref dat) => dat.consensus_encode(writer),
            Self::Headers(ref dat) => dat.consensus_encode(writer),
            Self::Ping(ref dat) => dat.0.consensus_encode(writer),
            Self::Pong(ref dat) => dat.0.consensus_encode(writer),
            Self::MerkleBlock(ref dat) => dat.consensus_encode(writer),
            Self::FilterLoad(ref dat) => dat.consensus_encode(writer),
            Self::FilterAdd(ref dat) => dat.consensus_encode(writer),
            Self::GetCFilters(ref dat) => dat.consensus_encode(writer),
            Self::CFilter(ref dat) => dat.consensus_encode(writer),
            Self::GetCFHeaders(ref dat) => dat.consensus_encode(writer),
            Self::CFHeaders(ref dat) => dat.consensus_encode(writer),
            Self::GetCFCheckpt(ref dat) => dat.consensus_encode(writer),
            Self::CFCheckpt(ref dat) => dat.consensus_encode(writer),
            Self::SendCmpct(ref dat) => dat.consensus_encode(writer),
            Self::CmpctBlock(ref dat) => dat.consensus_encode(writer),
            Self::GetBlockTxn(ref dat) => dat.consensus_encode(writer),
            Self::BlockTxn(ref dat) => dat.consensus_encode(writer),
            Self::Alert(ref dat) => dat.consensus_encode(writer),
            Self::Reject(ref dat) => dat.consensus_encode(writer),
            Self::FeeFilter(ref dat) => dat.consensus_encode(writer),
            Self::AddrV2(ref dat) => dat.consensus_encode(writer),
            Self::Verack
            | Self::SendHeaders
            | Self::MemPool
            | Self::GetAddr
            | Self::WtxidRelay
            | Self::FilterClear
            | Self::SendAddrV2 => Ok(0),
            // Don't use consensus_encode so as not to add a length suffix.
            Self::Unknown { payload: ref data, .. } => writer.write(data),
        }
    }
}

impl encoding::Encode for NetworkMessage {
    type Encoder<'e> = NetworkMessageEncoder<'e>;

    #[inline]
    fn encoder(&self) -> Self::Encoder<'_> { NetworkMessageEncoder::new(self) }
}

impl Encodable for V1NetworkMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(w)?;
        len += self.command().consensus_encode(w)?;
        len += self.payload_len.consensus_encode(w)?;
        len += self.checksum.consensus_encode(w)?;
        len += self.payload().consensus_encode(w)?;
        Ok(len)
    }
}

/// Encoder for [`NetworkMessage`]
#[derive(Debug, Clone)]
pub enum NetworkMessageEncoder<'e> {
    /// Encodes [`NetworkMessage::Version`]
    Version(<message_network::VersionMessage as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Addr`]
    Addr(<AddrPayload as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Inv`]
    Inv(<InventoryPayload as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetData`]
    GetData(<InventoryPayload as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::NotFound`]
    NotFound(<InventoryPayload as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetBlocks`]
    GetBlocks(<message_blockdata::GetBlocksMessage as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetHeaders`]
    GetHeaders(<message_blockdata::GetHeadersMessage as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Tx`]
    Tx(<transaction::Transaction as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Block`]
    Block(<block::Block as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Headers`]
    Headers(<HeadersMessage as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Ping`]
    Ping(<Ping as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Pong`]
    Pong(<Pong as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::MerkleBlock`]
    MerkleBlock(<MerkleBlock as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::FilterLoad`]
    FilterLoad(<message_bloom::FilterLoad as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::FilterAdd`]
    FilterAdd(<message_bloom::FilterAdd as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetCFilters`]
    GetCFilters(<message_filter::GetCFilters as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::CFilter`]
    CFilter(<message_filter::CFilter as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetCFHeaders`]
    GetCFHeaders(<message_filter::GetCFHeaders as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::CFHeaders`]
    CFHeaders(<message_filter::CFHeaders as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetCFCheckpt`]
    GetCFCheckpt(<message_filter::GetCFCheckpt as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::CFCheckpt`]
    CFCheckpt(<message_filter::CFCheckpt as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::SendCmpct`]
    SendCmpct(<message_compact_blocks::SendCmpct as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::CmpctBlock`]
    CmpctBlock(<bip152::HeaderAndShortIds as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::GetBlockTxn`]
    GetBlockTxn(<bip152::BlockTransactionsRequest as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::BlockTxn`]
    BlockTxn(<bip152::BlockTransactions as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Alert`]
    Alert(<message_network::Alert as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::Reject`]
    Reject(<message_network::Reject as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::FeeFilter`]
    FeeFilter(<FeeFilter as encoding::Encode>::Encoder<'e>),
    /// Encodes [`NetworkMessage::AddrV2`]
    AddrV2(<AddrV2Payload as encoding::Encode>::Encoder<'e>),
    /// Encodes zero-payload messages: verack, mempool, sendheaders, getaddr, wtxidrelay,
    /// filterclear, sendaddrv2.
    Empty,
    /// Encodes [`NetworkMessage::Unknown`]; borrows the raw payload bytes directly.
    Unknown(BytesEncoder<'e>),
}

impl<'e> NetworkMessageEncoder<'e> {
    fn new(msg: &'e NetworkMessage) -> Self {
        use encoding::Encode as _;
        match msg {
            NetworkMessage::Version(dat) => Self::Version(dat.encoder()),
            NetworkMessage::Addr(dat) => Self::Addr(dat.encoder()),
            NetworkMessage::Inv(dat) => Self::Inv(dat.encoder()),
            NetworkMessage::GetData(dat) => Self::GetData(dat.encoder()),
            NetworkMessage::NotFound(dat) => Self::NotFound(dat.encoder()),
            NetworkMessage::GetBlocks(dat) => Self::GetBlocks(dat.encoder()),
            NetworkMessage::GetHeaders(dat) => Self::GetHeaders(dat.encoder()),
            NetworkMessage::Tx(dat) => Self::Tx(dat.encoder()),
            NetworkMessage::Block(dat) => Self::Block(dat.encoder()),
            NetworkMessage::Headers(dat) => Self::Headers(dat.encoder()),
            NetworkMessage::Ping(dat) => Self::Ping(dat.encoder()),
            NetworkMessage::Pong(dat) => Self::Pong(dat.encoder()),
            NetworkMessage::MerkleBlock(dat) => Self::MerkleBlock(dat.encoder()),
            NetworkMessage::FilterLoad(dat) => Self::FilterLoad(dat.encoder()),
            NetworkMessage::FilterAdd(dat) => Self::FilterAdd(dat.encoder()),
            NetworkMessage::GetCFilters(dat) => Self::GetCFilters(dat.encoder()),
            NetworkMessage::CFilter(dat) => Self::CFilter(dat.encoder()),
            NetworkMessage::GetCFHeaders(dat) => Self::GetCFHeaders(dat.encoder()),
            NetworkMessage::CFHeaders(dat) => Self::CFHeaders(dat.encoder()),
            NetworkMessage::GetCFCheckpt(dat) => Self::GetCFCheckpt(dat.encoder()),
            NetworkMessage::CFCheckpt(dat) => Self::CFCheckpt(dat.encoder()),
            NetworkMessage::SendCmpct(dat) => Self::SendCmpct(dat.encoder()),
            NetworkMessage::CmpctBlock(dat) => Self::CmpctBlock(dat.encoder()),
            NetworkMessage::GetBlockTxn(dat) => Self::GetBlockTxn(dat.encoder()),
            NetworkMessage::BlockTxn(dat) => Self::BlockTxn(dat.encoder()),
            NetworkMessage::Alert(dat) => Self::Alert(dat.encoder()),
            NetworkMessage::Reject(dat) => Self::Reject(dat.encoder()),
            NetworkMessage::FeeFilter(dat) => Self::FeeFilter(dat.encoder()),
            NetworkMessage::AddrV2(dat) => Self::AddrV2(dat.encoder()),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => Self::Empty,
            // Don't use encode_to_vec so as not to add a length prefix.
            NetworkMessage::Unknown { payload, .. } =>
                Self::Unknown(BytesEncoder::without_length_prefix(payload)),
        }
    }
}

impl encoding::Encoder for NetworkMessageEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match self {
            Self::Version(e) => e.current_chunk(),
            Self::Addr(e) => e.current_chunk(),
            Self::Inv(e) | Self::GetData(e) | Self::NotFound(e) => e.current_chunk(),
            Self::GetBlocks(e) => e.current_chunk(),
            Self::GetHeaders(e) => e.current_chunk(),
            Self::Tx(e) => e.current_chunk(),
            Self::Block(e) => e.current_chunk(),
            Self::Headers(e) => e.current_chunk(),
            Self::Ping(e) => e.current_chunk(),
            Self::Pong(e) => e.current_chunk(),
            Self::MerkleBlock(e) => e.current_chunk(),
            Self::FilterLoad(e) => e.current_chunk(),
            Self::FilterAdd(e) => e.current_chunk(),
            Self::GetCFilters(e) => e.current_chunk(),
            Self::CFilter(e) => e.current_chunk(),
            Self::GetCFHeaders(e) => e.current_chunk(),
            Self::CFHeaders(e) => e.current_chunk(),
            Self::GetCFCheckpt(e) => e.current_chunk(),
            Self::CFCheckpt(e) => e.current_chunk(),
            Self::SendCmpct(e) => e.current_chunk(),
            Self::CmpctBlock(e) => e.current_chunk(),
            Self::GetBlockTxn(e) => e.current_chunk(),
            Self::BlockTxn(e) => e.current_chunk(),
            Self::Alert(e) => e.current_chunk(),
            Self::Reject(e) => e.current_chunk(),
            Self::FeeFilter(e) => e.current_chunk(),
            Self::AddrV2(e) => e.current_chunk(),
            Self::Empty => &[],
            Self::Unknown(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Self::Version(e) => e.advance(),
            Self::Addr(e) => e.advance(),
            Self::Inv(e) | Self::GetData(e) | Self::NotFound(e) => e.advance(),
            Self::GetBlocks(e) => e.advance(),
            Self::GetHeaders(e) => e.advance(),
            Self::Tx(e) => e.advance(),
            Self::Block(e) => e.advance(),
            Self::Headers(e) => e.advance(),
            Self::Ping(e) => e.advance(),
            Self::Pong(e) => e.advance(),
            Self::MerkleBlock(e) => e.advance(),
            Self::FilterLoad(e) => e.advance(),
            Self::FilterAdd(e) => e.advance(),
            Self::GetCFilters(e) => e.advance(),
            Self::CFilter(e) => e.advance(),
            Self::GetCFHeaders(e) => e.advance(),
            Self::CFHeaders(e) => e.advance(),
            Self::GetCFCheckpt(e) => e.advance(),
            Self::CFCheckpt(e) => e.advance(),
            Self::SendCmpct(e) => e.advance(),
            Self::CmpctBlock(e) => e.advance(),
            Self::GetBlockTxn(e) => e.advance(),
            Self::BlockTxn(e) => e.advance(),
            Self::Alert(e) => e.advance(),
            Self::Reject(e) => e.advance(),
            Self::FeeFilter(e) => e.advance(),
            Self::AddrV2(e) => e.advance(),
            Self::Empty => false,
            Self::Unknown(e) => e.advance(),
        }
    }
}

encoding::encoder_newtype! {
    /// Encoder for [`V1NetworkMessage`].
    #[derive(Debug, Clone)]
    pub struct V1NetworkMessageEncoder<'e>(
        encoding::Encoder2<
            encoding::Encoder4<
                encoding::ArrayEncoder<4>,
                CommandStringEncoder,
                encoding::ArrayEncoder<4>,
                encoding::ArrayEncoder<4>,
            >,
            NetworkMessageEncoder<'e>,
        >
    );
}

impl encoding::Encode for V1NetworkMessage {
    type Encoder<'e> = V1NetworkMessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        V1NetworkMessageEncoder::new(encoding::Encoder2::new(
            encoding::Encoder4::new(
                encoding::ArrayEncoder::without_length_prefix(self.magic.to_bytes()),
                self.command().encoder(),
                encoding::ArrayEncoder::without_length_prefix(self.payload_len.to_le_bytes()),
                encoding::ArrayEncoder::without_length_prefix(self.checksum),
            ),
            NetworkMessageEncoder::new(&self.payload),
        ))
    }
}

#[derive(Debug, Clone)]
enum NetworkMessageDecoder {
    Version(message_network::VersionMessageDecoder),
    Addr(AddrPayloadDecoder),
    Inv(InventoryPayloadDecoder),
    GetData(InventoryPayloadDecoder),
    NotFound(InventoryPayloadDecoder),
    GetBlocks(message_blockdata::GetBlocksMessageDecoder),
    GetHeaders(message_blockdata::GetHeadersMessageDecoder),
    Tx(<transaction::Transaction as encoding::Decode>::Decoder),
    Block(<block::Block as encoding::Decode>::Decoder),
    Headers(HeadersMessageDecoder),
    Ping(PingDecoder),
    Pong(PongDecoder),
    MerkleBlock(<MerkleBlock as encoding::Decode>::Decoder),
    FilterLoad(message_bloom::FilterLoadDecoder),
    FilterAdd(message_bloom::FilterAddDecoder),
    GetCFilters(message_filter::GetCFiltersDecoder),
    CFilter(message_filter::CFilterDecoder),
    GetCFHeaders(message_filter::GetCFHeadersDecoder),
    CFHeaders(message_filter::CFHeadersDecoder),
    GetCFCheckpt(message_filter::GetCFCheckptDecoder),
    CFCheckpt(message_filter::CFCheckptDecoder),
    SendCmpct(message_compact_blocks::SendCmpctDecoder),
    CmpctBlock(<bip152::HeaderAndShortIds as encoding::Decode>::Decoder),
    GetBlockTxn(<bip152::BlockTransactionsRequest as encoding::Decode>::Decoder),
    BlockTxn(<bip152::BlockTransactions as encoding::Decode>::Decoder),
    Alert(message_network::AlertDecoder),
    Reject(message_network::RejectDecoder),
    FeeFilter(FeeFilterDecoder),
    AddrV2(AddrV2PayloadDecoder),
    /// Zero-payload messages: verack, mempool, sendheaders, getaddr, wtxidrelay,
    /// filterclear, sendaddrv2.
    Empty(CommandString),
    /// Unknown message — must buffer since type is unknown at compile time.
    Unknown {
        command: CommandString,
        remaining: usize,
        buffer: Vec<u8>,
    },
}

impl NetworkMessageDecoder {
    fn new(command: CommandString, payload_len: usize) -> Self {
        use encoding::Decode as _;
        match command.as_ref() {
            "version" => Self::Version(message_network::VersionMessage::decoder()),
            "verack" | "sendheaders" | "mempool" | "getaddr" | "wtxidrelay" | "filterclear"
            | "sendaddrv2" => Self::Empty(command),
            "addr" => Self::Addr(AddrPayload::decoder()),
            "inv" => Self::Inv(InventoryPayload::decoder()),
            "getdata" => Self::GetData(InventoryPayload::decoder()),
            "notfound" => Self::NotFound(InventoryPayload::decoder()),
            "getblocks" => Self::GetBlocks(message_blockdata::GetBlocksMessage::decoder()),
            "getheaders" => Self::GetHeaders(message_blockdata::GetHeadersMessage::decoder()),
            "tx" => Self::Tx(transaction::Transaction::decoder()),
            "block" => Self::Block(block::Block::decoder()),
            "headers" => Self::Headers(HeadersMessage::decoder()),
            "ping" => Self::Ping(Ping::decoder()),
            "pong" => Self::Pong(Pong::decoder()),
            "merkleblock" => Self::MerkleBlock(MerkleBlock::decoder()),
            "filterload" => Self::FilterLoad(message_bloom::FilterLoad::decoder()),
            "filteradd" => Self::FilterAdd(message_bloom::FilterAdd::decoder()),
            "getcfilters" => Self::GetCFilters(message_filter::GetCFilters::decoder()),
            "cfilter" => Self::CFilter(message_filter::CFilter::decoder()),
            "getcfheaders" => Self::GetCFHeaders(message_filter::GetCFHeaders::decoder()),
            "cfheaders" => Self::CFHeaders(message_filter::CFHeaders::decoder()),
            "getcfcheckpt" => Self::GetCFCheckpt(message_filter::GetCFCheckpt::decoder()),
            "cfcheckpt" => Self::CFCheckpt(message_filter::CFCheckpt::decoder()),
            "sendcmpct" => Self::SendCmpct(message_compact_blocks::SendCmpct::decoder()),
            "cmpctblock" => Self::CmpctBlock(bip152::HeaderAndShortIds::decoder()),
            "getblocktxn" => Self::GetBlockTxn(bip152::BlockTransactionsRequest::decoder()),
            "blocktxn" => Self::BlockTxn(bip152::BlockTransactions::decoder()),
            "alert" => Self::Alert(message_network::Alert::decoder()),
            "reject" => Self::Reject(message_network::Reject::decoder()),
            "feefilter" => Self::FeeFilter(FeeFilter::decoder()),
            "addrv2" => Self::AddrV2(AddrV2Payload::decoder()),
            _ => Self::Unknown {
                command,
                remaining: payload_len,
                buffer: Vec::with_capacity(payload_len),
            },
        }
    }
}

impl encoding::Decoder for NetworkMessageDecoder {
    type Output = NetworkMessage;
    type Error = V1NetworkMessageDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let err = V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload);
        match self {
            Self::Version(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Addr(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Inv(d) | Self::GetData(d) | Self::NotFound(d) =>
                d.push_bytes(bytes).map_err(|_| err),
            Self::GetBlocks(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::GetHeaders(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Tx(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Block(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Headers(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Ping(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Pong(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::MerkleBlock(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::FilterLoad(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::FilterAdd(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::GetCFilters(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::CFilter(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::GetCFHeaders(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::CFHeaders(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::GetCFCheckpt(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::CFCheckpt(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::SendCmpct(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::CmpctBlock(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::GetBlockTxn(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::BlockTxn(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Alert(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Reject(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::FeeFilter(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::AddrV2(d) => d.push_bytes(bytes).map_err(|_| err),
            Self::Empty(_) => Ok(false),
            Self::Unknown { remaining, buffer, .. } => {
                let copy_len = bytes.len().min(*remaining);
                let (to_copy, rest) = bytes.split_at(copy_len);
                buffer.extend_from_slice(to_copy);
                *bytes = rest;
                *remaining -= copy_len;
                Ok(*remaining > 0)
            }
        }
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let err = V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Payload);
        match self {
            Self::Version(d) => Ok(NetworkMessage::Version(d.end().map_err(|_| err)?)),
            Self::Addr(d) => Ok(NetworkMessage::Addr(d.end().map_err(|_| err)?)),
            Self::Inv(d) => Ok(NetworkMessage::Inv(d.end().map_err(|_| err)?)),
            Self::GetData(d) => Ok(NetworkMessage::GetData(d.end().map_err(|_| err)?)),
            Self::NotFound(d) => Ok(NetworkMessage::NotFound(d.end().map_err(|_| err)?)),
            Self::GetBlocks(d) => Ok(NetworkMessage::GetBlocks(d.end().map_err(|_| err)?)),
            Self::GetHeaders(d) => Ok(NetworkMessage::GetHeaders(d.end().map_err(|_| err)?)),
            Self::Tx(d) => Ok(NetworkMessage::Tx(d.end().map_err(|_| err)?)),
            Self::Block(d) => Ok(NetworkMessage::Block(d.end().map_err(|_| err)?)),
            Self::Headers(d) => Ok(NetworkMessage::Headers(d.end().map_err(|_| err)?)),
            Self::Ping(d) => Ok(NetworkMessage::Ping(d.end().map_err(|_| err)?)),
            Self::Pong(d) => Ok(NetworkMessage::Pong(d.end().map_err(|_| err)?)),
            Self::MerkleBlock(d) => Ok(NetworkMessage::MerkleBlock(d.end().map_err(|_| err)?)),
            Self::FilterLoad(d) => Ok(NetworkMessage::FilterLoad(d.end().map_err(|_| err)?)),
            Self::FilterAdd(d) => Ok(NetworkMessage::FilterAdd(d.end().map_err(|_| err)?)),
            Self::GetCFilters(d) => Ok(NetworkMessage::GetCFilters(d.end().map_err(|_| err)?)),
            Self::CFilter(d) => Ok(NetworkMessage::CFilter(d.end().map_err(|_| err)?)),
            Self::GetCFHeaders(d) => Ok(NetworkMessage::GetCFHeaders(d.end().map_err(|_| err)?)),
            Self::CFHeaders(d) => Ok(NetworkMessage::CFHeaders(d.end().map_err(|_| err)?)),
            Self::GetCFCheckpt(d) => Ok(NetworkMessage::GetCFCheckpt(d.end().map_err(|_| err)?)),
            Self::CFCheckpt(d) => Ok(NetworkMessage::CFCheckpt(d.end().map_err(|_| err)?)),
            Self::SendCmpct(d) => Ok(NetworkMessage::SendCmpct(d.end().map_err(|_| err)?)),
            Self::CmpctBlock(d) => Ok(NetworkMessage::CmpctBlock(d.end().map_err(|_| err)?)),
            Self::GetBlockTxn(d) => Ok(NetworkMessage::GetBlockTxn(d.end().map_err(|_| err)?)),
            Self::BlockTxn(d) => Ok(NetworkMessage::BlockTxn(d.end().map_err(|_| err)?)),
            Self::Alert(d) => Ok(NetworkMessage::Alert(d.end().map_err(|_| err)?)),
            Self::Reject(d) => Ok(NetworkMessage::Reject(d.end().map_err(|_| err)?)),
            Self::FeeFilter(d) => Ok(NetworkMessage::FeeFilter(d.end().map_err(|_| err)?)),
            Self::AddrV2(d) => Ok(NetworkMessage::AddrV2(d.end().map_err(|_| err)?)),
            Self::Empty(cmd) => match cmd.as_ref() {
                "verack" => Ok(NetworkMessage::Verack),
                "mempool" => Ok(NetworkMessage::MemPool),
                "sendheaders" => Ok(NetworkMessage::SendHeaders),
                "getaddr" => Ok(NetworkMessage::GetAddr),
                "wtxidrelay" => Ok(NetworkMessage::WtxidRelay),
                "filterclear" => Ok(NetworkMessage::FilterClear),
                "sendaddrv2" => Ok(NetworkMessage::SendAddrV2),
                _ => Err(err),
            },
            Self::Unknown { command, buffer, remaining } => {
                if remaining != 0 {
                    return Err(err);
                }
                Ok(NetworkMessage::Unknown { command, payload: buffer })
            }
        }
    }

    #[inline]
    fn read_limit(&self) -> usize {
        match self {
            Self::Version(d) => d.read_limit(),
            Self::Addr(d) => d.read_limit(),
            Self::Inv(d) | Self::GetData(d) | Self::NotFound(d) => d.read_limit(),
            Self::GetBlocks(d) => d.read_limit(),
            Self::GetHeaders(d) => d.read_limit(),
            Self::Tx(d) => d.read_limit(),
            Self::Block(d) => d.read_limit(),
            Self::Headers(d) => d.read_limit(),
            Self::Ping(d) => d.read_limit(),
            Self::Pong(d) => d.read_limit(),
            Self::MerkleBlock(d) => d.read_limit(),
            Self::FilterLoad(d) => d.read_limit(),
            Self::FilterAdd(d) => d.read_limit(),
            Self::GetCFilters(d) => d.read_limit(),
            Self::CFilter(d) => d.read_limit(),
            Self::GetCFHeaders(d) => d.read_limit(),
            Self::CFHeaders(d) => d.read_limit(),
            Self::GetCFCheckpt(d) => d.read_limit(),
            Self::CFCheckpt(d) => d.read_limit(),
            Self::SendCmpct(d) => d.read_limit(),
            Self::CmpctBlock(d) => d.read_limit(),
            Self::GetBlockTxn(d) => d.read_limit(),
            Self::BlockTxn(d) => d.read_limit(),
            Self::Alert(d) => d.read_limit(),
            Self::Reject(d) => d.read_limit(),
            Self::FeeFilter(d) => d.read_limit(),
            Self::AddrV2(d) => d.read_limit(),
            Self::Empty(_) => 0,
            Self::Unknown { remaining, .. } => *remaining,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum DecoderState {
    ReadingHeader {
        header_decoder: encoding::Decoder4<
            encoding::ArrayDecoder<4>,
            CommandStringDecoder,
            encoding::ArrayDecoder<4>,
            encoding::ArrayDecoder<4>,
        >,
    },
    ReadingPayload {
        magic_bytes: [u8; 4],
        payload_len_bytes: [u8; 4],
        checksum: [u8; 4],
        payload_decoder: NetworkMessageDecoder,
    },
}

/// Decoder for [`V1NetworkMessage`].
///
/// This decoder implements a two-phase decoding process for Bitcoin V1 P2P messages.
/// It first decodes the fixed-sized header. It then uses the payload length information
/// to decode the dynamically sized network message.
#[derive(Debug, Clone)]
pub struct V1NetworkMessageDecoder {
    state: DecoderState,
}

impl encoding::Decoder for V1NetworkMessageDecoder {
    type Output = V1NetworkMessage;
    type Error = V1NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        match &mut self.state {
            DecoderState::ReadingHeader { header_decoder } => {
                let need_more = header_decoder.push_bytes(bytes).map_err(|_| {
                    V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header)
                })?;

                if !need_more {
                    // Header complete, extract values and transition to payload state.
                    let old_state = core::mem::replace(
                        &mut self.state,
                        DecoderState::ReadingHeader {
                            header_decoder: encoding::Decoder4::new(
                                encoding::ArrayDecoder::new(),
                                CommandStringDecoder { inner: encoding::ArrayDecoder::new() },
                                encoding::ArrayDecoder::new(),
                                encoding::ArrayDecoder::new(),
                            ),
                        },
                    );

                    let DecoderState::ReadingHeader { header_decoder } = old_state else {
                        unreachable!("we are in ReadingHeader state")
                    };

                    let (magic_bytes, command, payload_len_bytes, checksum) =
                        header_decoder.end().map_err(|_| {
                            V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header)
                        })?;

                    let payload_len = u32::from_le_bytes(payload_len_bytes) as usize;
                    if payload_len > MAX_MSG_SIZE {
                        return Err(V1NetworkMessageDecoderError(
                            V1NetworkMessageDecoderErrorInner::PayloadTooLarge,
                        ));
                    }

                    let payload_decoder = NetworkMessageDecoder::new(command, payload_len);
                    self.state = DecoderState::ReadingPayload {
                        magic_bytes,
                        payload_len_bytes,
                        checksum,
                        payload_decoder,
                    };

                    // Continue with any remaining bytes.
                    return self.push_bytes(bytes);
                }

                Ok(need_more)
            }
            DecoderState::ReadingPayload { payload_decoder, .. } =>
                payload_decoder.push_bytes(bytes),
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            DecoderState::ReadingHeader { .. } =>
                Err(V1NetworkMessageDecoderError(V1NetworkMessageDecoderErrorInner::Header)),
            DecoderState::ReadingPayload {
                magic_bytes,
                payload_len_bytes,
                checksum,
                payload_decoder,
                ..
            } => {
                let payload = payload_decoder.end()?;
                let (_, expected_checksum) = sha2_checksum(&payload);
                if checksum != expected_checksum {
                    return Err(V1NetworkMessageDecoderError(
                        V1NetworkMessageDecoderErrorInner::InvalidChecksum {
                            expected: expected_checksum,
                            actual: checksum,
                        },
                    ));
                }

                Ok(V1NetworkMessage {
                    magic: Magic::from_bytes(magic_bytes),
                    payload,
                    payload_len: u32::from_le_bytes(payload_len_bytes),
                    checksum,
                })
            }
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            DecoderState::ReadingHeader { header_decoder } => header_decoder.read_limit(),
            DecoderState::ReadingPayload { payload_decoder, .. } => payload_decoder.read_limit(),
        }
    }
}

impl encoding::Decode for V1NetworkMessage {
    type Decoder = V1NetworkMessageDecoder;

    fn decoder() -> Self::Decoder {
        V1NetworkMessageDecoder {
            state: DecoderState::ReadingHeader {
                header_decoder: encoding::Decoder4::new(
                    encoding::ArrayDecoder::new(),
                    CommandStringDecoder { inner: encoding::ArrayDecoder::new() },
                    encoding::ArrayDecoder::new(),
                    encoding::ArrayDecoder::new(),
                ),
            },
        }
    }
}

/// Encoder for [`V2NetworkMessage`].
///
/// V2 messages encode a 1-byte short ID for optimized message types (IDs 1-28),
/// or a 0-byte flag followed by a 12-byte command string for non-optimized types.
#[derive(Clone, Debug)]
pub enum V2NetworkMessageEncoder<'e> {
    /// Optimized message with a 1-byte short ID followed by the payload.
    ShortId(Encoder2<ArrayEncoder<1>, NetworkMessageEncoder<'e>>),
    /// Non-optimized message with a 0-byte flag, 12-byte command, and payload.
    FullCommand(
        Encoder2<ArrayEncoder<1>, Encoder2<CommandStringEncoder, NetworkMessageEncoder<'e>>>,
    ),
}

impl encoding::Encoder for V2NetworkMessageEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match self {
            Self::ShortId(e) => e.current_chunk(),
            Self::FullCommand(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Self::ShortId(e) => e.advance(),
            Self::FullCommand(e) => e.advance(),
        }
    }
}

impl encoding::Encode for V2NetworkMessage {
    type Encoder<'e> = V2NetworkMessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        let (short_id, full_command) = v2_command_byte(&self.payload);
        let payload_encoder = NetworkMessageEncoder::new(&self.payload);

        match full_command {
            Some(cmd) => V2NetworkMessageEncoder::FullCommand(Encoder2::new(
                ArrayEncoder::without_length_prefix([short_id]),
                Encoder2::new(cmd.encoder(), payload_encoder),
            )),
            None => V2NetworkMessageEncoder::ShortId(Encoder2::new(
                ArrayEncoder::without_length_prefix([short_id]),
                payload_encoder,
            )),
        }
    }
}

// Returns the V2 short ID byte and optional full command for a [`NetworkMessage`].
fn v2_command_byte(payload: &NetworkMessage) -> (u8, Option<CommandString>) {
    match payload {
        NetworkMessage::Addr(_) => (1u8, None),
        NetworkMessage::Block(_) => (2u8, None),
        NetworkMessage::BlockTxn(_) => (3u8, None),
        NetworkMessage::CmpctBlock(_) => (4u8, None),
        NetworkMessage::FeeFilter(_) => (5u8, None),
        NetworkMessage::FilterAdd(_) => (6u8, None),
        NetworkMessage::FilterClear => (7u8, None),
        NetworkMessage::FilterLoad(_) => (8u8, None),
        NetworkMessage::GetBlocks(_) => (9u8, None),
        NetworkMessage::GetBlockTxn(_) => (10u8, None),
        NetworkMessage::GetData(_) => (11u8, None),
        NetworkMessage::GetHeaders(_) => (12u8, None),
        NetworkMessage::Headers(_) => (13u8, None),
        NetworkMessage::Inv(_) => (14u8, None),
        NetworkMessage::MemPool => (15u8, None),
        NetworkMessage::MerkleBlock(_) => (16u8, None),
        NetworkMessage::NotFound(_) => (17u8, None),
        NetworkMessage::Ping(_) => (18u8, None),
        NetworkMessage::Pong(_) => (19u8, None),
        NetworkMessage::SendCmpct(_) => (20u8, None),
        NetworkMessage::Tx(_) => (21u8, None),
        NetworkMessage::GetCFilters(_) => (22u8, None),
        NetworkMessage::CFilter(_) => (23u8, None),
        NetworkMessage::GetCFHeaders(_) => (24u8, None),
        NetworkMessage::CFHeaders(_) => (25u8, None),
        NetworkMessage::GetCFCheckpt(_) => (26u8, None),
        NetworkMessage::CFCheckpt(_) => (27u8, None),
        NetworkMessage::AddrV2(_) => (28u8, None),
        NetworkMessage::Version(_)
        | NetworkMessage::Verack
        | NetworkMessage::SendHeaders
        | NetworkMessage::GetAddr
        | NetworkMessage::WtxidRelay
        | NetworkMessage::SendAddrV2
        | NetworkMessage::Alert(_)
        | NetworkMessage::Reject(_)
        | NetworkMessage::Unknown { .. } => (0u8, Some(payload.command())),
    }
}

impl Encodable for V2NetworkMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        // A subset of message types are optimized to only use one byte to encode the command.
        // Non-optimized message types use the zero-byte flag and the following twelve bytes to encode the command.
        let (command_byte, full_command) = v2_command_byte(&self.payload);

        let mut len = command_byte.consensus_encode(writer)?;
        if let Some(cmd) = full_command {
            len += cmd.consensus_encode(writer)?;
        }

        // Encode the payload.
        len += self.payload.consensus_encode(writer)?;

        Ok(len)
    }
}

/// Network encoded [`Header`](primitives::block::Header) with associated byte for the length of
/// transactions that follow, which is currently always zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHeader {
    /// Block header.
    pub header: block::Header,
    /// Length of transaction list.
    pub length: u8,
}

impl NetworkHeader {
    /// Create a new [`NetworkHeader`] from underlying block header.
    pub const fn from_header(header: block::Header) -> Self { Self { header, length: 0 } }
}

encoding::encoder_newtype_exact! {
    /// The encoder type for a [`NetworkHeader`].
    #[derive(Debug, Clone)]
    pub struct NetworkHeaderEncoder<'e>(Encoder2<HeaderEncoder<'e>, ArrayEncoder<1>>);
}

impl encoding::Encode for NetworkHeader {
    type Encoder<'e> = NetworkHeaderEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        NetworkHeaderEncoder::new(Encoder2::new(
            self.header.encoder(),
            ArrayEncoder::without_length_prefix([self.length]),
        ))
    }
}

type NetworkHeaderInnerDecoder = Decoder2<HeaderDecoder, ArrayDecoder<1>>;

/// The decoder type for a [`NetworkHeader`].
#[derive(Debug, Clone)]
pub struct NetworkHeaderDecoder(NetworkHeaderInnerDecoder);

impl encoding::Decoder for NetworkHeaderDecoder {
    type Output = NetworkHeader;
    type Error = NetworkHeaderDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(NetworkHeaderDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (header, length) = self.0.end().map_err(NetworkHeaderDecoderError)?;
        Ok(NetworkHeader { header, length: u8::from_le_bytes(length) })
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for NetworkHeader {
    type Decoder = NetworkHeaderDecoder;

    fn decoder() -> Self::Decoder {
        NetworkHeaderDecoder(Decoder2::new(block::Header::decoder(), ArrayDecoder::new()))
    }
}

impl Decodable for NetworkHeader {
    fn consensus_decode<R: BufRead + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        Ok(Self { header: Decodable::consensus_decode(reader)?, length: reader.read_u8()? })
    }
}

impl Encodable for NetworkHeader {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut size = self.header.consensus_encode(writer)?;
        size += self.length.consensus_encode(writer)?;
        Ok(size)
    }
}

/// A list of bitcoin block headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage(pub Vec<NetworkHeader>);

impl HeadersMessage {
    /// Does each header point to the previous block hash in the list.
    pub fn is_connected(&self) -> bool {
        self.0
            .iter()
            .zip(self.0.iter().skip(1))
            .all(|(first, second)| first.header.block_hash().eq(&second.header.prev_blockhash))
    }

    /// Take the message as an iterator of [`Header`](primitives::block::Header).
    pub fn into_headers(self) -> impl Iterator<Item = block::Header> {
        self.0.into_iter().map(|network| network.header)
    }
}

impl_vec_wrapper!(HeadersMessage, NetworkHeader);

encoding::encoder_newtype! {
    /// The encoder type for a [`HeadersMessage`].
    #[derive(Debug, Clone)]
    pub struct HeadersMessageEncoder<'e>(Encoder2<CompactSizeEncoder, SliceEncoder<'e, NetworkHeader>>);
}

impl encoding::Encode for HeadersMessage {
    type Encoder<'e> = HeadersMessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        HeadersMessageEncoder::new(Encoder2::new(
            CompactSizeEncoder::new(self.0.len()),
            SliceEncoder::without_length_prefix(&self.0),
        ))
    }
}

type HeadersMessageInnerDecoder = VecDecoder<NetworkHeader>;

/// The decoder type for a [`HeadersMessage`].
#[derive(Debug, Clone)]
pub struct HeadersMessageDecoder(HeadersMessageInnerDecoder);

impl encoding::Decoder for HeadersMessageDecoder {
    type Output = HeadersMessage;
    type Error = HeadersMessageDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(HeadersMessageDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let headers = self.0.end().map_err(HeadersMessageDecoderError)?;
        Ok(HeadersMessage(headers))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decode for HeadersMessage {
    type Decoder = HeadersMessageDecoder;

    fn decoder() -> Self::Decoder { HeadersMessageDecoder(VecDecoder::new()) }
}

impl Decodable for V1NetworkMessage {
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode_from_finite_reader(r)?;
        let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
        let checked_data = CheckedData::consensus_decode_from_finite_reader(r)?;
        let checksum = checked_data.checksum();
        let raw_payload = checked_data.into_data();
        let payload_len = raw_payload.len() as u32;

        let mut mem_d = raw_payload.as_slice();
        let payload = match &cmd.0[..] {
            "version" =>
                NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "verack" => NetworkMessage::Verack,
            "addr" =>
                NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "inv" =>
                NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getdata" =>
                NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "getblocks" => NetworkMessage::GetBlocks(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getheaders" => NetworkMessage::GetHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "mempool" => NetworkMessage::MemPool,
            "block" =>
                NetworkMessage::Block(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "headers" => NetworkMessage::Headers(
                HeadersMessage::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping" => NetworkMessage::Ping(Ping(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?)),
            "pong" => NetworkMessage::Pong(Pong(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?)),
            "merkleblock" => NetworkMessage::MerkleBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterload" => NetworkMessage::FilterLoad(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filteradd" => NetworkMessage::FilterAdd(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterclear" => NetworkMessage::FilterClear,
            "tx" => NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfilters" => NetworkMessage::GetCFilters(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfilter" =>
                NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "getcfheaders" => NetworkMessage::GetCFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfheaders" => NetworkMessage::CFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfcheckpt" => NetworkMessage::CFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "reject" =>
                NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "alert" =>
                NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "feefilter" => NetworkMessage::FeeFilter(
                FeeFilter::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "sendcmpct" => NetworkMessage::SendCmpct(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cmpctblock" => NetworkMessage::CmpctBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getblocktxn" => NetworkMessage::GetBlockTxn(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "blocktxn" => NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "wtxidrelay" => NetworkMessage::WtxidRelay,
            "addrv2" =>
                NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            _ => NetworkMessage::Unknown { command: cmd, payload: raw_payload },
        };
        Ok(Self { magic, payload, payload_len, checksum })
    }

    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_MSG_SIZE.to_u64()))
    }
}

impl Decodable for V2NetworkMessage {
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let short_id: u8 = Decodable::consensus_decode_from_finite_reader(r)?;
        let payload = match short_id {
            0u8 => {
                // Full command encoding.
                let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
                match &cmd.0[..] {
                    "version" =>
                        NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(r)?),
                    "verack" => NetworkMessage::Verack,
                    "sendheaders" => NetworkMessage::SendHeaders,
                    "getaddr" => NetworkMessage::GetAddr,
                    "wtxidrelay" => NetworkMessage::WtxidRelay,
                    "sendaddrv2" => NetworkMessage::SendAddrV2,
                    "alert" =>
                        NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(r)?),
                    "reject" =>
                        NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(r)?),
                    _ => NetworkMessage::Unknown {
                        command: cmd,
                        payload: Vec::consensus_decode_from_finite_reader(r)?,
                    },
                }
            }
            1u8 => NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(r)?),
            2u8 => NetworkMessage::Block(Decodable::consensus_decode_from_finite_reader(r)?),
            3u8 => NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(r)?),
            4u8 => NetworkMessage::CmpctBlock(Decodable::consensus_decode_from_finite_reader(r)?),
            5u8 => NetworkMessage::FeeFilter(FeeFilter::consensus_decode_from_finite_reader(r)?),
            6u8 => NetworkMessage::FilterAdd(Decodable::consensus_decode_from_finite_reader(r)?),
            7u8 => NetworkMessage::FilterClear,
            8u8 => NetworkMessage::FilterLoad(Decodable::consensus_decode_from_finite_reader(r)?),
            9u8 => NetworkMessage::GetBlocks(Decodable::consensus_decode_from_finite_reader(r)?),
            10u8 => NetworkMessage::GetBlockTxn(Decodable::consensus_decode_from_finite_reader(r)?),
            11u8 => NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(r)?),
            12u8 => NetworkMessage::GetHeaders(Decodable::consensus_decode_from_finite_reader(r)?),
            13u8 =>
                NetworkMessage::Headers(HeadersMessage::consensus_decode_from_finite_reader(r)?),
            14u8 => NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(r)?),
            15u8 => NetworkMessage::MemPool,
            16u8 => NetworkMessage::MerkleBlock(Decodable::consensus_decode_from_finite_reader(r)?),
            17u8 => NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(r)?),
            18u8 => NetworkMessage::Ping(Ping(Decodable::consensus_decode_from_finite_reader(r)?)),
            19u8 => NetworkMessage::Pong(Pong(Decodable::consensus_decode_from_finite_reader(r)?)),
            20u8 => NetworkMessage::SendCmpct(Decodable::consensus_decode_from_finite_reader(r)?),
            21u8 => NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(r)?),
            22u8 => NetworkMessage::GetCFilters(Decodable::consensus_decode_from_finite_reader(r)?),
            23u8 => NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(r)?),
            24u8 =>
                NetworkMessage::GetCFHeaders(Decodable::consensus_decode_from_finite_reader(r)?),
            25u8 => NetworkMessage::CFHeaders(Decodable::consensus_decode_from_finite_reader(r)?),
            26u8 =>
                NetworkMessage::GetCFCheckpt(Decodable::consensus_decode_from_finite_reader(r)?),
            27u8 => NetworkMessage::CFCheckpt(Decodable::consensus_decode_from_finite_reader(r)?),
            28u8 => NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(r)?),
            _ =>
                return Err(encode::Error::Parse(encode::ParseError::ParseFailed(
                    "Unknown short ID",
                ))),
        };
        Ok(Self { payload })
    }

    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_MSG_SIZE.to_u64()))
    }
}

// State machine for decoding a [`V2NetworkMessage`].
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum V2NetworkMessageDecoderState {
    // Decoding the short-id byte, with the command string and payload decoder
    // waiting.
    ShortId(encoding::ArrayDecoder<1>),
    // Decoding the command string with the short-id byte stored, and payload
    // decoder waiting.
    CommandString(CommandStringDecoder),
    // Decoding the payload, with the short-id and command string.
    Payload(NetworkMessageDecoder),
    // Decoder has failed and cannot be used again.
    Errored,
}

/// Decoder for [`V2NetworkMessage`].
///
/// This decoder implements a multi-phase decoding process for Bitcoin V2 P2P messages.
/// It first decodes the 1-byte short ID. For optimized messages (IDs 1-28), it dispatches
/// directly to the payload decoder. For non-optimized messages (ID 0), it first reads the
/// 12-byte command string before dispatching.
pub struct V2NetworkMessageDecoder {
    state: V2NetworkMessageDecoderState,
}

impl V2NetworkMessageDecoder {
    /// Creates a payload decoder from a short ID (1-28).
    fn payload_decoder_from_short_id(
        short_id: u8,
    ) -> Result<NetworkMessageDecoder, V2NetworkMessageDecoderError> {
        use encoding::Decode as _;

        let err = V2NetworkMessageDecoderError::Payload(V1NetworkMessageDecoderError(
            V1NetworkMessageDecoderErrorInner::Payload,
        ));
        // Use a large payload_len for the Unknown variant buffer; actual messages use typed decoders.
        match short_id {
            1u8 => Ok(NetworkMessageDecoder::Addr(AddrPayload::decoder())),
            2u8 => Ok(NetworkMessageDecoder::Block(block::Block::decoder())),
            3u8 => Ok(NetworkMessageDecoder::BlockTxn(bip152::BlockTransactions::decoder())),
            4u8 => Ok(NetworkMessageDecoder::CmpctBlock(bip152::HeaderAndShortIds::decoder())),
            5u8 => Ok(NetworkMessageDecoder::FeeFilter(FeeFilter::decoder())),
            6u8 => Ok(NetworkMessageDecoder::FilterAdd(message_bloom::FilterAdd::decoder())),
            7u8 => Ok(NetworkMessageDecoder::Empty(
                CommandString::try_from_static("filterclear").map_err(|_| err)?,
            )),
            8u8 => Ok(NetworkMessageDecoder::FilterLoad(message_bloom::FilterLoad::decoder())),
            9u8 =>
                Ok(NetworkMessageDecoder::GetBlocks(message_blockdata::GetBlocksMessage::decoder())),
            10u8 =>
                Ok(NetworkMessageDecoder::GetBlockTxn(bip152::BlockTransactionsRequest::decoder())),
            11u8 => Ok(NetworkMessageDecoder::GetData(InventoryPayload::decoder())),
            12u8 => Ok(NetworkMessageDecoder::GetHeaders(
                message_blockdata::GetHeadersMessage::decoder(),
            )),
            13u8 => Ok(NetworkMessageDecoder::Headers(HeadersMessage::decoder())),
            14u8 => Ok(NetworkMessageDecoder::Inv(InventoryPayload::decoder())),
            15u8 => Ok(NetworkMessageDecoder::Empty(
                CommandString::try_from_static("mempool").map_err(|_| err)?,
            )),
            16u8 => Ok(NetworkMessageDecoder::MerkleBlock(MerkleBlock::decoder())),
            17u8 => Ok(NetworkMessageDecoder::NotFound(InventoryPayload::decoder())),
            18u8 => Ok(NetworkMessageDecoder::Ping(Ping::decoder())),
            19u8 => Ok(NetworkMessageDecoder::Pong(Pong::decoder())),
            20u8 =>
                Ok(NetworkMessageDecoder::SendCmpct(message_compact_blocks::SendCmpct::decoder())),
            21u8 => Ok(NetworkMessageDecoder::Tx(transaction::Transaction::decoder())),
            22u8 => Ok(NetworkMessageDecoder::GetCFilters(message_filter::GetCFilters::decoder())),
            23u8 => Ok(NetworkMessageDecoder::CFilter(message_filter::CFilter::decoder())),
            24u8 =>
                Ok(NetworkMessageDecoder::GetCFHeaders(message_filter::GetCFHeaders::decoder())),
            25u8 => Ok(NetworkMessageDecoder::CFHeaders(message_filter::CFHeaders::decoder())),
            26u8 =>
                Ok(NetworkMessageDecoder::GetCFCheckpt(message_filter::GetCFCheckpt::decoder())),
            27u8 => Ok(NetworkMessageDecoder::CFCheckpt(message_filter::CFCheckpt::decoder())),
            28u8 => Ok(NetworkMessageDecoder::AddrV2(AddrV2Payload::decoder())),
            id => Err(V2NetworkMessageDecoderError::UnknownShortId(id)),
        }
    }

    /// Creates a payload decoder from a command string (for short ID == 0).
    fn payload_decoder_from_command(command: CommandString) -> NetworkMessageDecoder {
        use encoding::Decode as _;

        match command.as_ref() {
            "version" => NetworkMessageDecoder::Version(message_network::VersionMessage::decoder()),
            "verack" | "sendheaders" | "getaddr" | "wtxidrelay" | "sendaddrv2" =>
                NetworkMessageDecoder::Empty(command),
            "alert" => NetworkMessageDecoder::Alert(message_network::Alert::decoder()),
            "reject" => NetworkMessageDecoder::Reject(message_network::Reject::decoder()),
            _ => NetworkMessageDecoder::Unknown {
                command,
                remaining: 0, // no payload length, buffer all bytes until end().
                buffer: Vec::new(),
            },
        }
    }
}

impl encoding::Decoder for V2NetworkMessageDecoder {
    type Output = V2NetworkMessage;
    type Error = V2NetworkMessageDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        loop {
            match &mut self.state {
                V2NetworkMessageDecoderState::ShortId(short_id_decoder) => {
                    if short_id_decoder
                        .push_bytes(bytes)
                        .map_err(|_| V2NetworkMessageDecoderError::ShortId)?
                    {
                        return Ok(true);
                    }

                    match mem::replace(&mut self.state, V2NetworkMessageDecoderState::Errored) {
                        V2NetworkMessageDecoderState::ShortId(short_id) => {
                            let short_id_bytes = short_id
                                .end()
                                .map_err(|_| V2NetworkMessageDecoderError::ShortId)?;
                            let id = short_id_bytes[0];
                            if id == 0 {
                                // Non-optimized: need to read 12-byte command string next.
                                self.state = V2NetworkMessageDecoderState::CommandString(
                                    CommandStringDecoder { inner: encoding::ArrayDecoder::new() },
                                );
                            } else {
                                // Optimized short ID (1-28): skip command, go straight to payload.
                                let payload_decoder = Self::payload_decoder_from_short_id(id)?;
                                self.state = V2NetworkMessageDecoderState::Payload(payload_decoder);
                            }
                        }
                        _ => unreachable!("we know we're in First state"),
                    }
                }
                V2NetworkMessageDecoderState::CommandString(command_string_decoder) => {
                    if command_string_decoder
                        .push_bytes(bytes)
                        .map_err(V2NetworkMessageDecoderError::Command)?
                    {
                        return Ok(true);
                    }
                    match mem::replace(&mut self.state, V2NetworkMessageDecoderState::Errored) {
                        V2NetworkMessageDecoderState::CommandString(command_string) => {
                            let command = command_string
                                .end()
                                .map_err(V2NetworkMessageDecoderError::Command)?;
                            let payload_decoder =
                                Self::payload_decoder_from_command(command.clone());
                            self.state = V2NetworkMessageDecoderState::Payload(payload_decoder);
                        }
                        _ => unreachable!("we know we're in the Second state"),
                    }
                }
                V2NetworkMessageDecoderState::Payload(payload_decoder) => {
                    return payload_decoder.push_bytes(bytes).map_err(|e| {
                        self.state = V2NetworkMessageDecoderState::Errored;
                        V2NetworkMessageDecoderError::Payload(e)
                    });
                }
                V2NetworkMessageDecoderState::Errored => {
                    panic!("use of failed decoder");
                }
            }
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            V2NetworkMessageDecoderState::ShortId(d) => {
                d.end().map_err(|_| V2NetworkMessageDecoderError::ShortId)?;
                unreachable!("incomplete ShortId decoder should error")
            }
            V2NetworkMessageDecoderState::CommandString(d) => {
                d.end().map_err(V2NetworkMessageDecoderError::Command)?;
                unreachable!("incomplete CommandString decoder should error")
            }
            V2NetworkMessageDecoderState::Payload(payload_decoder) => {
                let payload =
                    payload_decoder.end().map_err(V2NetworkMessageDecoderError::Payload)?;
                Ok(V2NetworkMessage { payload })
            }
            V2NetworkMessageDecoderState::Errored => panic!("use of failed decoder"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            V2NetworkMessageDecoderState::ShortId(short_id_decoder) =>
                short_id_decoder.read_limit(),
            V2NetworkMessageDecoderState::CommandString(command_string_decoder) =>
                command_string_decoder.read_limit(),
            V2NetworkMessageDecoderState::Payload(payload_decoder) => payload_decoder.read_limit(),
            V2NetworkMessageDecoderState::Errored => 0,
        }
    }
}

impl encoding::Decode for V2NetworkMessage {
    type Decoder = V2NetworkMessageDecoder;

    fn decoder() -> Self::Decoder {
        V2NetworkMessageDecoder {
            state: V2NetworkMessageDecoderState::ShortId(encoding::ArrayDecoder::new()),
        }
    }
}

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Constructs a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let hash = sha256d::hash(data.as_slice()).to_byte_array();
        let checksum = [hash[0], hash[1], hash[2], hash[3]];
        Self { data, checksum }
    }

    /// Returns a reference to the raw data without the checksum.
    pub fn data(&self) -> &[u8] { &self.data }

    /// Returns the raw data without the checksum.
    pub fn into_data(self) -> Vec<u8> { self.data }

    /// Returns the checksum of the data.
    pub fn checksum(&self) -> [u8; 4] { self.checksum }
}

impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        u32::try_from(self.data.len())
            .expect("network message use u32 as length")
            .consensus_encode(w)?;
        self.checksum().consensus_encode(w)?;
        Ok(8 + w.emit_slice(&self.data)?)
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = u32::consensus_decode_from_finite_reader(r)? as usize;

        let checksum = <[u8; 4]>::consensus_decode_from_finite_reader(r)?;
        let opts = ReadBytesFromFiniteReaderOpts { len, chunk_size: encode::MAX_VEC_SIZE };
        let data = read_bytes_from_finite_reader(r, opts)?;
        let hash = sha256d::hash(data.as_slice()).to_byte_array();
        let expected_checksum = [hash[0], hash[1], hash[2], hash[3]];
        if expected_checksum == checksum {
            Ok(Self { data, checksum })
        } else {
            Err(encode::ParseError::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            }
            .into())
        }
    }
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be malicious.
///
/// This function relies on reader being bound in amount of data
/// it returns for OOM protection. See [`Decodable::consensus_decode_from_finite_reader`].
#[inline]
fn read_bytes_from_finite_reader<D: Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, encode::Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_slice(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &impl encoding::Encode) -> (u64, [u8; 4]) {
    let mut engine = sha256d::HashEngine::new();
    hashes::encode_to_engine(data, &mut engine);
    let bytes_hashed = engine.n_bytes_hashed();
    let hash = engine.finalize();
    let checksum = hash.to_byte_array();
    let leading_bytes = [checksum[0], checksum[1], checksum[2], checksum[3]];

    (bytes_hashed, leading_bytes)
}

/// Error types for network messages.
pub mod error {
    use alloc::borrow::Cow;
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// Error decoding a [`CommandString`].
    ///
    /// [`CommandString`]: super::CommandString
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum CommandStringDecoderError {
        /// Unexpected end of data.
        UnexpectedEof(encoding::UnexpectedEofError),
        /// Command string contains non-ASCII characters.
        NotAscii,
    }

    impl fmt::Display for CommandStringDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Self::UnexpectedEof(e) => write!(f, "unexpected end of data: {}", e),
                Self::NotAscii => write!(f, "command string must be ASCII"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CommandStringDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::UnexpectedEof(e) => Some(e),
                Self::NotAscii => None,
            }
        }
    }

    /// Error returned when a command string is invalid.
    ///
    /// This is currently returned for command strings longer than 12.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct CommandStringError {
        pub(super) cow: Cow<'static, str>,
    }

    impl fmt::Display for CommandStringError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "the command string '{}' has length {} which is larger than 12",
                self.cow,
                self.cow.len()
            )
        }
    }

    impl std::error::Error for CommandStringError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
    }

    /// An error consensus decoding a [`V1MessageHeader`].
    ///
    /// [`V1MessageHeader`]: super::V1MessageHeader
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct V1MessageHeaderDecoderError(
        pub(super) <super::V1MessageHeaderInnerDecoder as encoding::Decoder>::Error,
    );

    impl fmt::Display for V1MessageHeaderDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "message header decoder error"; self.0)
        }
    }

    /// An error decoding a [`InventoryPayload`].
    ///
    /// [`InventoryPayload`]: super::InventoryPayload
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InventoryPayloadDecoderError(
        pub(super) <super::InventoryInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for InventoryPayloadDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for InventoryPayloadDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "inventory payload error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for InventoryPayloadDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error decoding a [`AddrPayload`].
    ///
    /// [`AddrPayload`]: super::AddrPayload
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddrPayloadDecoderError(
        pub(super) <super::AddrPayloadInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for AddrPayloadDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for AddrPayloadDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "addrv1 payload error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AddrPayloadDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error decoding a [`AddrV2Payload`].
    ///
    /// [`AddrV2Payload`]: super::AddrV2Payload
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddrV2PayloadDecoderError(
        pub(super) <super::AddrV2PayloadInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for AddrV2PayloadDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for AddrV2PayloadDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "addrv2 payload error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AddrV2PayloadDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error consensus decoding a [`Ping`].
    ///
    /// [`Ping`]: super::Ping
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PingDecoderError(pub(super) <encoding::ArrayDecoder<8> as encoding::Decoder>::Error);

    impl From<Infallible> for PingDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for PingDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "ping decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PingDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error consensus decoding a [`Pong`].
    ///
    /// [`Pong`]: super::Pong
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PongDecoderError(pub(super) <encoding::ArrayDecoder<8> as encoding::Decoder>::Error);

    impl From<Infallible> for PongDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for PongDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write_err!(f, "pong decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PongDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// Error decoding a raw network message.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct V1NetworkMessageDecoderError(pub(super) V1NetworkMessageDecoderErrorInner);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum V1NetworkMessageDecoderErrorInner {
        /// Error decoding the message header.
        Header,
        /// Payload length exceeds maximum allowed message size.
        PayloadTooLarge,
        /// Error decoding the message payload.
        Payload,
        /// Message checksum did not match the one reported in the message header.
        InvalidChecksum { expected: [u8; 4], actual: [u8; 4] },
    }

    impl fmt::Display for V1NetworkMessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self.0 {
                V1NetworkMessageDecoderErrorInner::Header => {
                    write!(f, "error decoding message header")
                }
                V1NetworkMessageDecoderErrorInner::PayloadTooLarge => {
                    write!(f, "payload length exceeds maximum allowed message size")
                }
                V1NetworkMessageDecoderErrorInner::Payload => {
                    write!(f, "error decoding message payload")
                }
                V1NetworkMessageDecoderErrorInner::InvalidChecksum { expected: ref e, actual: ref a } => write!(
                    f,
                    "invalid checksum: expected {:02x}{:02x}{:02x}{:02x}, actual {:02x}{:02x}{:02x}{:02x}",
                    e[0], e[1], e[2], e[3], a[0], a[1], a[2], a[3],
                ),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for V1NetworkMessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self.0 {
                V1NetworkMessageDecoderErrorInner::Header => None,
                V1NetworkMessageDecoderErrorInner::PayloadTooLarge => None,
                V1NetworkMessageDecoderErrorInner::Payload => None,
                V1NetworkMessageDecoderErrorInner::InvalidChecksum { expected: _, actual: _ } =>
                    None,
            }
        }
    }

    /// Error decoding a V2 network message.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum V2NetworkMessageDecoderError {
        /// Error decoding the short ID byte.
        ShortId,
        /// Error decoding the command string.
        Command(CommandStringDecoderError),
        /// Error decoding the message payload.
        Payload(V1NetworkMessageDecoderError),
        /// Unknown short ID value.
        UnknownShortId(u8),
    }

    impl fmt::Display for V2NetworkMessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::ShortId => {
                    write!(f, "error decoding V2 message short ID")
                }
                Self::Command(e) => {
                    write_err!(f, "error decoding V2 message command string"; e)
                }
                Self::Payload(e) => {
                    write_err!(f, "error decoding V2 message payload"; e)
                }
                Self::UnknownShortId(e) => {
                    write!(f, "unknown V2 message short ID: {e}")
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for V2NetworkMessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::ShortId => None,
                Self::Command(e) => Some(e),
                Self::Payload(e) => Some(e),
                Self::UnknownShortId(_) => None,
            }
        }
    }

    /// An error decoding a [`NetworkHeader`] message.
    ///
    /// [`NetworkHeader`]: super::NetworkHeader
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NetworkHeaderDecoderError(
        pub(super) <super::NetworkHeaderInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for NetworkHeaderDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for NetworkHeaderDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "network header error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for NetworkHeaderDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error decoding a [`HeadersMessage`] message.
    ///
    /// [`HeadersMessage`]: super::HeadersMessage
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HeadersMessageDecoderError(
        pub(super) <super::HeadersMessageInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for HeadersMessageDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for HeadersMessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "headersmessage error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for HeadersMessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<AddrV1Message>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrV2Payload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<AddrV2Message>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for InventoryPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<message_blockdata::Inventory>::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for CommandString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary::<String>()?.into()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NetworkHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { header: u.arbitrary()?, length: u.arbitrary()? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for HeadersMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> { Ok(Self(u.arbitrary()?)) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for NetworkMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=36)? {
            0 => Ok(Self::Version(u.arbitrary()?)),
            1 => Ok(Self::Verack),
            2 => Ok(Self::Addr(u.arbitrary()?)),
            3 => Ok(Self::Inv(u.arbitrary()?)),
            4 => Ok(Self::GetData(u.arbitrary()?)),
            5 => Ok(Self::NotFound(u.arbitrary()?)),
            6 => Ok(Self::GetBlocks(u.arbitrary()?)),
            7 => Ok(Self::GetHeaders(u.arbitrary()?)),
            8 => Ok(Self::MemPool),
            9 => Ok(Self::Tx(u.arbitrary()?)),
            10 => Ok(Self::Block(u.arbitrary()?)),
            11 => Ok(Self::Headers(u.arbitrary()?)),
            12 => Ok(Self::SendHeaders),
            13 => Ok(Self::GetAddr),
            14 => Ok(Self::Ping(Ping(u.arbitrary()?))),
            15 => Ok(Self::Pong(Pong(u.arbitrary()?))),
            16 => Ok(Self::MerkleBlock(u.arbitrary()?)),
            17 => Ok(Self::FilterLoad(u.arbitrary()?)),
            18 => Ok(Self::FilterAdd(u.arbitrary()?)),
            19 => Ok(Self::FilterClear),
            20 => Ok(Self::GetCFilters(u.arbitrary()?)),
            21 => Ok(Self::CFilter(u.arbitrary()?)),
            22 => Ok(Self::GetCFHeaders(u.arbitrary()?)),
            23 => Ok(Self::CFHeaders(u.arbitrary()?)),
            24 => Ok(Self::GetCFCheckpt(u.arbitrary()?)),
            25 => Ok(Self::CFCheckpt(u.arbitrary()?)),
            26 => Ok(Self::SendCmpct(u.arbitrary()?)),
            27 => Ok(Self::CmpctBlock(u.arbitrary()?)),
            28 => Ok(Self::GetBlockTxn(u.arbitrary()?)),
            29 => Ok(Self::BlockTxn(u.arbitrary()?)),
            30 => Ok(Self::Alert(u.arbitrary()?)),
            31 => Ok(Self::Reject(u.arbitrary()?)),
            32 => Ok(Self::FeeFilter(u.arbitrary()?)),
            33 => Ok(Self::WtxidRelay),
            34 => Ok(Self::AddrV2(u.arbitrary()?)),
            35 => Ok(Self::SendAddrV2),
            _ => Ok(Self::Unknown { command: u.arbitrary()?, payload: Vec::<u8>::arbitrary(u)? }),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for V1NetworkMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use std::net::Ipv4Addr;

    use hex_unstable::hex;
    use primitives::transaction::{Transaction, Txid};
    use primitives::{Block, BlockHash};
    use units::BlockHeight;

    use super::*;
    use crate::address::{AddrV2, Address};
    use crate::bip152::BlockTransactionsRequest;
    use crate::message_blockdata::{BlockLocator, GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::message_compact_blocks::SendCmpct;
    use crate::message_filter::{
        CFCheckpt, CFHeaders, CFilter, FilterHash, FilterHeader, GetCFCheckpt, GetCFHeaders,
        GetCFilters,
    };
    use crate::message_network::{Alert, Reject, RejectReason, VersionMessage};
    use crate::{ProtocolVersion, ServiceFlags};

    fn hash(array: [u8; 32]) -> sha256d::Hash { sha256d::Hash::from_byte_array(array) }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn full_round_ser_der_raw_network_message() {
        let version_msg: VersionMessage = encoding::decode_from_slice(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
        let tx: Transaction = encoding::decode_from_slice(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
        let block: Block = encoding::decode_from_slice(&hex!("00608e2e094d41aecfbcbf8fe70cb60be57516b07db1bafee4c4de5dad760000000000004aec16eab3be95abe9c54e01cf850c14b8c5cad1bc6b2e73e811db5d5998ada404503e66fcff031b4ebd99d701010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3402983a000404503e6604f1f617271083bc3d6600000000000000000007bb1b0a636b706f6f6c0d506f72746c616e642e484f444cffffffff0200f2052a010000001976a9142ce72b25fe97b52638c199acfaa5e3891ddfed5b88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();
        let header: block::Header = encoding::decode_from_slice(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
        let script = &hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac");
        let merkle_block: MerkleBlock = encoding::decode_from_slice(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
        let cmptblock = encoding::decode_from_slice(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
        let blocktxn = encoding::decode_from_slice(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

        let msgs = [
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(AddrPayload(vec![AddrV1Message {
                time: 45,
                address: Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
            }])),
            NetworkMessage::Inv(InventoryPayload(vec![Inventory::Block(
                BlockHash::from_byte_array(hash([8u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::GetData(InventoryPayload(vec![Inventory::Transaction(
                Txid::from_byte_array(hash([45u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::NotFound(InventoryPayload(vec![Inventory::Error([0u8; 32])])),
            NetworkMessage::GetBlocks(GetBlocksMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: BlockLocator::from(vec![
                    BlockHash::from_byte_array(hash([1u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                ]),
                stop_hash: BlockHash::from_byte_array(hash([5u8; 32]).to_byte_array()),
            }),
            NetworkMessage::GetHeaders(GetHeadersMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: BlockLocator::from(vec![
                    BlockHash::from_byte_array(hash([10u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([40u8; 32]).to_byte_array()),
                ]),
                stop_hash: BlockHash::from_byte_array(hash([50u8; 32]).to_byte_array()),
            }),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(tx),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(HeadersMessage(vec![NetworkHeader { header, length: 0 }])),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(Ping(15)),
            NetworkMessage::Pong(Pong(23)),
            NetworkMessage::MerkleBlock(merkle_block),
            NetworkMessage::FilterLoad(FilterLoad {
                filter: hex!("03614e9b050000000000000001").to_vec(),
                hash_funcs: 1,
                tweak: 2,
                flags: BloomFlags::All,
            }),
            NetworkMessage::FilterAdd(FilterAdd { data: script.to_vec() }),
            NetworkMessage::FilterAdd(FilterAdd {
                data: hash([29u8; 32]).as_byte_array().to_vec(),
            }),
            NetworkMessage::FilterClear,
            NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 2,
                start_height: BlockHeight::from(52),
                stop_hash: BlockHash::from_byte_array(hash([42u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFilter(CFilter {
                filter_type: 7,
                block_hash: BlockHash::from_byte_array(hash([25u8; 32]).to_byte_array()),
                filter: vec![1, 2, 3],
            }),
            NetworkMessage::GetCFHeaders(GetCFHeaders {
                filter_type: 4,
                start_height: BlockHeight::from(102),
                stop_hash: BlockHash::from_byte_array(hash([47u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFHeaders(CFHeaders {
                filter_type: 13,
                stop_hash: BlockHash::from_byte_array(hash([53u8; 32]).to_byte_array()),
                previous_filter_header: FilterHeader::from_byte_array(
                    hash([12u8; 32]).to_byte_array(),
                ),
                filter_hashes: vec![
                    FilterHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                    FilterHash::from_byte_array(hash([12u8; 32]).to_byte_array()),
                ],
            }),
            NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                filter_type: 17,
                stop_hash: BlockHash::from_byte_array(hash([25u8; 32]).to_byte_array()),
            }),
            NetworkMessage::CFCheckpt(CFCheckpt {
                filter_type: 27,
                stop_hash: BlockHash::from_byte_array(hash([77u8; 32]).to_byte_array()),
                filter_headers: vec![
                    FilterHeader::from_byte_array(hash([3u8; 32]).to_byte_array()),
                    FilterHeader::from_byte_array(hash([99u8; 32]).to_byte_array()),
                ],
            }),
            NetworkMessage::Alert(Alert::final_alert()),
            NetworkMessage::Reject(Reject {
                message: "Test reject".into(),
                ccode: RejectReason::Duplicate,
                reason: "Cause".into(),
                hash: hash([255u8; 32]),
            }),
            NetworkMessage::FeeFilter(FeeFilter::from(FeeRate::BROADCAST_MIN)),
            NetworkMessage::WtxidRelay,
            NetworkMessage::AddrV2(AddrV2Payload(vec![AddrV2Message {
                addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                services: ServiceFlags::NONE,
                time: 0,
            }])),
            NetworkMessage::SendAddrV2,
            NetworkMessage::CmpctBlock(cmptblock),
            NetworkMessage::GetBlockTxn(BlockTransactionsRequest::from_indices_unchecked(
                BlockHash::from_byte_array(hash([11u8; 32]).to_byte_array()),
                vec![0, 1, 2, 3, 10, 3002],
            )),
            NetworkMessage::BlockTxn(blocktxn),
            NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 8333 }),
        ];

        for msg in &msgs {
            let raw_msg = V1NetworkMessage::new(Magic::from_bytes([57, 0, 0, 0]), msg.clone());
            // V1 messages via encoding traits.
            let encoded = encoding::encode_to_vec(&raw_msg);
            let decoded = encoding::decode_from_slice::<V1NetworkMessage>(&encoded).unwrap();
            assert_eq!(decoded, raw_msg);

            // V2 messages via encoding traits
            let v2_msg = V2NetworkMessage::new(msg.clone());

            let v2_encoded = encoding::encode_to_vec(&v2_msg);
            let v2_decoded = encoding::decode_from_slice::<V2NetworkMessage>(&v2_encoded).unwrap();
            assert_eq!(v2_decoded, v2_msg);
        }
    }

    #[test]
    fn commandstring() {
        // Test converting.
        assert_eq!(
            CommandString::try_from_static("AndrewAndrew").unwrap().as_ref(),
            "AndrewAndrew"
        );
        assert!(CommandString::try_from_static("AndrewAndrewA").is_err());

        // Test serializing.
        let cs = CommandString("Andrew".into());
        assert_eq!(
            encoding::encode_to_vec(&cs),
            [0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]
        );

        // Test deserializing
        let cs: Result<CommandString, _> =
            encoding::decode_from_slice(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("Andrew").unwrap());

        // Test that embedded null bytes are preserved while trailing nulls are trimmed
        let cs: Result<CommandString, _> =
            encoding::decode_from_slice(&[0, 0x41u8, 0x6e, 0x64, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "\0And\0rew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("\0And\0rew").unwrap());

        // Invalid CommandString, must be ASCII
        assert!(encoding::decode_from_slice::<CommandString>(&[
            0, 0x41u8, 0x6e, 0xa4, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0
        ])
        .is_err());

        // Invalid CommandString, must be 12 bytes
        assert!(encoding::decode_from_slice::<CommandString>(&[
            0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0
        ])
        .is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_verack() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::BITCOIN, NetworkMessage::Verack)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                        0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_verack() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::Verack)),
            [
                0x00, // Full command encoding flag.
                0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn roundtrip_encode_decode_ping() {
        let ping = Ping(314);
        let encoded_ping = encoding::encode_to_vec(&ping);
        let decoded_ping = encoding::decode_from_slice::<Ping>(&encoded_ping).unwrap();
        assert_eq!(decoded_ping, ping);
    }

    #[test]
    fn roundtrip_encode_decode_pong() {
        let pong = Pong(314);
        let encoded_pong = encoding::encode_to_vec(&pong);
        let decoded_pong = encoding::decode_from_slice::<Pong>(&encoded_pong).unwrap();
        assert_eq!(decoded_pong, pong);
    }

    #[test]
    fn pong_from_ping_constructors() {
        let ping = Ping::new(314);
        let pong = Pong::from_ping(&ping);
        assert_eq!(pong.0, 314);
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_mempool() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::BITCOIN, NetworkMessage::MemPool)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                        0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_mempool() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::MemPool)),
            [
                0x0F, // MemPool command short ID
            ]
        );
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_getaddr() {
        assert_eq!(encoding::encode_to_vec(&V1NetworkMessage::new(Magic::BITCOIN, NetworkMessage::GetAddr)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                        0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_getaddr() {
        assert_eq!(
            encoding::encode_to_vec(&V2NetworkMessage::new(NetworkMessage::GetAddr)),
            [
                0x00, // Full command encoding flag.
                0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn deserialize_getaddr() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
            0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2
        ]);
        let preimage = V1NetworkMessage::new(Magic::BITCOIN, NetworkMessage::GetAddr);
        assert!(msg.is_ok());
        let msg: V1NetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_v2_getaddr() {
        let msg = encoding::decode_from_slice(&[
            0x00, // Full command encoding flag
            0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let preimage = V2NetworkMessage::new(NetworkMessage::GetAddr);
        assert!(msg.is_ok());
        let msg: V2NetworkMessage = msg.unwrap();
        assert_eq!(preimage, msg);
    }

    #[test]
    fn deserialize_version() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice::<V1NetworkMessage>(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01
        ]);

        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.magic, Magic::BITCOIN);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn deserialize_v2_version() {
        #[rustfmt::skip]
        let msg = encoding::decode_from_slice::<V2NetworkMessage>(&[
            0x00, // Full command encoding flag
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, // "version" command
            0x7f, 0x11, 0x01, 0x00, // version: 70015
            0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
            0xf0, 0x0f, 0x4d, 0x5c, 0x00, 0x00, 0x00, 0x00, // timestamp: 1_548_554_224
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receiver services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, // addr_recv
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sender services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_from
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1, // nonce
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31, 0x2f, // user_agent: "/Satoshi:0.17.1/"
            0x93, 0x8c, 0x08, 0x00, // start_height: 560_275
            0x01 // relay: true
        ]).unwrap();

        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message() {
        #[rustfmt::skip]
        let data: [u8; 128] = [
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0x00, 0x00
        ];
        let msg = encoding::decode_from_slice_unbounded::<V1NetworkMessage>(&mut data.as_ref());
        assert!(msg.is_ok());

        let msg = msg.unwrap();
        assert_eq!(encoding::encode_to_vec(&msg).len(), data.to_vec().len() - 2);
        assert_eq!(msg.magic, Magic::BITCOIN);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, ProtocolVersion::INVALID_CB_NO_BAN_VERSION);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1_548_554_224);
            assert_eq!(version_msg.nonce, 13_952_548_347_456_104_954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560_275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn headers_message() {
        let block_900_000 = encoding::decode_from_slice::<block::Header>(
            &hex!("00a0ab20247d4d9f582f9750344cdf62c46d81d046be960340960100000000000000000070f96945530651135839d8adc3f40e595118ec74c7ad81a3d17bb022e554fb0c937f4268743702177ad05f92")
        ).unwrap();
        let block_900_001 = encoding::decode_from_slice::<block::Header>(
            &hex!("00e000208a96960d6d1ca4ee4a283fd83da309b8d5d2bfed380501000000000000000000371c9ffd63d75fb36c57d58eb842d23c0e7ec049daf16d94cc38805c346e9d52e880426874370217973dc83b")
        ).unwrap();
        let block_900_002 = encoding::decode_from_slice::<block::Header>(
            &hex!("0400ff3ffc834fac4e1eb2ae41f1f9776e0f8e24a6090603ffa8010000000000000000002efba7e7280aa60f0a650f29e30332d52e11af57bc58cc6e71f343851f016c676182426874370217e3615653")
        ).unwrap();
        let header_900_000 = NetworkHeader { header: block_900_000, length: 0 };
        let header_900_001 = NetworkHeader { header: block_900_001, length: 0 };
        let header_900_002 = NetworkHeader { header: block_900_002, length: 0 };
        let headers_message = HeadersMessage(vec![header_900_000, header_900_001, header_900_002]);
        assert!(headers_message.is_connected());
    }

    #[test]
    fn network_message_decode() {
        use encoding::Decoder;

        let data = hex!("010101010101");

        let mut decoder =
            NetworkMessageDecoder::new(CommandString::try_from_static("unknown").unwrap(), 6);
        let _ = decoder.push_bytes(&mut data.as_slice());
        let decoded = decoder.end().unwrap();

        let enc = encoding::encode_to_vec(&decoded);
        assert_eq!(data.as_slice(), enc.as_slice());
    }

    #[test]
    fn command_string_encoder() {
        use encoding::{Encode as _, ExactSizeEncoder as _};

        let cmd = CommandString::try_from_static("version").unwrap();
        let expected_bytes: [u8; 12] = [b'v', b'e', b'r', b's', b'i', b'o', b'n', 0, 0, 0, 0, 0];

        let mut encoder = cmd.encoder();
        assert_eq!(encoder.len(), expected_bytes.len());

        let encoded = encoding::drain_to_vec(&mut encoder);
        assert_eq!(encoded, expected_bytes);
    }
}
