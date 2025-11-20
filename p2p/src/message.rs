// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network messages.
//!
//! This module defines the `NetworkMessage` and `RawNetworkMessage` types that
//! are used for (de)serializing Bitcoin objects for transmission on the network.

use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::{cmp, fmt};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::block::HeaderExt;
use bitcoin::consensus::encode::{self, Decodable, Encodable, ReadExt, WriteExt};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{block, transaction};
use hashes::sha256d;
use internals::ToU64 as _;
use io::{self, BufRead, Read, Write};
use units::FeeRate;

use crate::address::{AddrV2Message, Address};
use crate::consensus::{impl_consensus_encoding, impl_vec_wrapper};
use crate::{
    message_blockdata, message_bloom, message_compact_blocks, message_filter, message_network,
    Magic,
};

/// The maximum number of [super::message_blockdata::Inventory] items in an `inv` message.
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

/// Error returned when a command string is invalid.
///
/// This is currently returned for command strings longer than 12.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommandStringError {
    cow: Cow<'static, str>,
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

/// A Network message using the v1 p2p protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawNetworkMessage {
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

impl_consensus_encoding!(V1MessageHeader, magic, command, length, checksum);

/// A Network message using the v2 p2p protocol defined in BIP-0324.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2NetworkMessage {
    payload: NetworkMessage,
}

/// A list of inventory items.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InventoryPayload(pub Vec<message_blockdata::Inventory>);

/// A list of legacy p2p address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrPayload(pub Vec<(u32, Address)>);

/// A list of v2 address messages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrV2Payload(pub Vec<AddrV2Message>);

impl_vec_wrapper!(InventoryPayload, message_blockdata::Inventory);
impl_vec_wrapper!(AddrPayload, (u32, Address));
impl_vec_wrapper!(AddrV2Payload, AddrV2Message);

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
    Ping(u64),
    /// `pong`
    Pong(u64),
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
    CmpctBlock(message_compact_blocks::CmpctBlock),
    /// BIP-0152 getblocktxn
    GetBlockTxn(message_compact_blocks::GetBlockTxn),
    /// BIP-0152 blocktxn
    BlockTxn(message_compact_blocks::BlockTxn),
    /// `alert`
    Alert(message_network::Alert),
    /// `reject`
    Reject(message_network::Reject),
    /// `feefilter`
    FeeFilter(FeeRate),
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
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
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

    /// Returns the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        match *self {
            Self::Unknown { command: ref c, .. } => c.clone(),
            _ => CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands"),
        }
    }
}

impl RawNetworkMessage {
    /// Constructs a new [RawNetworkMessage]
    pub fn new(magic: Magic, payload: NetworkMessage) -> Self {
        let mut engine = sha256d::Hash::engine();
        let payload_len = payload.consensus_encode(&mut engine).expect("engine doesn't error");
        let payload_len = u32::try_from(payload_len).expect("network message use u32 as length");
        let checksum = sha256d::Hash::from_engine(engine);
        let checksum = checksum.to_byte_array();
        let checksum = [checksum[0], checksum[1], checksum[2], checksum[3]];
        Self { magic, payload, payload_len, checksum }
    }

    /// Consumes the [RawNetworkMessage] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage { self.payload }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage { &self.payload }

    /// Magic bytes to identify the network these messages are meant for
    pub fn magic(&self) -> &Magic { &self.magic }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Returns the CommandString for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

impl V2NetworkMessage {
    /// Constructs a new [V2NetworkMessage].
    pub fn new(payload: NetworkMessage) -> Self { Self { payload } }

    /// Consumes the [V2NetworkMessage] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage { self.payload }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage { &self.payload }

    /// Returns the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Returns the CommandString for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

impl Encodable for HeadersMessage {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += w.emit_compact_size(self.0.len())?;
        for header in self.0.iter() {
            len += header.consensus_encode(w)?;
            len += 0u8.consensus_encode(w)?;
        }
        Ok(len)
    }
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
            Self::Ping(ref dat) => dat.consensus_encode(writer),
            Self::Pong(ref dat) => dat.consensus_encode(writer),
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
            Self::FeeFilter(ref dat) => dat.to_sat_per_kvb_ceil().consensus_encode(writer),
            Self::AddrV2(ref dat) => dat.consensus_encode(writer),
            Self::Verack
            | Self::SendHeaders
            | Self::MemPool
            | Self::GetAddr
            | Self::WtxidRelay
            | Self::FilterClear
            | Self::SendAddrV2 => Ok(0),
            Self::Unknown { payload: ref data, .. } => data.consensus_encode(writer),
        }
    }
}

impl Encodable for RawNetworkMessage {
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

impl Encodable for V2NetworkMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        // A subset of message types are optimized to only use one byte to encode the command.
        // Non-optimized message types use the zero-byte flag and the following twelve bytes to encode the command.
        let (command_byte, full_command) = match self.payload {
            NetworkMessage::Addr(_) => (1u8, None),
            NetworkMessage::Inv(_) => (14u8, None),
            NetworkMessage::GetData(_) => (11u8, None),
            NetworkMessage::NotFound(_) => (17u8, None),
            NetworkMessage::GetBlocks(_) => (9u8, None),
            NetworkMessage::GetHeaders(_) => (12u8, None),
            NetworkMessage::MemPool => (15u8, None),
            NetworkMessage::Tx(_) => (21u8, None),
            NetworkMessage::Block(_) => (2u8, None),
            NetworkMessage::Headers(_) => (13u8, None),
            NetworkMessage::Ping(_) => (18u8, None),
            NetworkMessage::Pong(_) => (19u8, None),
            NetworkMessage::MerkleBlock(_) => (16u8, None),
            NetworkMessage::FilterLoad(_) => (8u8, None),
            NetworkMessage::FilterAdd(_) => (6u8, None),
            NetworkMessage::FilterClear => (7u8, None),
            NetworkMessage::GetCFilters(_) => (22u8, None),
            NetworkMessage::CFilter(_) => (23u8, None),
            NetworkMessage::GetCFHeaders(_) => (24u8, None),
            NetworkMessage::CFHeaders(_) => (25u8, None),
            NetworkMessage::GetCFCheckpt(_) => (26u8, None),
            NetworkMessage::CFCheckpt(_) => (27u8, None),
            NetworkMessage::SendCmpct(_) => (20u8, None),
            NetworkMessage::CmpctBlock(_) => (4u8, None),
            NetworkMessage::GetBlockTxn(_) => (10u8, None),
            NetworkMessage::BlockTxn(_) => (3u8, None),
            NetworkMessage::FeeFilter(_) => (5u8, None),
            NetworkMessage::AddrV2(_) => (28u8, None),
            NetworkMessage::Version(_)
            | NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::SendAddrV2
            | NetworkMessage::Alert(_)
            | NetworkMessage::Reject(_)
            | NetworkMessage::Unknown { .. } => (0u8, Some(self.payload.command())),
        };

        let mut len = command_byte.consensus_encode(writer)?;
        if let Some(cmd) = full_command {
            len += cmd.consensus_encode(writer)?;
        }

        // Encode the payload.
        len += self.payload.consensus_encode(writer)?;

        Ok(len)
    }
}

/// A list of bitcoin block headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersMessage(pub Vec<block::Header>);

impl HeadersMessage {
    /// Does each header point to the previous block hash in the list.
    pub fn is_connected(&self) -> bool {
        self.0
            .iter()
            .zip(self.0.iter().skip(1))
            .all(|(first, second)| first.block_hash().eq(&second.prev_blockhash))
    }

    /// Each header passes its own proof-of-work target.
    pub fn all_targets_satisfied(&self) -> bool {
        !self.0.iter().any(|header| {
            let target = header.target();
            let valid_pow = header.validate_pow(target);
            valid_pow.is_err()
        })
    }
}

impl Decodable for HeadersMessage {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = r.read_compact_size()?;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(crate::consensus::parse_failed_error(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(Self(ret))
    }

    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_MSG_SIZE.to_u64()))
    }
}

impl Decodable for RawNetworkMessage {
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
            "ping" =>
                NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
            "pong" =>
                NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
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
            "feefilter" => {
                NetworkMessage::FeeFilter(
                    u64::consensus_decode_from_finite_reader(&mut mem_d)?
                        .try_into()
                        .ok()
                        // Given some absurdly large value, using the maximum conveys that no
                        // transactions should be relayed to this peer.
                        .map_or(FeeRate::MAX, FeeRate::from_sat_per_kvb),
                )
            }
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
            5u8 => NetworkMessage::FeeFilter(
                u64::consensus_decode_from_finite_reader(r)?
                    .try_into()
                    .ok()
                    // Given some absurdly large value, using the maximum conveys that no
                    // transactions should be relayed to this peer.
                    .map_or(FeeRate::MAX, FeeRate::from_sat_per_kvb),
            ),
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
            18u8 => NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(r)?),
            19u8 => NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(r)?),
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

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Constructs a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = sha2_checksum(&data);
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
        let expected_checksum = sha2_checksum(&data);
        if expected_checksum != checksum {
            Err(encode::ParseError::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            }
            .into())
        } else {
            Ok(Self { data, checksum })
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
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = sha256d::hash(data);
    let checksum = checksum.to_byte_array();
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrPayload {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(Vec::<(u32, Address)>::arbitrary(u)?))
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
            14 => Ok(Self::Ping(u.arbitrary()?)),
            15 => Ok(Self::Pong(u.arbitrary()?)),
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
impl<'a> Arbitrary<'a> for RawNetworkMessage {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use std::net::Ipv4Addr;

    use bitcoin::bip152::BlockTransactionsRequest;
    use bitcoin::bip158::{FilterHash, FilterHeader};
    use bitcoin::block::{Block, BlockHash};
    use bitcoin::consensus::encode::{deserialize, deserialize_partial, serialize};
    use bitcoin::transaction::{Transaction, Txid};
    use hex_lit::hex;
    use units::BlockHeight;

    use super::*;
    use crate::address::AddrV2;
    use crate::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::message_compact_blocks::{GetBlockTxn, SendCmpct};
    use crate::message_filter::{
        CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
    };
    use crate::message_network::{Alert, Reject, RejectReason, VersionMessage};
    use crate::{ProtocolVersion, ServiceFlags};

    fn hash(array: [u8; 32]) -> sha256d::Hash { sha256d::Hash::from_byte_array(array) }

    #[test]
    fn full_round_ser_der_raw_network_message() {
        let version_msg: VersionMessage = deserialize(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
        let tx: Transaction = deserialize(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
        let block: Block = deserialize(&hex!("00608e2e094d41aecfbcbf8fe70cb60be57516b07db1bafee4c4de5dad760000000000004aec16eab3be95abe9c54e01cf850c14b8c5cad1bc6b2e73e811db5d5998ada404503e66fcff031b4ebd99d701010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3402983a000404503e6604f1f617271083bc3d6600000000000000000007bb1b0a636b706f6f6c0d506f72746c616e642e484f444cffffffff0200f2052a010000001976a9142ce72b25fe97b52638c199acfaa5e3891ddfed5b88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();
        let header: block::Header = deserialize(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
        let script = &hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac");
        let merkle_block: MerkleBlock = deserialize(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
        let cmptblock = deserialize(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
        let blocktxn = deserialize(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

        let msgs = [
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(AddrPayload(vec![(
                45,
                Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
            )])),
            NetworkMessage::Inv(InventoryPayload(vec![Inventory::Block(
                BlockHash::from_byte_array(hash([8u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::GetData(InventoryPayload(vec![Inventory::Transaction(
                Txid::from_byte_array(hash([45u8; 32]).to_byte_array()),
            )])),
            NetworkMessage::NotFound(InventoryPayload(vec![Inventory::Error([0u8; 32])])),
            NetworkMessage::GetBlocks(GetBlocksMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: vec![
                    BlockHash::from_byte_array(hash([1u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                ],
                stop_hash: BlockHash::from_byte_array(hash([5u8; 32]).to_byte_array()),
            }),
            NetworkMessage::GetHeaders(GetHeadersMessage {
                version: ProtocolVersion::from_nonstandard(70001),
                locator_hashes: vec![
                    BlockHash::from_byte_array(hash([10u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([40u8; 32]).to_byte_array()),
                ],
                stop_hash: BlockHash::from_byte_array(hash([50u8; 32]).to_byte_array()),
            }),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(tx),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(HeadersMessage(vec![header])),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(15),
            NetworkMessage::Pong(23),
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
            NetworkMessage::FeeFilter(FeeRate::BROADCAST_MIN),
            NetworkMessage::WtxidRelay,
            NetworkMessage::AddrV2(AddrV2Payload(vec![AddrV2Message {
                addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                services: ServiceFlags::NONE,
                time: 0,
            }])),
            NetworkMessage::SendAddrV2,
            NetworkMessage::CmpctBlock(cmptblock),
            NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: BlockHash::from_byte_array(hash([11u8; 32]).to_byte_array()),
                    indexes: vec![0, 1, 2, 3, 10, 3002],
                },
            }),
            NetworkMessage::BlockTxn(blocktxn),
            NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 8333 }),
        ];

        for msg in &msgs {
            // V1 messages.
            let raw_msg = RawNetworkMessage::new(Magic::from_bytes([57, 0, 0, 0]), msg.clone());
            assert_eq!(deserialize::<RawNetworkMessage>(&serialize(&raw_msg)).unwrap(), raw_msg);

            // V2 messages.
            let v2_msg = V2NetworkMessage::new(msg.clone());
            assert_eq!(deserialize::<V2NetworkMessage>(&serialize(&v2_msg)).unwrap(), v2_msg);
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
        assert_eq!(serialize(&cs), [0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);

        // Test deserializing
        let cs: Result<CommandString, _> =
            deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("Andrew").unwrap());

        // Test that embedded null bytes are preserved while trailing nulls are trimmed
        let cs: Result<CommandString, _> =
            deserialize(&[0, 0x41u8, 0x6e, 0x64, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "\0And\0rew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("\0And\0rew").unwrap());

        // Invalid CommandString, must be ASCII
        assert!(deserialize::<CommandString>(&[
            0, 0x41u8, 0x6e, 0xa4, 0, 0x72, 0x65, 0x77, 0, 0, 0, 0
        ])
        .is_err());

        // Invalid CommandString, must be 12 bytes
        assert!(deserialize::<CommandString>(&[
            0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0
        ])
        .is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_verack() {
        assert_eq!(serialize(&RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Verack)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                        0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_verack() {
        assert_eq!(
            serialize(&V2NetworkMessage::new(NetworkMessage::Verack)),
            [
                0x00, // Full command encoding flag.
                0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_ping() {
        assert_eq!(serialize(&RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Ping(100))),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn serialize_v2_ping() {
        assert_eq!(
            serialize(&V2NetworkMessage::new(NetworkMessage::Ping(100))),
            [
                0x12, // Ping command short ID
                0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_mempool() {
        assert_eq!(serialize(&RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::MemPool)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                        0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_mempool() {
        assert_eq!(
            serialize(&V2NetworkMessage::new(NetworkMessage::MemPool)),
            [
                0x0F, // MemPool command short ID
            ]
        );
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_getaddr() {
        assert_eq!(serialize(&RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::GetAddr)),
                       [0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                        0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_v2_getaddr() {
        assert_eq!(
            serialize(&V2NetworkMessage::new(NetworkMessage::GetAddr)),
            [
                0x00, // Full command encoding flag.
                0x67, 0x65, 0x74, 0x61, 0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn deserialize_getaddr() {
        #[rustfmt::skip]
        let msg = deserialize(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
            0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2
        ]);
        let preimage = RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::GetAddr);
        assert!(msg.is_ok());
        let msg: RawNetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_v2_getaddr() {
        let msg = deserialize(&[
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
        let msg = deserialize::<RawNetworkMessage>(&[
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
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn deserialize_v2_version() {
        #[rustfmt::skip]
        let msg = deserialize::<V2NetworkMessage>(&[
            0x00, // Full command encoding flag
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, // "version" command
            0x7f, 0x11, 0x01, 0x00, // version: 70015
            0x0d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
            0xf0, 0x0f, 0x4d, 0x5c, 0x00, 0x00, 0x00, 0x00, // timestamp: 1548554224
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // receiver services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, // addr_recv
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sender services: NONE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr_from
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1, // nonce
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68, 0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31, 0x2f, // user_agent: "/Satoshi:0.17.1/"
            0x93, 0x8c, 0x08, 0x00, // start_height: 560275
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
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message() {
        #[rustfmt::skip]
        let data = [
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
        let msg = deserialize_partial::<RawNetworkMessage>(&data);
        assert!(msg.is_ok());

        let (msg, consumed) = msg.unwrap();
        assert_eq!(consumed, data.to_vec().len() - 2);
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
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent.to_string(), "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn serialize_checkeddata() {
        let cd = CheckedData::new(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(serialize(&cd), [5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn deserialize_checkeddata() {
        let cd: Result<CheckedData, _> =
            deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData::new(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn headers_message() {
        let block_900_000 = deserialize::<block::Header>(
            &hex!("00a0ab20247d4d9f582f9750344cdf62c46d81d046be960340960100000000000000000070f96945530651135839d8adc3f40e595118ec74c7ad81a3d17bb022e554fb0c937f4268743702177ad05f92")
        ).unwrap();
        let block_900_001 = deserialize::<block::Header>(
            &hex!("00e000208a96960d6d1ca4ee4a283fd83da309b8d5d2bfed380501000000000000000000371c9ffd63d75fb36c57d58eb842d23c0e7ec049daf16d94cc38805c346e9d52e880426874370217973dc83b")
        ).unwrap();
        let block_900_002 = deserialize::<block::Header>(
            &hex!("0400ff3ffc834fac4e1eb2ae41f1f9776e0f8e24a6090603ffa8010000000000000000002efba7e7280aa60f0a650f29e30332d52e11af57bc58cc6e71f343851f016c676182426874370217e3615653")
        ).unwrap();
        let headers_message = HeadersMessage(vec![block_900_000, block_900_001, block_900_002]);
        assert!(headers_message.is_connected());
        assert!(headers_message.all_targets_satisfied());
    }
}
