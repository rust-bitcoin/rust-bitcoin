// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network messages.
//!
//! This module defines the `NetworkMessage` and `RawNetworkMessage` types that
//! are used for (de)serializing Bitcoin objects for transmission on the network.

use core::{fmt, iter};

use hashes::sha256d;
use internals::ToU64 as _;
use io::{BufRead, Write};

use crate::consensus::encode::{self, CheckedData, Decodable, Encodable, ReadExt, WriteExt};
use crate::merkle_tree::MerkleBlock;
use crate::p2p::address::{AddrV2Message, Address};
use crate::p2p::{
    message_blockdata, message_bloom, message_compact_blocks, message_filter, message_network,
    Magic,
};
use crate::prelude::{Box, Cow, String, ToOwned, Vec};
use crate::{block, consensus, transaction};

/// The maximum number of [super::message_blockdata::Inventory] items in an `inv` message.
///
/// This limit is not currently enforced by this implementation.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum size, in bytes, of an encoded message
/// This by necessity should be larger tham `MAX_VEC_SIZE`
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
    pub fn try_from_static(s: &'static str) -> Result<CommandString, CommandStringError> {
        Self::try_from_static_cow(s.into())
    }

    fn try_from_static_cow(cow: Cow<'static, str>) -> Result<CommandString, CommandStringError> {
        if cow.len() > 12 {
            Err(CommandStringError { cow })
        } else {
            Ok(CommandString(cow))
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
        let rv = iter::FromIterator::from_iter(rawbytes.iter().filter_map(|&u| {
            if u > 0 {
                Some(u as char)
            } else {
                None
            }
        }));
        Ok(CommandString(rv))
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

#[cfg(feature = "std")]
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

/// A Network message using the v2 p2p protocol defined in BIP324.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2NetworkMessage {
    payload: NetworkMessage,
}

/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(Vec<(u32, Address)>),
    /// `inv`
    Inv(Vec<message_blockdata::Inventory>),
    /// `getdata`
    GetData(Vec<message_blockdata::Inventory>),
    /// `notfound`
    NotFound(Vec<message_blockdata::Inventory>),
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
    Headers(Vec<block::Header>),
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
    /// BIP 37 `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// BIP 37 `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// BIP 37 `filterclear`
    FilterClear,
    /// BIP157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// BIP152 sendcmpct
    SendCmpct(message_compact_blocks::SendCmpct),
    /// BIP152 cmpctblock
    CmpctBlock(message_compact_blocks::CmpctBlock),
    /// BIP152 getblocktxn
    GetBlockTxn(message_compact_blocks::GetBlockTxn),
    /// BIP152 blocktxn
    BlockTxn(message_compact_blocks::BlockTxn),
    /// `alert`
    Alert(Vec<u8>),
    /// `reject`
    Reject(message_network::Reject),
    /// `feefilter`
    FeeFilter(i64),
    /// `wtxidrelay`
    WtxidRelay,
    /// `addrv2`
    AddrV2(Vec<AddrV2Message>),
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
    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        match *self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::MerkleBlock(_) => "merkleblock",
            NetworkMessage::FilterLoad(_) => "filterload",
            NetworkMessage::FilterAdd(_) => "filteradd",
            NetworkMessage::FilterClear => "filterclear",
            NetworkMessage::GetCFilters(_) => "getcfilters",
            NetworkMessage::CFilter(_) => "cfilter",
            NetworkMessage::GetCFHeaders(_) => "getcfheaders",
            NetworkMessage::CFHeaders(_) => "cfheaders",
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt",
            NetworkMessage::CFCheckpt(_) => "cfcheckpt",
            NetworkMessage::SendCmpct(_) => "sendcmpct",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::GetBlockTxn(_) => "getblocktxn",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::Alert(_) => "alert",
            NetworkMessage::Reject(_) => "reject",
            NetworkMessage::FeeFilter(_) => "feefilter",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::AddrV2(_) => "addrv2",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::Unknown { .. } => "unknown",
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        match *self {
            NetworkMessage::Unknown { command: ref c, .. } => c.clone(),
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

    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

impl V2NetworkMessage {
    /// Constructs a new [V2NetworkMessage].
    pub fn new(payload: NetworkMessage) -> Self { Self { payload } }

    /// Consumes the [V2NetworkMessage] instance and returns the inner payload.
    pub fn into_payload(self) -> NetworkMessage { self.payload }

    /// The actual message data
    pub fn payload(&self) -> &NetworkMessage { &self.payload }

    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str { self.payload.cmd() }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString { self.payload.command() }
}

struct HeaderSerializationWrapper<'a>(&'a Vec<block::Header>);

impl Encodable for HeaderSerializationWrapper<'_> {
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
            NetworkMessage::Version(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Addr(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Inv(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetData(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::NotFound(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetBlocks(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Tx(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Block(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Headers(ref dat) =>
                HeaderSerializationWrapper(dat).consensus_encode(writer),
            NetworkMessage::Ping(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Pong(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::MerkleBlock(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FilterLoad(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FilterAdd(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFilters(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFilter(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFHeaders(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetCFCheckpt(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CFCheckpt(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::SendCmpct(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::CmpctBlock(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::GetBlockTxn(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::BlockTxn(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Alert(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Reject(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::FeeFilter(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::AddrV2(ref dat) => dat.consensus_encode(writer),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::WtxidRelay
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => Ok(0),
            NetworkMessage::Unknown { payload: ref data, .. } => data.consensus_encode(writer),
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

struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
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
                return Err(consensus::parse_failed_error(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
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
                HeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0,
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
            "feefilter" => NetworkMessage::FeeFilter(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
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
        Ok(RawNetworkMessage { magic, payload, payload_len, checksum })
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
            5u8 => NetworkMessage::FeeFilter(Decodable::consensus_decode_from_finite_reader(r)?),
            6u8 => NetworkMessage::FilterAdd(Decodable::consensus_decode_from_finite_reader(r)?),
            7u8 => NetworkMessage::FilterClear,
            8u8 => NetworkMessage::FilterLoad(Decodable::consensus_decode_from_finite_reader(r)?),
            9u8 => NetworkMessage::GetBlocks(Decodable::consensus_decode_from_finite_reader(r)?),
            10u8 => NetworkMessage::GetBlockTxn(Decodable::consensus_decode_from_finite_reader(r)?),
            11u8 => NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(r)?),
            12u8 => NetworkMessage::GetHeaders(Decodable::consensus_decode_from_finite_reader(r)?),
            13u8 => NetworkMessage::Headers(
                HeaderDeserializationWrapper::consensus_decode_from_finite_reader(r)?.0,
            ),
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
        Ok(V2NetworkMessage { payload })
    }

    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_MSG_SIZE.to_u64()))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use hex::test_hex_unwrap as hex;
    use units::BlockHeight;

    use super::*;
    use crate::bip152::BlockTransactionsRequest;
    use crate::bip158::{FilterHash, FilterHeader};
    use crate::block::{Block, BlockHash};
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize};
    use crate::p2p::address::AddrV2;
    use crate::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::p2p::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};
    use crate::p2p::message_filter::{
        CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
    };
    use crate::p2p::message_network::{Reject, RejectReason, VersionMessage};
    use crate::p2p::ServiceFlags;
    use crate::script::ScriptBuf;
    use crate::transaction::{Transaction, Txid};

    fn hash(array: [u8; 32]) -> sha256d::Hash { sha256d::Hash::from_byte_array(array) }

    #[test]
    fn full_round_ser_der_raw_network_message() {
        let version_msg: VersionMessage = deserialize(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
        let tx: Transaction = deserialize(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
        let block: Block = deserialize(&include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw")[..]).unwrap();
        let header: block::Header = deserialize(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
        let script: ScriptBuf =
            deserialize(&hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac")).unwrap();
        let merkle_block: MerkleBlock = deserialize(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
        let cmptblock = deserialize(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
        let blocktxn = deserialize(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

        let msgs = [
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(vec![(
                45,
                Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
            )]),
            NetworkMessage::Inv(vec![Inventory::Block(BlockHash::from_byte_array(
                hash([8u8; 32]).to_byte_array(),
            ))]),
            NetworkMessage::GetData(vec![Inventory::Transaction(Txid::from_byte_array(
                hash([45u8; 32]).to_byte_array(),
            ))]),
            NetworkMessage::NotFound(vec![Inventory::Error([0u8; 32])]),
            NetworkMessage::GetBlocks(GetBlocksMessage::new(
                vec![
                    BlockHash::from_byte_array(hash([1u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([4u8; 32]).to_byte_array()),
                ],
                BlockHash::from_byte_array(hash([5u8; 32]).to_byte_array()),
            )),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(
                vec![
                    BlockHash::from_byte_array(hash([10u8; 32]).to_byte_array()),
                    BlockHash::from_byte_array(hash([40u8; 32]).to_byte_array()),
                ],
                BlockHash::from_byte_array(hash([50u8; 32]).to_byte_array()),
            )),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(tx),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(vec![header]),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(15),
            NetworkMessage::Pong(23),
            NetworkMessage::MerkleBlock(merkle_block),
            NetworkMessage::FilterLoad(FilterLoad {
                filter: hex!("03614e9b050000000000000001"),
                hash_funcs: 1,
                tweak: 2,
                flags: BloomFlags::All,
            }),
            NetworkMessage::FilterAdd(FilterAdd { data: script.as_bytes().to_vec() }),
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
            NetworkMessage::Alert(vec![45, 66, 3, 2, 6, 8, 9, 12, 3, 130]),
            NetworkMessage::Reject(Reject {
                message: "Test reject".into(),
                ccode: RejectReason::Duplicate,
                reason: "Cause".into(),
                hash: hash([255u8; 32]),
            }),
            NetworkMessage::FeeFilter(1000),
            NetworkMessage::WtxidRelay,
            NetworkMessage::AddrV2(vec![AddrV2Message {
                addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                services: ServiceFlags::NONE,
                time: 0,
            }]),
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

        let short_cs: Result<CommandString, _> =
            deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
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
            assert_eq!(version_msg.version, 70015);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
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
            assert_eq!(version_msg.version, 70015);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
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
            assert_eq!(version_msg.version, 70015);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::WITNESS
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("wrong message type");
        }
    }
}
