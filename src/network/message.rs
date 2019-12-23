// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network message
//!
//! This module defines the `Message` traits which are used
//! for (de)serializing Bitcoin objects for transmission on the network. It
//! also defines (de)serialization routines for many primitives.
//!

use std::{io, iter, mem, fmt};
use std::borrow::Cow;
use std::io::Cursor;

use blockdata::block;
use blockdata::transaction;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use network::message_filter;
use consensus::encode::{CheckedData, Decodable, Encodable, VarInt};
use consensus::{encode, serialize};
use consensus::encode::MAX_VEC_SIZE;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl From<&'static str> for CommandString {
    fn from(f: &'static str) -> Self {
        CommandString(f.into())
    }
}

impl From<String> for CommandString {
    fn from(f: String) -> Self {
        CommandString(f.into())
    }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Encodable for CommandString {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        s: S,
    ) -> Result<usize, encode::Error> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        if strbytes.len() > 12 {
            return Err(encode::Error::UnrecognizedNetworkCommand(self.0.clone().into_owned()));
        }
        for x in 0..strbytes.len() {
            rawbytes[x] = strbytes[x];
        }
        rawbytes.consensus_encode(s)
    }
}

impl Decodable for CommandString {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(d)?;
        let rv = iter::FromIterator::from_iter(
            rawbytes
                .iter()
                .filter_map(|&u| if u > 0 { Some(u as char) } else { None })
        );
        Ok(CommandString(rv))
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A Network message
pub struct RawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
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
    Headers(Vec<block::BlockHeader>),
    /// `sendheaders`
    SendHeaders,
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    // TODO: bloom filtering
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
    /// `alert`
    Alert(Vec<u8>),
    /// `reject`
    Reject(message_network::Reject)
}

impl NetworkMessage {
    /// Return the CommandString for the message command.
    pub fn command(&self) -> &'static CommandString {
        match *self {
            NetworkMessage::Version(_) => &Self::possibilites()[0],
            NetworkMessage::Verack => &Self::possibilites()[1],
            NetworkMessage::Addr(_) => &Self::possibilites()[2],
            NetworkMessage::Inv(_) => &Self::possibilites()[3],
            NetworkMessage::GetData(_) => &Self::possibilites()[4],
            NetworkMessage::NotFound(_) => &Self::possibilites()[5],
            NetworkMessage::GetBlocks(_) => &Self::possibilites()[6],
            NetworkMessage::GetHeaders(_) => &Self::possibilites()[7],
            NetworkMessage::MemPool => &Self::possibilites()[8],
            NetworkMessage::Tx(_) => &Self::possibilites()[9],
            NetworkMessage::Block(_) => &Self::possibilites()[10],
            NetworkMessage::Headers(_) => &Self::possibilites()[11],
            NetworkMessage::SendHeaders => &Self::possibilites()[12],
            NetworkMessage::GetAddr => &Self::possibilites()[13],
            NetworkMessage::Ping(_) => &Self::possibilites()[14],
            NetworkMessage::Pong(_) => &Self::possibilites()[15],
            NetworkMessage::GetCFilters(_) => &Self::possibilites()[16],
            NetworkMessage::CFilter(_) => &Self::possibilites()[17],
            NetworkMessage::GetCFHeaders(_) => &Self::possibilites()[18],
            NetworkMessage::CFHeaders(_) => &Self::possibilites()[19],
            NetworkMessage::GetCFCheckpt(_) => &Self::possibilites()[20],
            NetworkMessage::CFCheckpt(_) => &Self::possibilites()[21],
            NetworkMessage::Alert(_) => &Self::possibilites()[22],
            NetworkMessage::Reject(_) => &Self::possibilites()[23],
        }
    }
    /// Returns a list of all supported commands.
    pub fn possibilites() -> &'static [CommandString] {
        &[
            CommandString(Cow::Borrowed("version")),
            CommandString(Cow::Borrowed("verack")),
            CommandString(Cow::Borrowed("addr")),
            CommandString(Cow::Borrowed("inv")),
            CommandString(Cow::Borrowed("getdata")),
            CommandString(Cow::Borrowed("notfound")),
            CommandString(Cow::Borrowed("getblocks")),
            CommandString(Cow::Borrowed("getheaders")),
            CommandString(Cow::Borrowed("mempool")),
            CommandString(Cow::Borrowed("tx")),
            CommandString(Cow::Borrowed("block")),
            CommandString(Cow::Borrowed("headers")),
            CommandString(Cow::Borrowed("sendheaders")),
            CommandString(Cow::Borrowed("getaddr")),
            CommandString(Cow::Borrowed("ping")),
            CommandString(Cow::Borrowed("pong")),
            CommandString(Cow::Borrowed("getcfilters")),
            CommandString(Cow::Borrowed("cfilter")),
            CommandString(Cow::Borrowed("getcfheaders")),
            CommandString(Cow::Borrowed("cfheaders")),
            CommandString(Cow::Borrowed("getcfcheckpt")),
            CommandString(Cow::Borrowed("cfcheckpt")),
            CommandString(Cow::Borrowed("alert")),
            CommandString(Cow::Borrowed("reject")),
        ]
    }
}

impl RawNetworkMessage {
    /// Return the CommandString for the message command.
    pub fn command(&self) -> &'static CommandString {
        self.payload.command()
    }
}

struct HeaderSerializationWrapper<'a>(&'a Vec<block::BlockHeader>);

impl<'a> Encodable for HeaderSerializationWrapper<'a> {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(&mut s)?;
        for header in self.0.iter() {
            len += header.consensus_encode(&mut s)?;
            len += 0u8.consensus_encode(&mut s)?;
        }
        Ok(len)
    }
}

impl Encodable for RawNetworkMessage {
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(&mut s)?;
        len += self.command().consensus_encode(&mut s)?;
        len += CheckedData(match self.payload {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat)    => serialize(dat),
            NetworkMessage::Inv(ref dat)     => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat)      => serialize(dat),
            NetworkMessage::Block(ref dat)   => serialize(dat),
            NetworkMessage::Headers(ref dat) => serialize(&HeaderSerializationWrapper(dat)),
            NetworkMessage::Ping(ref dat)    => serialize(dat),
            NetworkMessage::Pong(ref dat)    => serialize(dat),
            NetworkMessage::GetCFilters(ref dat) => serialize(dat),
            NetworkMessage::CFilter(ref dat) => serialize(dat),
            NetworkMessage::GetCFHeaders(ref dat) => serialize(dat),
            NetworkMessage::CFHeaders(ref dat) => serialize(dat),
            NetworkMessage::GetCFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::CFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::Alert(ref dat)    => serialize(dat),
            NetworkMessage::Reject(ref dat) => serialize(dat),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr => vec![],
        }).consensus_encode(&mut s)?;
        Ok(len)
    }
}

struct HeaderDeserializationWrapper(Vec<block::BlockHeader>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let byte_size = (len as usize)
                            .checked_mul(mem::size_of::<block::BlockHeader>())
                            .ok_or(encode::Error::ParseFailed("Invalid length"))?;
        if byte_size > MAX_VEC_SIZE {
            return Err(encode::Error::OversizedVectorAllocation { requested: byte_size, max: MAX_VEC_SIZE })
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
            if u8::consensus_decode(&mut d)? != 0u8 {
                return Err(encode::Error::ParseFailed("Headers message should not contain transactions"));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }
}

impl Decodable for RawNetworkMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode(&mut d)?;
        let cmd = CommandString::consensus_decode(&mut d)?.0;
        let raw_payload = CheckedData::consensus_decode(&mut d)?.0;

        let mut mem_d = Cursor::new(raw_payload);
        let payload = match &cmd[..] {
            "version" => NetworkMessage::Version(Decodable::consensus_decode(&mut mem_d)?),
            "verack"  => NetworkMessage::Verack,
            "addr"    => NetworkMessage::Addr(Decodable::consensus_decode(&mut mem_d)?),
            "inv"     => NetworkMessage::Inv(Decodable::consensus_decode(&mut mem_d)?),
            "getdata" => NetworkMessage::GetData(Decodable::consensus_decode(&mut mem_d)?),
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode(&mut mem_d)?),
            "getblocks" => NetworkMessage::GetBlocks(Decodable::consensus_decode(&mut mem_d)?),
            "getheaders" => NetworkMessage::GetHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "mempool" => NetworkMessage::MemPool,
            "block"   => NetworkMessage::Block(Decodable::consensus_decode(&mut mem_d)?),
            "headers" => NetworkMessage::Headers(
                HeaderDeserializationWrapper::consensus_decode(&mut mem_d)?.0
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getaddr" => NetworkMessage::GetAddr,
            "ping"    => NetworkMessage::Ping(Decodable::consensus_decode(&mut mem_d)?),
            "pong"    => NetworkMessage::Pong(Decodable::consensus_decode(&mut mem_d)?),
            "tx"      => NetworkMessage::Tx(Decodable::consensus_decode(&mut mem_d)?),
            "getcfilters" => NetworkMessage::GetCFilters(Decodable::consensus_decode(&mut mem_d)?),
            "cfilter" => NetworkMessage::CFilter(Decodable::consensus_decode(&mut mem_d)?),
            "getcfheaders" => NetworkMessage::GetCFHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "cfheaders" => NetworkMessage::CFHeaders(Decodable::consensus_decode(&mut mem_d)?),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(Decodable::consensus_decode(&mut mem_d)?),
            "cfcheckpt" => NetworkMessage::CFCheckpt(Decodable::consensus_decode(&mut mem_d)?),
            "reject" => NetworkMessage::Reject(Decodable::consensus_decode(&mut mem_d)?),
            "alert"   => NetworkMessage::Alert(Decodable::consensus_decode(&mut mem_d)?),
            _ => return Err(encode::Error::UnrecognizedNetworkCommand(cmd.into_owned())),
        };
        Ok(RawNetworkMessage {
            magic: magic,
            payload: payload
        })
    }
}

#[cfg(test)]
mod test {
    use super::{CommandString, NetworkMessage, RawNetworkMessage};
    use consensus::encode::{deserialize, deserialize_partial, serialize, Encodable};
    use network::constants::ServiceFlags;
    use secp256k1::rand::prelude::SmallRng;
    use secp256k1::rand::{thread_rng, Rng, SeedableRng};
    use std::io;
    use test_rand_types::gen_vec;

    #[test]
    fn full_round_ser_der_raw_network_message_test() {
        let mut rng = SmallRng::from_rng(thread_rng()).unwrap();
        let msgs = vec![
            NetworkMessage::Version(rng.gen()),
            NetworkMessage::Verack,
            NetworkMessage::Addr(gen_vec(&mut rng)),
            NetworkMessage::Inv(gen_vec(&mut rng)),
            NetworkMessage::GetData(gen_vec(&mut rng)),
            NetworkMessage::NotFound(gen_vec(&mut rng)),
            NetworkMessage::GetBlocks(rng.gen()),
            NetworkMessage::GetHeaders(rng.gen()),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(rng.gen()),
            NetworkMessage::Block(rng.gen()),
            NetworkMessage::Headers(gen_vec(&mut rng)),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(rng.gen()),
            NetworkMessage::Pong(rng.gen()),
            NetworkMessage::GetCFilters(rng.gen()),
            NetworkMessage::CFilter(rng.gen()),
            NetworkMessage::GetCFHeaders(rng.gen()),
            NetworkMessage::CFHeaders(rng.gen()),
            NetworkMessage::GetCFCheckpt(rng.gen()),
            NetworkMessage::CFCheckpt(rng.gen()),
            NetworkMessage::Alert(gen_vec(&mut rng)),
            NetworkMessage::Reject(rng.gen()),
        ];

        for msg in msgs {
            let raw_msg = RawNetworkMessage {magic: 57, payload: msg};
            assert_eq!(deserialize::<RawNetworkMessage>(&serialize(&raw_msg)).unwrap(), raw_msg);
        }
    }

    #[test]
    fn serialize_commandstring_test() {
        let cs = CommandString("Andrew".into());
        assert_eq!(serialize(&cs), vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);

        // Test oversized one.
        let mut encoder = io::Cursor::new(vec![]);
        assert!(CommandString("AndrewAndrewA".into()).consensus_encode(&mut encoder).is_err());
    }

    #[test]
    fn deserialize_commandstring_test() {
        let cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), "Andrew".into());

        let short_cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
    }

    #[test]
    fn serialize_verack_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Verack }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                                  0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_ping_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Ping(100) }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                                  0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }


    #[test]
    fn serialize_mempool_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::MemPool }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                                  0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn serialize_getaddr_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr }),
                             vec![0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                                  0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn deserialize_getaddr_test() {
        let msg = deserialize(
            &[0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
        let preimage = RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr };
        assert!(msg.is_ok());
        let msg : RawNetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_version_test() {
        let msg = deserialize::<RawNetworkMessage>(
            &[  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
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
                0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01 ]);

        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message_test() {
        let data = [  0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
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
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0, 0 ];
        let msg = deserialize_partial::<RawNetworkMessage>(&data);
        assert!(msg.is_ok());

        let (msg, consumed) = msg.unwrap();
        assert_eq!(consumed, data.to_vec().len() - 2);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(version_msg.services, ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::WITNESS | ServiceFlags::NETWORK_LIMITED);
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert_eq!(version_msg.relay, true);
        } else {
            panic!("Wrong message type");
        }
    }
}
