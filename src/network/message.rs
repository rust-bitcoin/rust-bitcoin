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

//! # Network message
//!
//! This module defines the `Message` traits which are used
//! for (de)serializing Bitcoin objects for transmission on the network. It
//! also defines (de)serialization routines for many primitives.
//!

use std::iter;
use std::io::Cursor;
use std::sync::mpsc::Sender;

use blockdata::block;
use blockdata::transaction;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::encodable::CheckedData;
use network::serialize::{serialize, RawDecoder, SimpleEncoder, SimpleDecoder};
use util::{self, propagate_err};

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(pub String);

impl<S: SimpleEncoder> ConsensusEncodable<S> for CommandString {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        let &CommandString(ref inner_str) = self;
        let mut rawbytes = [0u8; 12];
        let strbytes = inner_str.as_bytes();
        if strbytes.len() > 12 {
            panic!("Command string longer than 12 bytes");
        }
        for x in 0..strbytes.len() {
            rawbytes[x] = strbytes[x];
        }
        rawbytes.consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for CommandString {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<CommandString, D::Error> {
        let rawbytes: [u8; 12] = try!(ConsensusDecodable::consensus_decode(d));
        let rv = iter::FromIterator::from_iter(rawbytes.iter().filter_map(|&u| if u > 0 { Some(u as char) } else { None }));
        Ok(CommandString(rv))
    }
}

/// A Network message
pub struct RawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage
}

/// A response from the peer-connected socket
pub enum SocketResponse {
    /// A message was received
    MessageReceived(NetworkMessage),
    /// An error occured and the socket needs to close
    ConnectionFailed(util::Error, Sender<()>)
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
    Headers(Vec<block::LoneBlockHeader>),
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64)
    // TODO: reject,
    // TODO: bloom filtering
    // TODO: alert
}

impl RawNetworkMessage {
    fn command(&self) -> String {
        match self.payload {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack     => "verack",
            NetworkMessage::Addr(_)    => "addr",
            NetworkMessage::Inv(_)     => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool    => "mempool",
            NetworkMessage::Tx(_)      => "tx",
            NetworkMessage::Block(_)   => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetAddr    => "getaddr",
            NetworkMessage::Ping(_)    => "ping",
            NetworkMessage::Pong(_)    => "pong",
        }.to_owned()
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for RawNetworkMessage {
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        try!(self.magic.consensus_encode(s));
        try!(CommandString(self.command()).consensus_encode(s));
        try!(CheckedData(match self.payload {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Verack           => Ok(vec![]),
            NetworkMessage::Addr(ref dat)    => serialize(dat),
            NetworkMessage::Inv(ref dat)     => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::MemPool          => Ok(vec![]),
            NetworkMessage::Tx(ref dat)      => serialize(dat),
            NetworkMessage::Block(ref dat)   => serialize(dat),
            NetworkMessage::Headers(ref dat) => serialize(dat),
            NetworkMessage::GetAddr          => Ok(vec![]),
            NetworkMessage::Ping(ref dat)    => serialize(dat),
            NetworkMessage::Pong(ref dat)    => serialize(dat),
        }.unwrap()).consensus_encode(s));
        Ok(())
    }
}

// TODO: restriction on D::Error is so that `propagate_err` will work;
//       is there a more generic way to handle this?
impl<D: SimpleDecoder<Error=util::Error>> ConsensusDecodable<D> for RawNetworkMessage {
    fn consensus_decode(d: &mut D) -> Result<RawNetworkMessage, D::Error> {
        let magic = try!(ConsensusDecodable::consensus_decode(d));
        let CommandString(cmd): CommandString= try!(ConsensusDecodable::consensus_decode(d));
        let CheckedData(raw_payload): CheckedData = try!(ConsensusDecodable::consensus_decode(d));

        let mut mem_d = RawDecoder::new(Cursor::new(raw_payload));
        let payload = match &cmd[..] {
            "version" => NetworkMessage::Version(try!(propagate_err("version".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "verack"  => NetworkMessage::Verack,
            "addr"    => NetworkMessage::Addr(try!(propagate_err("addr".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "inv"     => NetworkMessage::Inv(try!(propagate_err("inv".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "getdata" => NetworkMessage::GetData(try!(propagate_err("getdata".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "notfound" => NetworkMessage::NotFound(try!(propagate_err("notfound".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "getblocks" => NetworkMessage::GetBlocks(try!(propagate_err("getblocks".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "getheaders" => NetworkMessage::GetHeaders(try!(propagate_err("getheaders".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "mempool" => NetworkMessage::MemPool,
            "block"   => NetworkMessage::Block(try!(propagate_err("block".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "headers" => NetworkMessage::Headers(try!(propagate_err("headers".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "getaddr" => NetworkMessage::GetAddr,
            "ping"    => NetworkMessage::Ping(try!(propagate_err("ping".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "pong"    => NetworkMessage::Pong(try!(propagate_err("pong".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            "tx"      => NetworkMessage::Tx(try!(propagate_err("tx".to_owned(), ConsensusDecodable::consensus_decode(&mut mem_d)))),
            cmd => return Err(d.error(format!("unrecognized network command `{}`", cmd)))
        };
        Ok(RawNetworkMessage {
            magic: magic,
            payload: payload
        })
    }
}

#[cfg(test)]
mod test {
    use super::{RawNetworkMessage, NetworkMessage, CommandString};

    use network::serialize::{deserialize, serialize};

    #[test]
    fn serialize_commandstring_test() {
        let cs = CommandString("Andrew".to_owned());
        assert_eq!(serialize(&cs).ok(), Some(vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn deserialize_commandstring_test() {
        let cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.unwrap(), CommandString("Andrew".to_owned()));

        let short_cs: Result<CommandString, _> = deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
    }

    #[test]
    fn serialize_verack_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Verack }).ok(),
                             Some(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                                       0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]));
    }

    #[test]
    fn serialize_ping_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Ping(100) }).ok(),
                             Some(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                                       0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    }


    #[test]
    fn serialize_mempool_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::MemPool }).ok(),
                             Some(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                                       0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                       0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]));
    }

    #[test]
    fn serialize_getaddr_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr }).ok(),
                             Some(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                                       0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]));
    }

}
