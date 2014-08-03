// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

use collections::Vec;
use std::io::{IoError, IoResult, OtherIoError};
use std::io::MemReader;

use blockdata::block;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use network::encodable::{ConsensusDecodable, ConsensusEncodable};
use network::encodable::CheckedData;
use network::serialize::{serialize, RawDecoder, SimpleEncoder, SimpleDecoder};
use util::misc::prepend_err;

/// Serializer for command string
#[deriving(PartialEq, Clone, Show)]
pub struct CommandString(pub String);

impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for CommandString {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    let &CommandString(ref inner_str) = self;
    let mut rawbytes = [0u8, ..12]; 
    rawbytes.copy_from(inner_str.as_bytes().as_slice());
    rawbytes.consensus_encode(s)
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for CommandString {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<CommandString, E> {
    let rawbytes: [u8, ..12] = try!(ConsensusDecodable::consensus_decode(d)); 
    let rv: String = FromIterator::from_iter(rawbytes.iter().filter_map(|&u| if u > 0 { Some(u as char) } else { None }));
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

#[deriving(Show)]
/// A Network message payload. Proper documentation is available on the Bitcoin
/// wiki https://en.bitcoin.it/wiki/Protocol_specification
pub enum NetworkMessage{
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
  // TODO: tx,
  /// `block`
  Block(block::Block),
  /// `headers`
  Headers(Vec<block::LoneBlockHeader>),
  // TODO: getaddr,
  // TODO: mempool,
  // TODO: checkorder,
  // TODO: submitorder,
  // TODO: reply,
  /// `ping`
  Ping(u64),
  /// `pong`
  Pong(u64),
  // TODO: reject,
  // TODO: bloom filtering
  // TODO: alert
}

impl RawNetworkMessage {
  fn command(&self) -> String {
    match self.payload {
      Version(_) => "version",
      Verack     => "verack",
      Addr(_)    => "addr",
      Inv(_)     => "inv",
      GetData(_) => "getdata",
      NotFound(_) => "notfound",
      GetBlocks(_) => "getblocks",
      GetHeaders(_) => "getheaders",
      Block(_)   => "block",
      Headers(_) => "headers",
      Ping(_)    => "ping",
      Pong(_)    => "pong"
    }.to_string()
  }
}

impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for RawNetworkMessage {
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    try!(self.magic.consensus_encode(s));
    try!(CommandString(self.command()).consensus_encode(s));
    try!(CheckedData(match self.payload {
      Version(ref dat) => serialize(dat),
      Verack           => Ok(vec![]),
      Addr(ref dat)    => serialize(dat),
      Inv(ref dat)     => serialize(dat),
      GetData(ref dat) => serialize(dat),
      NotFound(ref dat) => serialize(dat),
      GetBlocks(ref dat) => serialize(dat),
      GetHeaders(ref dat) => serialize(dat),
      Block(ref dat)   => serialize(dat),
      Headers(ref dat) => serialize(dat),
      Ping(ref dat)    => serialize(dat),
      Pong(ref dat)    => serialize(dat),
    }.unwrap()).consensus_encode(s));
    Ok(())
  }
}

impl<D:SimpleDecoder<IoError>> ConsensusDecodable<D, IoError> for RawNetworkMessage {
  fn consensus_decode(d: &mut D) -> IoResult<RawNetworkMessage> {
    let magic = try!(ConsensusDecodable::consensus_decode(d));
    let CommandString(cmd): CommandString= try!(ConsensusDecodable::consensus_decode(d));
    let CheckedData(raw_payload): CheckedData = try!(ConsensusDecodable::consensus_decode(d));

    let mut mem_d = RawDecoder::new(MemReader::new(raw_payload));
    let payload = match cmd.as_slice() {
      "version" => Version(try!(prepend_err("version", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "verack"  => Verack,
      "addr"    => Addr(try!(prepend_err("addr", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "inv"     => Inv(try!(prepend_err("inv", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "getdata" => GetData(try!(prepend_err("getdata", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "notfound" => NotFound(try!(prepend_err("notfound", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "getblocks" => GetBlocks(try!(prepend_err("getblocks", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "getheaders" => GetHeaders(try!(prepend_err("getheaders", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "block"   => Block(try!(prepend_err("block", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "headers" => Headers(try!(prepend_err("headers", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "ping"    => Ping(try!(prepend_err("ping", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      "pong"    => Ping(try!(prepend_err("pong", ConsensusDecodable::consensus_decode(&mut mem_d)))),
      cmd => {
        return Err(IoError {
                     kind: OtherIoError,
                     desc: "unknown message type",
                     detail: Some(format!("`{}` not recognized", cmd))
                  });
      }
    };
    Ok(RawNetworkMessage {
      magic: magic,
      payload: payload
    })
  }
}

#[cfg(test)]
mod test {
  use super::{RawNetworkMessage, CommandString, Verack, Ping};

  use std::io::IoResult;

  use network::serialize::{deserialize, serialize};

  #[test]
  fn serialize_commandstring_test() {
    let cs = CommandString(String::from_str("Andrew"));
    assert_eq!(serialize(&cs), Ok(vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]));
  }

  #[test]
  fn deserialize_commandstring_test() {
    let cs: IoResult<CommandString> = deserialize(vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
    assert!(cs.is_ok());
    assert_eq!(cs.unwrap(), CommandString(String::from_str("Andrew")));

    let short_cs: IoResult<CommandString> = deserialize(vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
    assert!(short_cs.is_err());
  }

  #[test]
  fn serialize_verack_test() {
    assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: Verack }),
               Ok(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                       0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]));
  }

  #[test]
  fn serialize_ping_test() {
    assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: Ping(100) }),
               Ok(vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                       0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
  }
}

