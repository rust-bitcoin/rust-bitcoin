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
use std::io::{IoError, IoResult, InvalidInput, OtherIoError, standard_error};

use blockdata::block;
use network::address::Address;
use network::message_network;
use network::message_blockdata;
use network::serialize::{Serializable, CheckedData};
use util::iter::FixedTakeable;
use util::misc::prepend_err;

/// Serializer for command string
#[deriving(PartialEq, Clone, Show)]
pub struct CommandString(pub String);

impl Serializable for CommandString {
  fn serialize(&self) -> Vec<u8> {
    let &CommandString(ref inner_str) = self;
    let mut rawbytes = [0u8, ..12]; 
    rawbytes.copy_from(inner_str.as_bytes().as_slice());
    Vec::from_slice(rawbytes.as_slice())
  }

  fn deserialize<I: Iterator<u8>>(iter: I) -> IoResult<CommandString> {
    let mut fixiter = iter.fixed_take(12);
    let rv: String = FromIterator::from_iter(fixiter.by_ref().filter_map(|u| if u > 0 { Some(u as char) } else { None }));
    // Once we've read the string, run out the iterator
    for _ in fixiter {}
    match fixiter.is_err() {
      false => Ok(CommandString(rv)),
      true => Err(standard_error(InvalidInput))
    }
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

impl Serializable for RawNetworkMessage {
  fn serialize(&self) -> Vec<u8> {
    let mut ret = vec![];
    ret.extend(self.magic.serialize().move_iter());
    ret.extend(CommandString(self.command()).serialize().move_iter());
    let payload_data = match self.payload {
      Version(ref dat) => dat.serialize(),
      Verack           => vec![],
      Addr(ref dat)    => dat.serialize(),
      Inv(ref dat)     => dat.serialize(),
      GetData(ref dat) => dat.serialize(),
      NotFound(ref dat) => dat.serialize(),
      GetBlocks(ref dat) => dat.serialize(),
      GetHeaders(ref dat) => dat.serialize(),
      Block(ref dat)   => dat.serialize(),
      Headers(ref dat) => dat.serialize(),
      Ping(ref dat)    => dat.serialize(),
      Pong(ref dat)    => dat.serialize()
    };
    ret.extend(CheckedData(payload_data).serialize().move_iter());
    ret
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<RawNetworkMessage> {
    let magic = try!(prepend_err("magic", Serializable::deserialize(iter.by_ref())));
    let CommandString(cmd): CommandString = try!(prepend_err("command", Serializable::deserialize(iter.by_ref())));
    let CheckedData(raw_payload): CheckedData = try!(prepend_err("payload", Serializable::deserialize(iter.by_ref())));
    let payload = match cmd.as_slice() {
      "version" => Version(try!(prepend_err("version", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "verack"  => Verack,
      "addr"    => Addr(try!(prepend_err("addr", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "inv"     => Inv(try!(prepend_err("inv", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "getdata" => GetData(try!(prepend_err("getdata", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "notfound" => NotFound(try!(prepend_err("notfound", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "getblocks" => GetBlocks(try!(prepend_err("getblocks", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "getheaders" => GetHeaders(try!(prepend_err("getheaders", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "block"   => Block(try!(prepend_err("block", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "headers" => Headers(try!(prepend_err("headers", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "ping"    => Ping(try!(prepend_err("ping", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
      "pong"    => Ping(try!(prepend_err("pong", Serializable::deserialize(raw_payload.iter().map(|n| *n))))),
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
  use std::io::IoResult;

  use network::message::CommandString;
  use network::serialize::Serializable;

  #[test]
  fn serialize_commandstring_test() {
    let cs = CommandString(String::from_str("Andrew"));
    assert_eq!(cs.serialize(), vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
  }

  #[test]
  fn deserialize_commandstring_test() {
    let cs: IoResult<CommandString> = Serializable::deserialize([0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0].iter().map(|n| *n));
    assert!(cs.is_ok());
    assert_eq!(cs.unwrap(), CommandString(String::from_str("Andrew")));

    let short_cs: IoResult<CommandString> = Serializable::deserialize([0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0].iter().map(|n| *n));
    assert!(short_cs.is_err());
  }

  // TODO: write tests for full network messages
}

