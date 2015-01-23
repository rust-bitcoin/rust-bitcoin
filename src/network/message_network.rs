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

//! # Network-related network messages
//!
//! This module defines network messages which describe peers and their
//! capabilities
//!

use std::io::IoResult;

use network::constants;
use network::address::Address;
use network::socket::Socket;

/// Some simple messages

/// The `version` message
#[deriving(PartialEq, Eq, Clone, Show)]
pub struct VersionMessage {
  /// The P2P network protocol version
  pub version: u32,
  /// A bitmask describing the services supported by this node
  pub services: u64,
  /// The time at which the `version` message was sent
  pub timestamp: i64,
  /// The network address of the peer receiving the message
  pub receiver: Address,
  /// The network address of the peer sending the message
  pub sender: Address,
  /// A random nonce used to detect loops in the network
  pub nonce: u64,
  /// A string describing the peer's software
  pub user_agent: String,
  /// The height of the maxmimum-work blockchain that the peer is aware of
  pub start_height: i32,
  /// Whether the receiving peer should relay messages to the sender; used
  /// if the sender is bandwidth-limited and would like to support bloom
  /// filtering. Defaults to true.
  pub relay: bool
}

impl VersionMessage {
  // TODO: we have fixed services and relay to 0
  /// Constructs a new `version` message
  pub fn new(timestamp: i64, mut socket: Socket, nonce: u64, start_height: i32) -> IoResult<VersionMessage> {
    let recv_addr = socket.receiver_address();
    let send_addr = socket.sender_address();
    // If we are not connected, we might not be able to get these address.s
    match recv_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }
    match send_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }
    Ok(VersionMessage {
      version: constants::PROTOCOL_VERSION,
      services: socket.services,
      timestamp: timestamp,
      receiver: recv_addr.unwrap(),
      sender: send_addr.unwrap(),
      nonce: nonce,
      user_agent: socket.user_agent,
      start_height: start_height,
      relay: false
    })
  }
}

impl_consensus_encoding!(VersionMessage, version, services, timestamp,
                                         receiver, sender, nonce,
                                         user_agent, start_height, relay);

#[cfg(test)]
mod tests {
  use super::VersionMessage;

  use std::io::IoResult;
  use serialize::hex::FromHex;

  use network::serialize::{deserialize, serialize};

  #[test]
  fn version_message_test() {
    // This message is from my satoshi node, morning of May 27 2014
    let from_sat = "721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001".from_hex().unwrap();

    let decode: IoResult<VersionMessage> = deserialize(from_sat.clone());
    assert!(decode.is_ok());
    let real_decode = decode.unwrap();
    assert_eq!(real_decode.version, 70002);
    assert_eq!(real_decode.services, 1);
    assert_eq!(real_decode.timestamp, 1401217254);
    // address decodes should be covered by Address tests
    assert_eq!(real_decode.nonce, 16735069437859780935);
    assert_eq!(real_decode.user_agent, String::from_str("/Satoshi:0.9.99/"));
    assert_eq!(real_decode.start_height, 302892);
    assert_eq!(real_decode.relay, true);

    assert_eq!(serialize(&real_decode), Ok(from_sat));
  }
}



