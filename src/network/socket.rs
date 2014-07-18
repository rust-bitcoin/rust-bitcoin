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

//! # Sockets
//!
//! This module provides support for low-level network communication.
//!

use time::now;
use std::rand::task_rng;
use rand::Rng;
use std::io::{IoError, IoResult, NotConnected, OtherIoError, standard_error};
use std::io::net::{ip, tcp};

use network::constants;
use network::address::Address;
use network::message::{RawNetworkMessage, NetworkMessage, Version};
use network::serialize::Serializable;
use network::message_network::VersionMessage;

/// Format an IP address in the 16-byte bitcoin protocol serialization
fn ipaddr_to_bitcoin_addr(ipaddr: &ip::IpAddr) -> [u8, ..16] {
  match *ipaddr {
    ip::Ipv4Addr(a, b, c, d) =>
        [0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0xff, 0xff, a, b, c, d],
    ip::Ipv6Addr(a, b, c, d, e, f, g, h) =>
        [(a / 0x100) as u8, (a % 0x100) as u8, (b / 0x100) as u8, (b % 0x100) as u8,
         (c / 0x100) as u8, (c % 0x100) as u8, (d / 0x100) as u8, (d % 0x100) as u8,
         (e / 0x100) as u8, (e % 0x100) as u8, (f / 0x100) as u8, (f % 0x100) as u8,
         (g / 0x100) as u8, (g % 0x100) as u8, (h / 0x100) as u8, (h % 0x100) as u8 ]
  } 
}

/// A network socket along with information about the peer
#[deriving(Clone)]
pub struct Socket {
  /// The underlying network data stream
  stream: Option<tcp::TcpStream>,
  /// Services supported by us
  pub services: u64,
  /// Our user agent
  pub user_agent: String,
  /// Nonce to identify our `version` messages
  pub version_nonce: u64,
  /// Network magic
  pub magic: u32
}

impl Socket {
  // TODO: we fix services to 0
  /// Construct a new socket
  pub fn new(network: constants::Network) -> Socket {
    let mut rng = task_rng();
    Socket {
      stream: None,
      services: 0,
      version_nonce: rng.gen(),
      user_agent: String::from_str(constants::USER_AGENT),
      magic: constants::magic(network)
    }
  }

  /// Connect to the peer
  pub fn connect(&mut self, host: &str, port: u16) -> IoResult<()> {
    match tcp::TcpStream::connect(host, port) {
      Ok(s)  => {
        self.stream = Some(s);
        Ok(()) 
      }
      Err(e) => Err(e)
    }
  }

  /// Peer address
  pub fn receiver_address(&mut self) -> IoResult<Address> {
    match self.stream {
      Some(ref mut s) => match s.peer_name() {
        Ok(addr) => {
          Ok(Address {
            services: self.services,
            address: ipaddr_to_bitcoin_addr(&addr.ip),
            port: addr.port
          })
        }
        Err(e) => Err(e)
      },
      None => Err(standard_error(NotConnected))
    }
  }

  /// Our own address
  pub fn sender_address(&mut self) -> IoResult<Address> {
    match self.stream {
      Some(ref mut s) => match s.socket_name() {
        Ok(addr) => {
          Ok(Address {
            services: self.services,
            address: ipaddr_to_bitcoin_addr(&addr.ip),
            port: addr.port
          })
        }
        Err(e) => Err(e)
      },
      None => Err(standard_error(NotConnected))
    }
  }

  /// Produce a version message appropriate for this socket
  pub fn version_message(&mut self, start_height: i32) -> IoResult<NetworkMessage> {
    let timestamp = now().to_timespec().sec;
    let recv_addr = self.receiver_address();
    let send_addr = self.sender_address();
    // If we are not connected, we might not be able to get these address.s
    match recv_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }
    match send_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }

    Ok(Version(VersionMessage {
      version: constants::PROTOCOL_VERSION,
      services: constants::SERVICES,
      timestamp: timestamp,
      receiver: recv_addr.unwrap(),
      sender: send_addr.unwrap(),
      nonce: self.version_nonce,
      user_agent: self.user_agent.clone(),
      start_height: start_height,
      relay: false
    }))
  }

  /// Send a general message across the line
  pub fn send_message(&mut self, payload: NetworkMessage) -> IoResult<()> {
    if self.stream.is_none() {
      Err(standard_error(NotConnected))
    }
    else {
      let stream = self.stream.get_mut_ref();
      let message = RawNetworkMessage { magic: self.magic, payload: payload };
      match stream.write(message.serialize().as_slice()) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
      }
    }
  }

  /// Receive the next message from the peer, decoding the network header
  /// and verifying its correctness. Returns the undecoded payload.
  pub fn receive_message(&mut self) -> IoResult<NetworkMessage> {
    match self.stream {
      None => Err(standard_error(NotConnected)),
      Some(ref mut s) => {
        let mut read_err = None;
        // We need a new scope since the closure in here borrows read_err,
        // and we try to read it afterward. Letting `iter` go out fixes it.
        let ret: IoResult<RawNetworkMessage> = {
          // Set up iterator so we will catch network errors properly
          let iter = s.bytes().filter_map(|res|
            match res {
              Ok(ch) => Some(ch),
              Err(e) => { read_err = Some(e); None }
            });
          // Receive message
          Serializable::deserialize(iter)
        };
        // Return
        match read_err {
          // Network errors get priority since they are probably more meaningful
          Some(e) => Err(e),
          _ => {
            match ret {
              // Next come parse errors
              Err(e) => Err(e),
              Ok(ret) => {
                // Finally magic (this should come before parse error, but we can't
                // get to it if the deserialization failed). TODO restructure this
                if ret.magic != self.magic {
                  Err(IoError {
                    kind: OtherIoError,
                    desc: "bad magic",
                    detail: Some(format!("got magic {:x}, expected {:x}", ret.magic, self.magic)),
                  })
                } else {
                  Ok(ret.payload)
                }
              }
            }
          }
        }
      }
    }
  }
}


