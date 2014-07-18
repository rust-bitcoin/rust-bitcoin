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

//! # Bitcoin network addresses
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.
//!

use std::fmt;
use std::io::{IoResult, standard_error, InvalidInput};

use network::serialize::Serializable;

/// A message which can be sent on the Bitcoin network
pub struct Address {
  /// Services provided by the peer whose address this is
  pub services: u64,
  /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
  pub address: [u8, ..16],
  /// Network port
  pub port: u16
}

impl Serializable for Address {
  fn serialize(&self) -> Vec<u8> {
    let mut rv = vec!();
    rv.extend(self.services.serialize().move_iter());
    rv.extend(self.address.iter().map(|n| *n));
    // Explicitly code the port since it needs to be big-endian
    rv.extend([(self.port / 256) as u8, (self.port % 256) as u8].iter().map(|n| *n));
    rv
  }

  fn deserialize<I: Iterator<u8>>(mut iter: I) -> IoResult<Address> {
    let ret = Address {
      services: try!(Serializable::deserialize(iter.by_ref())),
      address: try!(Serializable::deserialize(iter.by_ref())),
      // Explicitly code the port since it needs to be big-endian
      port: {
        let b1 = iter.next();
        let b2 = iter.next();
        if b1.is_none() || b2.is_none() {
          return Err(standard_error(InvalidInput));
        }
        (b1.unwrap() as u16) * 0x100 + (b2.unwrap() as u16)
      }
    };
    Ok(ret)
  }
}

impl fmt::Show for Address {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    // TODO: render services and hex-ize address
    write!(f, "Address {{services: {}, address: {}, port: {}}}",
              self.services, self.address.as_slice(), self.port)
  }
}

#[test]
fn serialize_address_test() {
  assert!(Address {
    services: 1,
    address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1],
    port: 8333
  }.serialize() == Vec::from_slice([1u8, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
                                    0x20, 0x8d]));
}

#[test]
fn deserialize_address_test() {
  let mut addr: IoResult<Address> = Serializable::deserialize([1u8, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
                                    0x20, 0x8d].iter().map(|n| *n));
  assert!(addr.is_ok())
  let full = addr.unwrap();
  assert!(full.services == 1);
  assert!(full.address == [0u8,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1]);
  assert!(full.port == 8333);

  addr = Serializable::deserialize([1u8, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1].iter().map(|n| *n));
  assert!(addr.is_err());
}



