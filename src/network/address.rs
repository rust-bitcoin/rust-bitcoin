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

use network::serialize::{SimpleEncoder, SimpleDecoder};
use network::encodable::{ConsensusDecodable, ConsensusEncodable};

/// A message which can be sent on the Bitcoin network
pub struct Address {
  /// Services provided by the peer whose address this is
  pub services: u64,
  /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
  pub address: [u8; 16],
  /// Network port
  pub port: u16
}

impl<S:SimpleEncoder<E>, E> ConsensusEncodable<S, E> for Address {
  #[inline]
  fn consensus_encode(&self, s: &mut S) -> Result<(), E> {
    try!(self.services.consensus_encode(s));
    try!(self.address.consensus_encode(s));
    // Explicitly code the port since it needs to be big-endian
    try!(((self.port / 0x100) as u8).consensus_encode(s));
    try!(((self.port % 0x100) as u8).consensus_encode(s));
    Ok(())
  }
}

impl<D:SimpleDecoder<E>, E> ConsensusDecodable<D, E> for Address {
  #[inline]
  fn consensus_decode(d: &mut D) -> Result<Address, E> {
    Ok(Address {
      services: try!(ConsensusDecodable::consensus_decode(d)),
      address: try!(ConsensusDecodable::consensus_decode(d)),
      // Explicitly code the port since it needs to be big-endian
      port: {
        let b1: u8 = try!(ConsensusDecodable::consensus_decode(d));
        let b2: u8 = try!(ConsensusDecodable::consensus_decode(d));
        (b1 as u16 * 0x100) + (b2 as u16)
      }
    })
  }
}

impl fmt::Debug for Address {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    // TODO: render services and hex-ize address
    write!(f, "Address {{services: {}, address: {}, port: {}}}",
              self.services, self.address.as_slice(), self.port)
  }
}

impl Clone for Address {
  fn clone(&self) -> Address {
    unsafe {
      use std::intrinsics::copy_nonoverlapping_memory;
      use std::mem;
      let mut ret = mem::uninitialized();
      copy_nonoverlapping_memory(&mut ret,
                                 self,
                                 mem::size_of::<Address>());
      ret
    }
  }
}

impl PartialEq for Address {
  fn eq(&self, other: &Address) -> bool {
    self.services == other.services &&
    self.address.as_slice() == other.address.as_slice() &&
    self.port == other.port
  }
}

impl Eq for Address {}

#[cfg(test)]
mod test {
  use super::Address;

  use std::io::IoResult;

  use network::serialize::{deserialize, serialize};

  #[test]
  fn serialize_address_test() {
    assert_eq!(serialize(&Address {
      services: 1,
      address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1],
      port: 8333
    }),
    Ok(vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1, 0x20, 0x8d]));
  }

  #[test]
  fn deserialize_address_test() {
    let mut addr: IoResult<Address> = deserialize(vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                       0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0,
                                                       0, 1, 0x20, 0x8d]);
    assert!(addr.is_ok());
    let full = addr.unwrap();
    assert!(full.services == 1);
    assert!(full.address == [0u8,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1]);
    assert!(full.port == 8333);

    addr = deserialize(vec![1u8, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1]);
    assert!(addr.is_err());
  }
}

