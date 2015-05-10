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
    pub address: [u16; 8],
    /// Network port
    pub port: u16
}

fn addr_to_be(addr: [u16; 8]) -> [u16; 8] {
    [addr[0].to_be(), addr[1].to_be(), addr[2].to_be(), addr[3].to_be(),
     addr[4].to_be(), addr[5].to_be(), addr[6].to_be(), addr[7].to_be()]
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Address {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), S::Error> {
        try!(self.services.consensus_encode(s));
        try!(addr_to_be(self.address).consensus_encode(s));
        self.port.to_be().consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Address {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<Address, D::Error> {
        Ok(Address {
            services: try!(ConsensusDecodable::consensus_decode(d)),
            address: addr_to_be(try!(ConsensusDecodable::consensus_decode(d))),
            port: u16::from_be(try!(ConsensusDecodable::consensus_decode(d)))
        })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: render services and hex-ize address
        write!(f, "Address {{services: {:?}, address: {:?}, port: {:?}}}",
               self.services, &self.address[..], self.port)
    }
}

impl Clone for Address {
    fn clone(&self) -> Address {
        unsafe {
            use std::intrinsics::copy_nonoverlapping;
            use std::mem;
            let mut ret = mem::uninitialized();
            copy_nonoverlapping(self,
                                &mut ret,
                                mem::size_of::<Address>());
            ret
        }
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Address) -> bool {
        self.services == other.services &&
        &self.address[..] == &other.address[..] &&
        self.port == other.port
    }
}

impl Eq for Address {}

#[cfg(test)]
mod test {
    use super::Address;

    use network::serialize::{deserialize, serialize};

    #[test]
    fn serialize_address_test() {
        assert_eq!(serialize(&Address {
            services: 1,
            address: [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001],
            port: 8333
        }).ok(),
        Some(vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1, 0x20, 0x8d]));
    }

    #[test]
    fn deserialize_address_test() {
        let mut addr: Result<Address, _> = deserialize(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                       0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0,
                                                       0, 1, 0x20, 0x8d]);
        assert!(addr.is_ok());
        let full = addr.unwrap();
        assert_eq!(full.services, 1);
        assert_eq!(full.address, [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
        assert_eq!(full.port, 8333);

        addr = deserialize(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1]);
        assert!(addr.is_err());
    }
}

