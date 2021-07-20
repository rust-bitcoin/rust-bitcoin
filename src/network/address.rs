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

//! Bitcoin network addresses
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.
//!
use prelude::*;

use core::{fmt, iter};
use std::net::{SocketAddr, Ipv6Addr, SocketAddrV4, SocketAddrV6, Ipv4Addr, ToSocketAddrs};

use io;
use network::constants::ServiceFlags;
use consensus::encode::{self, Decodable, Encodable, VarInt, ReadExt, WriteExt};

/// A message which can be sent on the Bitcoin network
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Services provided by the peer whose address this is
    pub services: ServiceFlags,
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16
}

const ONION : [u16; 3] = [0xFD87, 0xD87E, 0xEB43];

impl Address {
    /// Create an address message for a socket
    pub fn new(socket :&SocketAddr, services: ServiceFlags) -> Address {
        let (address, port) = match *socket {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port())
        };
        Address { address: address, port: port, services: services }
    }

    /// Extract socket address from an [Address] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the message contains a Tor address.
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        let addr = &self.address;
        if addr[0..3] == ONION {
            return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
        }
        let ipv6 = Ipv6Addr::new(
            addr[0],addr[1],addr[2],addr[3],
            addr[4],addr[5],addr[6],addr[7]
        );
        if let Some(ipv4) = ipv6.to_ipv4() {
            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, self.port)))
        } else {
            Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, self.port, 0, 0)))
        }
    }
}

fn addr_to_be(addr: [u16; 8]) -> [u16; 8] {
    // consensus_encode always encodes in LE, and we want to encode in BE.
    // this utility fn swap bytes before encoding so that the encoded result will be BE
    let mut result = addr.clone();
    for i in 0..8 {
        result[i] = result[i].swap_bytes();
    }
    result
}

impl Encodable for Address {
    #[inline]
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let len = self.services.consensus_encode(&mut s)?
            + addr_to_be(self.address).consensus_encode(&mut s)?

            // consensus_encode always encodes in LE, and we want to encode in BE.
            //TODO `len += io::Write::write(&mut e, &self.port.to_be_bytes())?;` when MSRV >= 1.32
            + self.port.swap_bytes().consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for Address {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(Address {
            services: Decodable::consensus_decode(&mut d)?,
            address: addr_to_be(Decodable::consensus_decode(&mut d)?),
            port: u16::swap_bytes(Decodable::consensus_decode(d)?)
        })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ipv6 = Ipv6Addr::from(self.address);

        match ipv6.to_ipv4() {
            Some(addr) => write!(f, "Address {{services: {}, address: {}, port: {}}}", 
                self.services, addr, self.port),
            None => write!(f, "Address {{services: {}, address: {}, port: {}}}", 
                self.services, ipv6, self.port)
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}

/// Supported networks for use in BIP155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AddrV2 {
    /// IPV4
    Ipv4(Ipv4Addr),
    /// IPV6
    Ipv6(Ipv6Addr),
    /// TORV2
    TorV2([u8; 10]),
    /// TORV3
    TorV3([u8; 32]),
    /// I2P
    I2p([u8; 32]),
    /// CJDNS
    Cjdns(Ipv6Addr),
    /// Unknown
    Unknown(u8, Vec<u8>),
}

impl Encodable for AddrV2 {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, io::Error> {
        fn encode_addr<W: io::Write>(mut e: W, network: u8, bytes: &[u8]) -> Result<usize, io::Error> {
                let len = 
                    network.consensus_encode(&mut e)? +
                    VarInt(bytes.len() as u64).consensus_encode(&mut e)? +
                    bytes.len();
                e.emit_slice(bytes)?;
                Ok(len)
        }
        Ok(match *self {
            AddrV2::Ipv4(ref addr) => encode_addr(e, 1, &addr.octets())?,
            AddrV2::Ipv6(ref addr) => encode_addr(e, 2, &addr.octets())?,
            AddrV2::TorV2(ref bytes) => encode_addr(e, 3, bytes)?,
            AddrV2::TorV3(ref bytes) => encode_addr(e, 4, bytes)?,
            AddrV2::I2p(ref bytes) => encode_addr(e, 5, bytes)?,
            AddrV2::Cjdns(ref addr) => encode_addr(e, 6, &addr.octets())?,
            AddrV2::Unknown(network, ref bytes) => encode_addr(e, network, bytes)?
        })
    }
}

impl Decodable for AddrV2 {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let network_id = u8::consensus_decode(&mut d)?;
        let len = VarInt::consensus_decode(&mut d)?.0;
        if len > 512 {
            return Err(encode::Error::ParseFailed("IP must be <= 512 bytes"));
        }
        Ok(match network_id {
            1 => {
                if len != 4 {
                    return Err(encode::Error::ParseFailed("Invalid IPv4 address"));
                }
                let addr: [u8; 4] = Decodable::consensus_decode(&mut d)?;
                AddrV2::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
            }, 
            2 => {
                if len != 16 {
                    return Err(encode::Error::ParseFailed("Invalid IPv6 address"));
                }
                let addr: [u16; 8] = addr_to_be(Decodable::consensus_decode(&mut d)?);
                if addr[0..3] == ONION {
                    return Err(encode::Error::ParseFailed("OnionCat address sent with IPv6 network id"));
                }
                if addr[0..6] == [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF] {
                    return Err(encode::Error::ParseFailed("IPV4 wrapped address sent with IPv6 network id"));
                }
                AddrV2::Ipv6(Ipv6Addr::new(
                    addr[0],addr[1],addr[2],addr[3],
                    addr[4],addr[5],addr[6],addr[7]
                ))
            }, 
            3 => {
                if len != 10 {
                    return Err(encode::Error::ParseFailed("Invalid TorV2 address"));
                }
                let id = Decodable::consensus_decode(&mut d)?;
                AddrV2::TorV2(id)
            },
            4 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("Invalid TorV3 address"));
                }
                let pubkey = Decodable::consensus_decode(&mut d)?;
                AddrV2::TorV3(pubkey)
            },
            5 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("Invalid I2P address"));
                }
                let hash = Decodable::consensus_decode(&mut d)?;
                AddrV2::I2p(hash)
            }, 
            6 => {
                if len != 16  {
                    return Err(encode::Error::ParseFailed("Invalid CJDNS address"));
                }
                let addr: [u16; 8] = Decodable::consensus_decode(&mut d)?;
                // check the first byte for the CJDNS marker
                if addr[0] as u8 != 0xFC {
                    return Err(encode::Error::ParseFailed("Invalid CJDNS address"));
                }
                let addr = addr_to_be(addr);
                AddrV2::Cjdns(Ipv6Addr::new(
                    addr[0],addr[1],addr[2],addr[3],
                    addr[4],addr[5],addr[6],addr[7]
                ))
            },
            _ => {
                // len already checked above to be <= 512
                let mut addr = vec![0u8; len as usize];
                d.read_slice(&mut addr)?;
                AddrV2::Unknown(network_id, addr)
            } 
        })
    }
}

/// Address received from BIP155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddrV2Message {
    /// Time that this node was last seen as connected to the network
    pub time: u32,
    /// Service bits
    pub services: ServiceFlags,
    /// Network ID + Network Address
    pub addr: AddrV2,
    /// Network port, 0 if not applicable
    pub port: u16
}

impl AddrV2Message {
    /// Extract socket address from an [AddrV2Message] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the address type can't be converted into a [SocketAddr].
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        match self.addr {
            AddrV2::Ipv4(addr) => Ok(SocketAddr::V4(SocketAddrV4::new(addr, self.port))),
            AddrV2::Ipv6(addr) => Ok(SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, 0))),
            _ => return Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
        }
    }
}

impl Encodable for AddrV2Message {
    fn consensus_encode<W: io::Write>(&self, mut e: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.time.consensus_encode(&mut e)?;
        len += VarInt(self.services.as_u64()).consensus_encode(&mut e)?;
        len += self.addr.consensus_encode(&mut e)?;

        // consensus_encode always encodes in LE, and we want to encode in BE.
        //TODO `len += io::Write::write(&mut e, &self.port.to_be_bytes())?;` when MSRV >= 1.32
        len += self.port.swap_bytes().consensus_encode(e)?;
        Ok(len)
    }   
}

impl Decodable for AddrV2Message {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(AddrV2Message{
            time: Decodable::consensus_decode(&mut d)?,
            services: ServiceFlags::from(VarInt::consensus_decode(&mut d)?.0),
            addr: Decodable::consensus_decode(&mut d)?,
            port: u16::swap_bytes(Decodable::consensus_decode(d)?),
        })
    }
}

impl ToSocketAddrs for AddrV2Message {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;
    use super::{AddrV2Message, AddrV2, Address};
    use network::constants::ServiceFlags;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
    use hashes::hex::FromHex;

    use consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_address_test() {
        assert_eq!(serialize(&Address {
            services: ServiceFlags::NETWORK,
            address: [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001],
            port: 8333
        }),
        vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1, 0x20, 0x8d]);
    }

    #[test]
    fn debug_format_test() {
        let mut flags = ServiceFlags::NETWORK;
        assert_eq!(
            format!("The address is: {:?}", Address {
                services: flags.add(ServiceFlags::WITNESS),
                address: [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001],
                port: 8333
            }), 
            "The address is: Address {services: ServiceFlags(NETWORK|WITNESS), address: 10.0.0.1, port: 8333}"
        );

        assert_eq!(
            format!("The address is: {:?}", Address {
                services: ServiceFlags::NETWORK_LIMITED,
                address: [0xFD87, 0xD87E, 0xEB43, 0, 0, 0xffff, 0x0a00, 0x0001],
                port: 8333
            }), 
            "The address is: Address {services: ServiceFlags(NETWORK_LIMITED), address: fd87:d87e:eb43::ffff:a00:1, port: 8333}"
        );
    }

    #[test]
    fn deserialize_address_test() {
        let mut addr: Result<Address, _> = deserialize(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                       0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0,
                                                       0, 1, 0x20, 0x8d]);
        assert!(addr.is_ok());
        let full = addr.unwrap();
        assert!(match full.socket_addr().unwrap() {
                    SocketAddr::V4(_) => true,
                    _ => false
                }
            );
        assert_eq!(full.services, ServiceFlags::NETWORK);
        assert_eq!(full.address, [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
        assert_eq!(full.port, 8333);

        addr = deserialize(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1]);
        assert!(addr.is_err());
    }

    #[test]
    fn test_socket_addr () {
        let s4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(111,222,123,4)), 5555);
        let a4 = Address::new(&s4, ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        assert_eq!(a4.socket_addr().unwrap(), s4);
        let s6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x1111, 0x2222, 0x3333, 0x4444,
        0x5555, 0x6666, 0x7777, 0x8888)), 9999);
        let a6 = Address::new(&s6, ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        assert_eq!(a6.socket_addr().unwrap(), s6);
    }

    #[test]
    fn onion_test () {
        let onionaddr = SocketAddr::new(
            IpAddr::V6(
            Ipv6Addr::from_str("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").unwrap()), 1111);
        let addr = Address::new(&onionaddr, ServiceFlags::NONE);
        assert!(addr.socket_addr().is_err());
    }

    #[test]
    fn serialize_addrv2_test() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L348

        let ip = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(serialize(&ip), Vec::from_hex("010401020304").unwrap());

        let ip = AddrV2::Ipv6(Ipv6Addr::from_str("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b").unwrap());

        let ip = AddrV2::TorV2(FromHex::from_hex("f1f2f3f4f5f6f7f8f9fa").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("030af1f2f3f4f5f6f7f8f9fa").unwrap());

        let ip = AddrV2::TorV3(FromHex::from_hex("53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88").unwrap());

        let ip = AddrV2::I2p(FromHex::from_hex("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87").unwrap());

        let ip = AddrV2::Cjdns(Ipv6Addr::from_str("fc00:1:2:3:4:5:6:7").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("0610fc000001000200030004000500060007").unwrap());

        let ip = AddrV2::Unknown(170, Vec::from_hex("01020304").unwrap());
        assert_eq!(serialize(&ip), Vec::from_hex("aa0401020304").unwrap());
    }

    #[test]
    fn deserialize_addrv2_test() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L386

        // Valid IPv4.
        let ip: AddrV2 = deserialize(&Vec::from_hex("010401020304").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));

        // Invalid IPv4, valid length but address itself is shorter.
        deserialize::<AddrV2>(&Vec::from_hex("01040102").unwrap()).unwrap_err();

        // Invalid IPv4, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("010501020304").unwrap()).is_err());

        // Invalid IPv4, with extreme length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("01fd010201020304").unwrap()).is_err());

        // Valid IPv6.
        let ip: AddrV2 = deserialize(&Vec::from_hex("02100102030405060708090a0b0c0d0e0f10").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::Ipv6(Ipv6Addr::from_str("102:304:506:708:90a:b0c:d0e:f10").unwrap()));

        // Invalid IPv6, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("020400").unwrap()).is_err());

        // Invalid IPv6, contains embedded IPv4.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("021000000000000000000000ffff01020304").unwrap()).is_err());

        // Invalid IPv6, contains embedded TORv2.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("0210fd87d87eeb430102030405060708090a").unwrap()).is_err());

        // Valid TORv2.
        let ip: AddrV2 = deserialize(&Vec::from_hex("030af1f2f3f4f5f6f7f8f9fa").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::TorV2(FromHex::from_hex("f1f2f3f4f5f6f7f8f9fa").unwrap()));

        // Invalid TORv2, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("030700").unwrap()).is_err());

        // Valid TORv3.
        let ip: AddrV2 = deserialize(&Vec::from_hex("042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::TorV3(FromHex::from_hex("79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f").unwrap()));

        // Invalid TORv3, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("040000").unwrap()).is_err());

        // Valid I2P.
        let ip: AddrV2 = deserialize(&Vec::from_hex("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::I2p(FromHex::from_hex("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87").unwrap()));

        // Invalid I2P, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("050300").unwrap()).is_err());

        // Valid CJDNS.
        let ip: AddrV2 = deserialize(&Vec::from_hex("0610fc000001000200030004000500060007").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::Cjdns(Ipv6Addr::from_str("fc00:1:2:3:4:5:6:7").unwrap()));

        // Invalid CJDNS, incorrect marker
        assert!(deserialize::<AddrV2>(&Vec::from_hex("0610fd000001000200030004000500060007").unwrap()).is_err());

        // Invalid CJDNS, with bogus length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("060100").unwrap()).is_err());

        // Unknown, with extreme length.
        assert!(deserialize::<AddrV2>(&Vec::from_hex("aafe0000000201020304050607").unwrap()).is_err());

        // Unknown, with reasonable length.
        let ip: AddrV2 = deserialize(&Vec::from_hex("aa0401020304").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, Vec::from_hex("01020304").unwrap()));

        // Unknown, with zero length.
        let ip: AddrV2 = deserialize(&Vec::from_hex("aa00").unwrap()).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, vec![]));
    }

    #[test]
    fn addrv2message_test() {
        let raw = Vec::from_hex("0261bc6649019902abab208d79627683fd4804010409090909208d").unwrap();
        let addresses: Vec<AddrV2Message> = deserialize(&raw).unwrap();

        assert_eq!(addresses, vec![
            AddrV2Message{services: ServiceFlags::NETWORK, time: 0x4966bc61, port: 8333, addr: AddrV2::Unknown(153, Vec::from_hex("abab").unwrap())},
            AddrV2Message{services: ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS, time: 0x83766279, port: 8333, addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9))},
        ]);

        assert_eq!(serialize(&addresses), raw);
    }
}
