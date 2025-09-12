// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network addresses.
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.

use alloc::vec;
use alloc::vec::Vec;
use core::{fmt, iter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use bitcoin::consensus::encode::{self, Decodable, Encodable, ReadExt, WriteExt};
use io::{BufRead, Read, Write};

use crate::ServiceFlags;

/// A message which can be sent on the Bitcoin network
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Services provided by the peer whose address this is
    pub services: ServiceFlags,
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16,
}

const ONION: [u16; 3] = [0xFD87, 0xD87E, 0xEB43];

impl Address {
    /// Constructs a new address message for a socket
    pub fn new(socket: &SocketAddr, services: ServiceFlags) -> Address {
        let (address, port) = match *socket {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port()),
        };
        Address { address, port, services }
    }

    /// Builds a useless address that cannot be connected to. One may find this desirable if it is
    /// known the data will be ignored by the recipient.
    pub const fn useless() -> Address {
        Address { services: ServiceFlags::NONE, address: [0; 8], port: 0 }
    }

    /// Extracts socket address from an [Address] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the message contains a Tor address.
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        let addr = &self.address;
        if addr[0..3] == ONION {
            return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
        }
        let ipv6 =
            Ipv6Addr::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
        if let Some(ipv4) = ipv6.to_ipv4() {
            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, self.port)))
        } else {
            Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, self.port, 0, 0)))
        }
    }
}

impl Encodable for Address {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.services.consensus_encode(w)?;

        for word in &self.address {
            w.write_all(&word.to_be_bytes())?;
            len += 2;
        }

        w.write_all(&self.port.to_be_bytes())?;
        len += 2;

        Ok(len)
    }
}

impl Decodable for Address {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Address {
            services: Decodable::consensus_decode(r)?,
            address: read_be_address(r)?,
            port: u16::swap_bytes(Decodable::consensus_decode(r)?),
        })
    }
}

/// Reads a big-endian address from reader.
fn read_be_address<R: Read + ?Sized>(r: &mut R) -> Result<[u16; 8], encode::Error> {
    let mut address = [0u16; 8];
    let mut buf = [0u8; 2];

    for word in &mut address {
        Read::read_exact(r, &mut buf)?;
        *word = u16::from_be_bytes(buf)
    }
    Ok(address)
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ipv6 = Ipv6Addr::from(self.address);

        match ipv6.to_ipv4() {
            Some(addr) => write!(
                f,
                "Address {{services: {}, address: {}, port: {}}}",
                self.services, addr, self.port
            ),
            None => write!(
                f,
                "Address {{services: {}, address: {}, port: {}}}",
                self.services, ipv6, self.port
            ),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}

/// Supported networks for use in BIP-0155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AddrV2 {
    /// IPV4
    Ipv4(Ipv4Addr),
    /// IPV6
    Ipv6(Ipv6Addr),
    /// TORV3
    TorV3([u8; 32]),
    /// I2P
    I2p([u8; 32]),
    /// CJDNS
    Cjdns(Ipv6Addr),
    /// Unknown
    Unknown(u8, Vec<u8>),
}

impl TryFrom<AddrV2> for IpAddr {
    type Error = AddrV2ToIpAddrError;

    fn try_from(addr: AddrV2) -> Result<IpAddr, Self::Error> {
        match addr {
            AddrV2::Ipv4(ip) => Ok(IpAddr::V4(ip)),
            AddrV2::Ipv6(ip) => Ok(IpAddr::V6(ip)),
            AddrV2::Cjdns(_) => Err(AddrV2ToIpAddrError::Cjdns),
            AddrV2::TorV3(_) => Err(AddrV2ToIpAddrError::TorV3),
            AddrV2::I2p(_) => Err(AddrV2ToIpAddrError::I2p),
            AddrV2::Unknown(_, _) => Err(AddrV2ToIpAddrError::Unknown),
        }
    }
}

impl TryFrom<AddrV2> for Ipv4Addr {
    type Error = AddrV2ToIpv4AddrError;

    fn try_from(addr: AddrV2) -> Result<Ipv4Addr, Self::Error> {
        match addr {
            AddrV2::Ipv4(ip) => Ok(ip),
            AddrV2::Ipv6(_) => Err(AddrV2ToIpv4AddrError::Ipv6),
            AddrV2::Cjdns(_) => Err(AddrV2ToIpv4AddrError::Cjdns),
            AddrV2::TorV3(_) => Err(AddrV2ToIpv4AddrError::TorV3),
            AddrV2::I2p(_) => Err(AddrV2ToIpv4AddrError::I2p),
            AddrV2::Unknown(_, _) => Err(AddrV2ToIpv4AddrError::Unknown),
        }
    }
}

impl TryFrom<AddrV2> for Ipv6Addr {
    type Error = AddrV2ToIpv6AddrError;

    fn try_from(addr: AddrV2) -> Result<Ipv6Addr, Self::Error> {
        match addr {
            AddrV2::Ipv6(ip) => Ok(ip),
            AddrV2::Cjdns(_) => Err(AddrV2ToIpv6AddrError::Cjdns),
            AddrV2::Ipv4(_) => Err(AddrV2ToIpv6AddrError::Ipv4),
            AddrV2::TorV3(_) => Err(AddrV2ToIpv6AddrError::TorV3),
            AddrV2::I2p(_) => Err(AddrV2ToIpv6AddrError::I2p),
            AddrV2::Unknown(_, _) => Err(AddrV2ToIpv6AddrError::Unknown),
        }
    }
}

impl From<IpAddr> for AddrV2 {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(ip) => AddrV2::Ipv4(ip),
            IpAddr::V6(ip) => AddrV2::Ipv6(ip),
        }
    }
}

impl From<Ipv4Addr> for AddrV2 {
    fn from(addr: Ipv4Addr) -> Self { AddrV2::Ipv4(addr) }
}

impl From<Ipv6Addr> for AddrV2 {
    fn from(addr: Ipv6Addr) -> Self { AddrV2::Ipv6(addr) }
}

impl Encodable for AddrV2 {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        fn encode_addr<W: Write + ?Sized>(
            w: &mut W,
            network: u8,
            bytes: &[u8],
        ) -> Result<usize, io::Error> {
            Ok(network.consensus_encode(w)?
                + crate::consensus::consensus_encode_with_size(bytes, w)?)
        }
        Ok(match *self {
            AddrV2::Ipv4(ref addr) => encode_addr(w, 1, &addr.octets())?,
            AddrV2::Ipv6(ref addr) => encode_addr(w, 2, &addr.octets())?,
            AddrV2::TorV3(ref bytes) => encode_addr(w, 4, bytes)?,
            AddrV2::I2p(ref bytes) => encode_addr(w, 5, bytes)?,
            AddrV2::Cjdns(ref addr) => encode_addr(w, 6, &addr.octets())?,
            AddrV2::Unknown(network, ref bytes) => encode_addr(w, network, bytes)?,
        })
    }
}

impl Decodable for AddrV2 {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let network_id = u8::consensus_decode(r)?;
        let len = r.read_compact_size()?;
        if len > 512 {
            return Err(crate::consensus::parse_failed_error("IP must be <= 512 bytes"));
        }
        Ok(match network_id {
            1 => {
                if len != 4 {
                    return Err(crate::consensus::parse_failed_error("invalid IPv4 address"));
                }
                let addr: [u8; 4] = Decodable::consensus_decode(r)?;
                AddrV2::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
            }
            2 => {
                if len != 16 {
                    return Err(crate::consensus::parse_failed_error("invalid IPv6 address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                if addr[0..3] == ONION {
                    return Err(crate::consensus::parse_failed_error(
                        "OnionCat address sent with IPv6 network id",
                    ));
                }
                if addr[0..6] == [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF] {
                    return Err(crate::consensus::parse_failed_error(
                        "IPV4 wrapped address sent with IPv6 network id",
                    ));
                }
                AddrV2::Ipv6(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }

            4 => {
                if len != 32 {
                    return Err(crate::consensus::parse_failed_error("invalid TorV3 address"));
                }
                let pubkey = Decodable::consensus_decode(r)?;
                AddrV2::TorV3(pubkey)
            }
            5 => {
                if len != 32 {
                    return Err(crate::consensus::parse_failed_error("invalid I2P address"));
                }
                let hash = Decodable::consensus_decode(r)?;
                AddrV2::I2p(hash)
            }
            6 => {
                if len != 16 {
                    return Err(crate::consensus::parse_failed_error("invalid CJDNS address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                // check the first byte for the CJDNS marker
                if addr[0] >> 8 != 0xFC {
                    return Err(crate::consensus::parse_failed_error("invalid CJDNS address"));
                }
                AddrV2::Cjdns(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }
            _ => {
                // len already checked above to be <= 512
                let mut addr = vec![0u8; len as usize];
                r.read_slice(&mut addr)?;
                AddrV2::Unknown(network_id, addr)
            }
        })
    }
}

/// Address received from BIP-0155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddrV2Message {
    /// Time that this node was last seen as connected to the network
    pub time: u32,
    /// Service bits
    pub services: ServiceFlags,
    /// Network ID + Network Address
    pub addr: AddrV2,
    /// Network port, 0 if not applicable
    pub port: u16,
}

impl AddrV2Message {
    /// Extracts socket address from an [AddrV2Message] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the address type can't be converted into a [SocketAddr].
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        match self.addr {
            AddrV2::Ipv4(addr) => Ok(SocketAddr::V4(SocketAddrV4::new(addr, self.port))),
            AddrV2::Ipv6(addr) => Ok(SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, 0))),
            _ => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
        }
    }
}

impl Encodable for AddrV2Message {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.time.consensus_encode(w)?;
        len += w.emit_compact_size(self.services.to_u64())?;
        len += self.addr.consensus_encode(w)?;

        w.write_all(&self.port.to_be_bytes())?;
        len += 2; // port u16 is two bytes.

        Ok(len)
    }
}

impl Decodable for AddrV2Message {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(AddrV2Message {
            time: Decodable::consensus_decode(r)?,
            services: ServiceFlags::from(r.read_compact_size()?),
            addr: Decodable::consensus_decode(r)?,
            port: u16::swap_bytes(Decodable::consensus_decode(r)?),
        })
    }
}

impl ToSocketAddrs for AddrV2Message {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}

/// Error types for [`AddrV2`] to [`IpAddr`] conversion.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrV2ToIpAddrError {
    /// A [`AddrV2::TorV3`] address cannot be converted to a [`IpAddr`].
    TorV3,
    /// A [`AddrV2::I2p`] address cannot be converted to a [`IpAddr`].
    I2p,
    /// A [`AddrV2::Cjdns`] address cannot be converted to a [`IpAddr`],
    Cjdns,
    /// A [`AddrV2::Unknown`] address cannot be converted to a [`IpAddr`].
    Unknown,
}

impl fmt::Display for AddrV2ToIpAddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to IpAddr"),
            Self::I2p => write!(f, "I2P addresses cannot be converted to IpAddr"),
            Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to IpAddr"),
            Self::Unknown => write!(f, "Unknown address type cannot be converted to IpAddr"),
        }
    }
}

impl std::error::Error for AddrV2ToIpAddrError {}

/// Error types for [`AddrV2`] to [`Ipv4Addr`] conversion.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrV2ToIpv4AddrError {
    /// A [`AddrV2::Ipv6`] address cannot be converted to a [`Ipv4Addr`].
    Ipv6,
    /// A [`AddrV2::TorV3`] address cannot be converted to a [`Ipv4Addr`].
    TorV3,
    /// A [`AddrV2::I2p`] address cannot be converted to a [`Ipv4Addr`].
    I2p,
    /// A [`AddrV2::Cjdns`] address cannot be converted to a [`Ipv4Addr`],
    Cjdns,
    /// A [`AddrV2::Unknown`] address cannot be converted to a [`Ipv4Addr`].
    Unknown,
}

impl fmt::Display for AddrV2ToIpv4AddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv6 => write!(f, "Ipv6 addresses cannot be converted to Ipv4Addr"),
            Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to Ipv4Addr"),
            Self::I2p => write!(f, "I2P addresses cannot be converted to Ipv4Addr"),
            Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to Ipv4Addr"),
            Self::Unknown => write!(f, "Unknown address type cannot be converted to Ipv4Addr"),
        }
    }
}

impl std::error::Error for AddrV2ToIpv4AddrError {}

/// Error types for [`AddrV2`] to [`Ipv6Addr`] conversion.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrV2ToIpv6AddrError {
    /// A [`AddrV2::Ipv4`] address cannot be converted to a [`Ipv6Addr`].
    Ipv4,
    /// A [`AddrV2::TorV3`] address cannot be converted to a [`Ipv6Addr`].
    TorV3,
    /// A [`AddrV2::I2p`] address cannot be converted to a [`Ipv6Addr`].
    I2p,
    /// A [`AddrV2::Cjdns`] address cannot be converted to a [`Ipv6Addr`],
    Cjdns,
    /// A [`AddrV2::Unknown`] address cannot be converted to a [`Ipv6Addr`].
    Unknown,
}

impl fmt::Display for AddrV2ToIpv6AddrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "Ipv addresses cannot be converted to Ipv6Addr"),
            Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to Ipv6Addr"),
            Self::I2p => write!(f, "I2P addresses cannot be converted to Ipv6Addr"),
            Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to Ipv6Addr"),
            Self::Unknown => write!(f, "Unknown address type cannot be converted to Ipv6Addr"),
        }
    }
}

impl std::error::Error for AddrV2ToIpv6AddrError {}

#[cfg(test)]
mod test {
    use alloc::{format, vec};
    use std::net::IpAddr;

    use bitcoin::consensus::encode::{deserialize, serialize};
    use hex::FromHex;
    use hex_lit::hex;

    use super::*;
    use crate::message::AddrV2Payload;

    #[test]
    fn serialize_address() {
        assert_eq!(
            serialize(&Address {
                services: ServiceFlags::NETWORK,
                address: [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001],
                port: 8333
            }),
            [
                1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
                0x20, 0x8d
            ]
        );
    }

    #[test]
    fn debug_format() {
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
    fn deserialize_address() {
        let mut addr: Result<Address, _> = deserialize(&[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
            0x20, 0x8d,
        ]);
        assert!(addr.is_ok());
        let full = addr.unwrap();
        assert!(matches!(full.socket_addr().unwrap(), SocketAddr::V4(_)));
        assert_eq!(full.services, ServiceFlags::NETWORK);
        assert_eq!(full.address, [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
        assert_eq!(full.port, 8333);

        addr = deserialize(&[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
        ]);
        assert!(addr.is_err());
    }

    #[test]
    fn socket_addr() {
        let s4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(111, 222, 123, 4)), 5555);
        let a4 = Address::new(&s4, ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        assert_eq!(a4.socket_addr().unwrap(), s4);
        let s6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            )),
            9999,
        );
        let a6 = Address::new(&s6, ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        assert_eq!(a6.socket_addr().unwrap(), s6);
    }

    #[test]
    fn onion() {
        let onionaddr = SocketAddr::new(
            IpAddr::V6("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca".parse::<Ipv6Addr>().unwrap()),
            1111,
        );
        let addr = Address::new(&onionaddr, ServiceFlags::NONE);
        assert!(addr.socket_addr().is_err());
    }

    #[test]
    fn serialize_addrv2() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L348

        let ip = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(serialize(&ip), hex!("010401020304"));

        let ip =
            AddrV2::Ipv6("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b".parse::<Ipv6Addr>().unwrap());
        assert_eq!(serialize(&ip), hex!("02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b"));

        let ip = AddrV2::TorV3(
            FromHex::from_hex("53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88")
                .unwrap(),
        );
        assert_eq!(
            serialize(&ip),
            hex!("042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88")
        );

        let ip = AddrV2::I2p(
            FromHex::from_hex("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")
                .unwrap(),
        );
        assert_eq!(
            serialize(&ip),
            hex!("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")
        );

        let ip = AddrV2::Cjdns("fc01:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap());
        assert_eq!(serialize(&ip), hex!("0610fc010001000200030004000500060007"));

        let ip = AddrV2::Unknown(170, hex!("01020304").to_vec());
        assert_eq!(serialize(&ip), hex!("aa0401020304"));
    }

    #[test]
    fn deserialize_addrv2() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L386

        // Valid IPv4.
        let ip: AddrV2 = deserialize(&hex!("010401020304")).unwrap();
        assert_eq!(ip, AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4)));

        // Invalid IPv4, valid length but address itself is shorter.
        deserialize::<AddrV2>(&hex!("01040102")).unwrap_err();

        // Invalid IPv4, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("010501020304")).is_err());

        // Invalid IPv4, with extreme length.
        assert!(deserialize::<AddrV2>(&hex!("01fd010201020304")).is_err());

        // Valid IPv6.
        let ip: AddrV2 = deserialize(&hex!("02100102030405060708090a0b0c0d0e0f10")).unwrap();
        assert_eq!(
            ip,
            AddrV2::Ipv6("102:304:506:708:90a:b0c:d0e:f10".parse::<Ipv6Addr>().unwrap())
        );

        // Invalid IPv6, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("020400")).is_err());

        // Invalid IPv6, contains embedded IPv4.
        assert!(deserialize::<AddrV2>(&hex!("021000000000000000000000ffff01020304")).is_err());

        // Invalid IPv6, contains embedded TORv2.
        assert!(deserialize::<AddrV2>(&hex!("0210fd87d87eeb430102030405060708090a")).is_err());

        // Valid TORv3.
        let ip: AddrV2 = deserialize(&hex!(
            "042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"
        ))
        .unwrap();
        assert_eq!(
            ip,
            AddrV2::TorV3(
                FromHex::from_hex(
                    "79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"
                )
                .unwrap()
            )
        );

        // Invalid TORv3, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("040000")).is_err());

        // Valid I2P.
        let ip: AddrV2 = deserialize(&hex!(
            "0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"
        ))
        .unwrap();
        assert_eq!(
            ip,
            AddrV2::I2p(
                FromHex::from_hex(
                    "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"
                )
                .unwrap()
            )
        );

        // Invalid I2P, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("050300")).is_err());

        // Valid CJDNS.
        let ip: AddrV2 = deserialize(&hex!("0610fc000001000200030004000500060007")).unwrap();
        assert_eq!(ip, AddrV2::Cjdns("fc00:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap()));

        // Invalid CJDNS, incorrect marker
        assert!(deserialize::<AddrV2>(&hex!("0610fd000001000200030004000500060007")).is_err());

        // Invalid CJDNS, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("060100")).is_err());

        // Unknown, with extreme length.
        assert!(deserialize::<AddrV2>(&hex!("aafe0000000201020304050607")).is_err());

        // Unknown, with reasonable length.
        let ip: AddrV2 = deserialize(&hex!("aa0401020304")).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, hex!("01020304").to_vec()));

        // Unknown, with zero length.
        let ip: AddrV2 = deserialize(&hex!("aa00")).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, vec![]));
    }

    #[test]
    fn addrv2message() {
        let raw = hex!("0261bc6649019902abab208d79627683fd4804010409090909208d");
        let addresses: AddrV2Payload = deserialize(&raw).unwrap();

        assert_eq!(
            addresses.0,
            vec![
                AddrV2Message {
                    services: ServiceFlags::NETWORK,
                    time: 0x4966bc61,
                    port: 8333,
                    addr: AddrV2::Unknown(153, hex!("abab").to_vec())
                },
                AddrV2Message {
                    services: ServiceFlags::NETWORK_LIMITED
                        | ServiceFlags::WITNESS
                        | ServiceFlags::COMPACT_FILTERS,
                    time: 0x83766279,
                    port: 8333,
                    addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9))
                },
            ]
        );

        assert_eq!(serialize(&addresses), raw);
    }

    #[test]
    fn addrv2_to_ipaddr_ipv4() {
        let addr = AddrV2::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_addr = IpAddr::try_from(addr).unwrap();

        assert_eq!(ip_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn addrv2_to_ipaddr_ipv6() {
        let addr = AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ip_addr = IpAddr::try_from(addr).unwrap();

        assert_eq!(ip_addr, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn addrv2_to_ipaddr_cjdns() {
        let addr = AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpAddrError::Cjdns);
    }

    #[test]
    fn addrv2_to_ipaddr_torv3() {
        let addr = AddrV2::TorV3([0; 32]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpAddrError::TorV3);
    }

    #[test]
    fn addrv2_to_ipaddr_i2p() {
        let addr = AddrV2::I2p([0; 32]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpAddrError::I2p);
    }

    #[test]
    fn addrv2_to_ipaddr_unknown() {
        let addr = AddrV2::Unknown(42, vec![1, 2, 3, 4]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpAddrError::Unknown);
    }

    #[test]
    fn addrv2_to_ipv4addr_ipv4() {
        let addr = AddrV2::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_addr = Ipv4Addr::try_from(addr).unwrap();

        assert_eq!(ip_addr, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn addrv2_to_ipv4addr_ipv6() {
        let addr = AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = Ipv4Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv4AddrError::Ipv6);
    }

    #[test]
    fn addrv2_to_ipv4addr_cjdns() {
        let addr = AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        let result = Ipv4Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv4AddrError::Cjdns);
    }

    #[test]
    fn addrv2_to_ipv4addr_torv3() {
        let addr = AddrV2::TorV3([0; 32]);
        let result = Ipv4Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv4AddrError::TorV3);
    }

    #[test]
    fn addrv2_to_ipv4addr_i2p() {
        let addr = AddrV2::I2p([0; 32]);
        let result = Ipv4Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv4AddrError::I2p);
    }

    #[test]
    fn addrv2_to_ipv4addr_unknown() {
        let addr = AddrV2::Unknown(42, vec![1, 2, 3, 4]);
        let result = Ipv4Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv4AddrError::Unknown);
    }

    #[test]
    fn addrv2_to_ipv6addr_ipv4() {
        let addr = AddrV2::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let result = Ipv6Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv6AddrError::Ipv4);
    }

    #[test]
    fn addrv2_to_ipv6addr_ipv6() {
        let addr = AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ip_addr = Ipv6Addr::try_from(addr).unwrap();

        assert_eq!(ip_addr, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn addrv2_to_ipv6addr_cjdns() {
        let addr = AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        let result = Ipv6Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv6AddrError::Cjdns);
    }

    #[test]
    fn addrv2_to_ipv6addr_torv3() {
        let addr = AddrV2::TorV3([0; 32]);
        let result = Ipv6Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv6AddrError::TorV3);
    }

    #[test]
    fn addrv2_to_ipv6addr_i2p() {
        let addr = AddrV2::I2p([0; 32]);
        let result = Ipv6Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv6AddrError::I2p);
    }

    #[test]
    fn addrv2_to_ipv6addr_unknown() {
        let addr = AddrV2::Unknown(42, vec![1, 2, 3, 4]);
        let result = Ipv6Addr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AddrV2ToIpv6AddrError::Unknown);
    }
}
