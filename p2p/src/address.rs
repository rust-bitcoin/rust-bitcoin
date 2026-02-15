// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network addresses.
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::{fmt, iter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::encode::{self, Decodable, Encodable, ReadExt, WriteExt};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, BytesEncoder, CompactSizeEncoder, Decoder2,
};
use internals::write_err;
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
const IPV4_EMBEDDED_IPV6: [u16; 6] = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF];

impl Address {
    /// Constructs a new address message for a socket
    pub fn new(socket: &SocketAddr, services: ServiceFlags) -> Self {
        let (address, port) = match *socket {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port()),
        };
        Self { services, address, port }
    }

    /// Builds a useless address that cannot be connected to. One may find this desirable if it is
    /// known the data will be ignored by the recipient.
    pub const fn useless() -> Self {
        Self { services: ServiceFlags::NONE, address: [0; 8], port: 0 }
    }

    /// Extracts socket address from an [Address] message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message contains a Tor V2 onion address.
    pub fn socket_addr(&self) -> Result<SocketAddr, UnroutableAddressError> {
        let addr = &self.address;
        if addr[0..3] == ONION {
            return Err(UnroutableAddressError::TorV2);
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
        Ok(Self {
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
        *word = u16::from_be_bytes(buf);
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
        self.socket_addr()
            .map(iter::once)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
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
    type Error = UnroutableAddressError;

    fn try_from(addr: AddrV2) -> Result<Self, Self::Error> {
        match addr {
            AddrV2::Ipv4(ip) => Ok(Self::V4(ip)),
            AddrV2::Ipv6(ip) => Ok(Self::V6(ip)),
            AddrV2::Cjdns(_) => Err(UnroutableAddressError::Cjdns),
            AddrV2::TorV3(_) => Err(UnroutableAddressError::TorV3),
            AddrV2::I2p(_) => Err(UnroutableAddressError::I2p),
            AddrV2::Unknown(_, _) => Err(UnroutableAddressError::Unknown),
        }
    }
}

impl TryFrom<AddrV2> for Ipv4Addr {
    type Error = AddrV2ToIpv4AddrError;

    fn try_from(addr: AddrV2) -> Result<Self, Self::Error> {
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

    fn try_from(addr: AddrV2) -> Result<Self, Self::Error> {
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
            IpAddr::V4(ip) => Self::Ipv4(ip),
            IpAddr::V6(ip) => Self::Ipv6(ip),
        }
    }
}

impl From<Ipv4Addr> for AddrV2 {
    fn from(addr: Ipv4Addr) -> Self { Self::Ipv4(addr) }
}

impl From<Ipv6Addr> for AddrV2 {
    fn from(addr: Ipv6Addr) -> Self { Self::Ipv6(addr) }
}

/// The encoder type for [`AddrV2`].
pub struct AddrV2Encoder<'e> {
    network: Option<ArrayEncoder<1>>,
    size: Option<CompactSizeEncoder>,
    bytes4: Option<ArrayEncoder<4>>,
    bytes16: Option<ArrayEncoder<16>>,
    bytes32: Option<ArrayEncoder<32>>,
    nbytes: Option<BytesEncoder<'e>>,
}

impl<'e> AddrV2Encoder<'e> {
    const EMPTY: Self = Self {
        network: None,
        size: None,
        bytes4: None,
        bytes16: None,
        bytes32: None,
        nbytes: None,
    };
    /// Construct a new [`AddrV2`] encoder.
    pub fn new(addr_v2: &'e AddrV2) -> Self {
        // Each address is prefixed with the network type and length of the byte array.
        match addr_v2 {
            AddrV2::Ipv4(ipv4) => {
                let octets = ipv4.octets();
                Self {
                    network: Some(ArrayEncoder::without_length_prefix([1])),
                    size: Some(CompactSizeEncoder::new(4)),
                    bytes4: Some(ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::Ipv6(ipv6) => {
                let octets = ipv6.octets();
                Self {
                    network: Some(ArrayEncoder::without_length_prefix([2])),
                    size: Some(CompactSizeEncoder::new(16)),
                    bytes16: Some(ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::TorV3(onion) => Self {
                network: Some(ArrayEncoder::without_length_prefix([4])),
                size: Some(CompactSizeEncoder::new(32)),
                bytes32: Some(ArrayEncoder::without_length_prefix(*onion)),
                ..Self::EMPTY
            },
            AddrV2::I2p(i2p) => Self {
                network: Some(ArrayEncoder::without_length_prefix([5])),
                size: Some(CompactSizeEncoder::new(32)),
                bytes32: Some(ArrayEncoder::without_length_prefix(*i2p)),
                ..Self::EMPTY
            },
            AddrV2::Cjdns(ipv6) => {
                let octets = ipv6.octets();
                Self {
                    network: Some(ArrayEncoder::without_length_prefix([6])),
                    size: Some(CompactSizeEncoder::new(16)),
                    bytes16: Some(ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::Unknown(network, bytes) => Self {
                network: Some(ArrayEncoder::without_length_prefix([*network])),
                size: Some(CompactSizeEncoder::new(bytes.len())),
                nbytes: Some(BytesEncoder::<'e>::without_length_prefix(bytes.as_slice())),
                ..Self::EMPTY
            },
        }
    }
}

impl<'e> encoding::Encoder for AddrV2Encoder<'e> {
    fn current_chunk(&self) -> &[u8] {
        if let Some(network) = &self.network {
            return network.current_chunk();
        }
        if let Some(cs) = &self.size {
            return cs.current_chunk();
        }
        if let Some(b) = &self.bytes4 {
            return b.current_chunk();
        }
        if let Some(b) = &self.bytes16 {
            return b.current_chunk();
        }
        if let Some(b) = &self.bytes32 {
            return b.current_chunk();
        }
        if let Some(b) = &self.nbytes {
            return b.current_chunk();
        }
        &[]
    }

    fn advance(&mut self) -> bool {
        if self.network.is_some() && !self.network.advance() {
            self.network = None;
            return true;
        }
        if self.size.is_some() && !self.size.advance() {
            self.size = None;
            return true;
        }
        if self.bytes4.is_some() && !self.bytes4.advance() {
            self.bytes4 = None;
            return false;
        }
        if self.bytes16.is_some() && !self.bytes16.advance() {
            self.bytes16 = None;
            return false;
        }
        if self.bytes32.is_some() && !self.bytes32.advance() {
            self.bytes32 = None;
            return false;
        }
        if self.nbytes.is_some() && !self.nbytes.advance() {
            self.nbytes = None;
            return false;
        }
        true
    }
}

impl encoding::Encodable for AddrV2 {
    type Encoder<'e> = AddrV2Encoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> { AddrV2Encoder::new(self) }
}

type AddrV2InnerDecoder = Decoder2<ArrayDecoder<1>, ByteVecDecoder>;

/// The decoder type for an [`AddrV2`] type.
pub struct AddrV2Decoder(AddrV2InnerDecoder);

impl AddrV2Decoder {
    #[inline]
    const fn be_bytes_to_segments(bytes: [u8; 16]) -> [u16; 8] {
        [
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            u16::from_be_bytes([bytes[8], bytes[9]]),
            u16::from_be_bytes([bytes[10], bytes[11]]),
            u16::from_be_bytes([bytes[12], bytes[13]]),
            u16::from_be_bytes([bytes[14], bytes[15]]),
        ]
    }

    #[inline]
    const fn ipv6_from_segments(segments: [u16; 8]) -> Ipv6Addr {
        Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )
    }

    #[inline]
    fn to_fixed_size_slice<const N: usize>(
        addr_bytes: Vec<u8>,
    ) -> Result<[u8; N], AddrV2DecoderError> {
        Ok(addr_bytes.try_into().map_err(|e: Vec<u8>| {
            AddrV2DecoderError::InvalidAddressLength { expected: N, got: e.len() }
        })?)
    }
}

impl encoding::Decoder for AddrV2Decoder {
    type Output = AddrV2;
    type Error = AddrV2DecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrV2DecoderError::Decoder)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let (net_type, addr_bytes) = self.0.end().map_err(AddrV2DecoderError::Decoder)?;
        match u8::from_le_bytes(net_type) {
            1 => {
                let octets = Self::to_fixed_size_slice::<4>(addr_bytes)?;
                Ok(AddrV2::Ipv4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])))
            }
            2 => {
                let bytes = Self::to_fixed_size_slice::<16>(addr_bytes)?;
                let octets = Self::be_bytes_to_segments(bytes);
                if octets[0..3] == ONION {
                    return Err(AddrV2DecoderError::WrappedOnionCat);
                }
                if octets[0..6] == IPV4_EMBEDDED_IPV6 {
                    return Err(AddrV2DecoderError::WrappedIpv4);
                }
                Ok(AddrV2::Ipv6(Self::ipv6_from_segments(octets)))
            }
            4 => {
                let onion = Self::to_fixed_size_slice::<32>(addr_bytes)?;
                Ok(AddrV2::TorV3(onion))
            }
            5 => {
                let i2p = Self::to_fixed_size_slice::<32>(addr_bytes)?;
                Ok(AddrV2::I2p(i2p))
            }
            6 => {
                let octets = Self::to_fixed_size_slice::<16>(addr_bytes)?;
                if octets[0] != 0xFC {
                    return Err(AddrV2DecoderError::NotCjdns);
                }
                Ok(AddrV2::Cjdns(Self::ipv6_from_segments(Self::be_bytes_to_segments(octets))))
            }
            any => Ok(AddrV2::Unknown(any, addr_bytes)),
        }
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl encoding::Decodable for AddrV2 {
    type Decoder = AddrV2Decoder;

    fn decoder() -> Self::Decoder {
        AddrV2Decoder(Decoder2::new(ArrayDecoder::new(), ByteVecDecoder::new()))
    }
}

/// An error decoding a [`AddrV2`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrV2DecoderError {
    /// Inner decoder failure.
    Decoder(<AddrV2InnerDecoder as encoding::Decoder>::Error),
    /// The address cannot be decoded given the buffer size.
    InvalidAddressLength {
        /// The expected size given the address type.
        expected: usize,
        /// Actual size of the buffer.
        got: usize,
    },
    /// Expected CJDNS address but got an invalid mask.
    NotCjdns,
    /// `OnionCat` address sent as IPV6 is invalid.
    WrappedOnionCat,
    /// Wrapped IPV4 sent as IPV6 is invalid.
    WrappedIpv4,
}

impl From<Infallible> for AddrV2DecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for AddrV2DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(d) => write_err!(f, "addrv2 error"; d),
            Self::InvalidAddressLength { expected, got } =>
                write!(f, "invalid length. expected {}, got {}", expected, got),
            Self::NotCjdns => write!(f, "CJDNS address must start with a reserved byte."),
            Self::WrappedOnionCat => write!(f, "OnionCat address sent as IPv6 is invalid."),
            Self::WrappedIpv4 => write!(f, "wrapped IPv4 sent as IPv6 is invalid."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddrV2DecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(d) => Some(d),
            Self::InvalidAddressLength { expected: _, got: _ } => None,
            Self::NotCjdns => None,
            Self::WrappedOnionCat => None,
            Self::WrappedIpv4 => None,
        }
    }
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
            Self::Ipv4(ref addr) => encode_addr(w, 1, &addr.octets())?,
            Self::Ipv6(ref addr) => encode_addr(w, 2, &addr.octets())?,
            Self::TorV3(ref bytes) => encode_addr(w, 4, bytes)?,
            Self::I2p(ref bytes) => encode_addr(w, 5, bytes)?,
            Self::Cjdns(ref addr) => encode_addr(w, 6, &addr.octets())?,
            Self::Unknown(network, ref bytes) => encode_addr(w, network, bytes)?,
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
                Self::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
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
                Self::Ipv6(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }

            4 => {
                if len != 32 {
                    return Err(crate::consensus::parse_failed_error("invalid TorV3 address"));
                }
                let pubkey = Decodable::consensus_decode(r)?;
                Self::TorV3(pubkey)
            }
            5 => {
                if len != 32 {
                    return Err(crate::consensus::parse_failed_error("invalid I2P address"));
                }
                let hash = Decodable::consensus_decode(r)?;
                Self::I2p(hash)
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
                Self::Cjdns(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }
            _ => {
                // len already checked above to be <= 512
                let mut addr = vec![0u8; len as usize];
                r.read_slice(&mut addr)?;
                Self::Unknown(network_id, addr)
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
    /// Extracts socket address from an [`AddrV2Message`] message.
    ///
    /// # Errors
    ///
    /// Returns an error if the address type cannot be converted to a socket address
    /// (e.g. Tor, I2P, CJDNS addresses).
    pub fn socket_addr(&self) -> Result<SocketAddr, UnroutableAddressError> {
        match self.addr {
            AddrV2::Ipv4(addr) => Ok(SocketAddr::V4(SocketAddrV4::new(addr, self.port))),
            AddrV2::Ipv6(addr) => Ok(SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, 0))),
            AddrV2::TorV3(_) => Err(UnroutableAddressError::TorV3),
            AddrV2::I2p(_) => Err(UnroutableAddressError::I2p),
            AddrV2::Cjdns(_) => Err(UnroutableAddressError::Cjdns),
            AddrV2::Unknown(_, _) => Err(UnroutableAddressError::Unknown),
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
        Ok(Self {
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
        self.socket_addr()
            .map(iter::once)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

/// Error returned when an address cannot be converted to an IP-based address.
///
/// Addresses like Tor, I2P, and CJDNS use different routing mechanisms
/// and cannot be represented as standard IP addresses or socket addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnroutableAddressError {
    /// Tor V2 onion address.
    TorV2,
    /// Tor V3 onion address.
    TorV3,
    /// I2P address.
    I2p,
    /// CJDNS address.
    Cjdns,
    /// Unknown address type.
    Unknown,
}

impl fmt::Display for UnroutableAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TorV2 => write!(f, "Tor v2 addresses cannot be converted to IP addresses"),
            Self::TorV3 => write!(f, "Tor v3 addresses cannot be converted to IP addresses"),
            Self::I2p => write!(f, "I2P addresses cannot be converted to IP addresses"),
            Self::Cjdns => write!(f, "CJDNS addresses cannot be converted to IP addresses"),
            Self::Unknown => write!(f, "unknown address type cannot be converted to IP addresses"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnroutableAddressError {}

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
            Self::Ipv4 => write!(f, "Ipv4 addresses cannot be converted to Ipv6Addr"),
            Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to Ipv6Addr"),
            Self::I2p => write!(f, "I2P addresses cannot be converted to Ipv6Addr"),
            Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to Ipv6Addr"),
            Self::Unknown => write!(f, "Unknown address type cannot be converted to Ipv6Addr"),
        }
    }
}

impl std::error::Error for AddrV2ToIpv6AddrError {}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Address {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let socket_addr = match bool::arbitrary(u)? {
            true => SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                )),
                u.arbitrary()?,
            ),
            false => SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                    u.arbitrary()?,
                )),
                u.arbitrary()?,
            ),
        };

        Ok(Self::new(&socket_addr, u.arbitrary()?))
    }
}
#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrV2 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=5)? {
            0 => Ok(Self::Ipv4(Ipv4Addr::new(
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
            ))),
            1 => Ok(Self::Ipv6(Ipv6Addr::new(
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
            ))),
            2 => Ok(Self::TorV3(u.arbitrary()?)),
            3 => Ok(Self::I2p(u.arbitrary()?)),
            4 => Ok(Self::Cjdns(Ipv6Addr::new(
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
                u.arbitrary()?,
            ))),
            _ => Ok(Self::Unknown(u.arbitrary()?, Vec::<u8>::arbitrary(u)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddrV2Message {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            time: u.arbitrary()?,
            services: u.arbitrary()?,
            addr: u.arbitrary()?,
            port: u.arbitrary()?,
        })
    }
}

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

        let ip_bytes = hex!("010401020304");
        let ip = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(serialize(&ip), ip_bytes);
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), ip_bytes);

        let ip_bytes = hex!("02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
        let ip =
            AddrV2::Ipv6("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b".parse::<Ipv6Addr>().unwrap());
        assert_eq!(serialize(&ip), ip_bytes);
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), ip_bytes);

        let tor_bytes =
            hex!("042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
        let ip = AddrV2::TorV3(
            FromHex::from_hex("53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88")
                .unwrap(),
        );
        assert_eq!(serialize(&ip), tor_bytes);
        assert_eq!(encoding::encode_to_vec(&ip), tor_bytes);

        let i2p_bytes =
            hex!("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87");
        let ip = AddrV2::I2p(
            FromHex::from_hex("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87")
                .unwrap(),
        );
        assert_eq!(serialize(&ip), i2p_bytes);
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), i2p_bytes);

        let cjdns_bytes = hex!("0610fc010001000200030004000500060007");
        let ip = AddrV2::Cjdns("fc01:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap());
        assert_eq!(serialize(&ip), cjdns_bytes);
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), cjdns_bytes);

        let unk_bytes = hex!("aa0401020304");
        let ip = AddrV2::Unknown(170, hex!("01020304").to_vec());
        assert_eq!(serialize(&ip), unk_bytes);
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), unk_bytes);
    }

    #[test]
    fn deserialize_addrv2() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L386

        // Valid IPv4.
        let ip_bytes = hex!("010401020304");
        let want = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip: AddrV2 = deserialize(&ip_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&ip_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid IPv4, valid length but address itself is shorter.
        let invalid = hex!("01040102");
        deserialize::<AddrV2>(&invalid).unwrap_err();
        encoding::decode_from_slice::<AddrV2>(&invalid).unwrap_err();

        // Invalid IPv4, with bogus length.
        let invalid = hex!("010501020304");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        encoding::decode_from_slice::<AddrV2>(&invalid).unwrap_err();

        // Invalid IPv4, with extreme length.
        let extreme = hex!("01fd010201020304");
        assert!(deserialize::<AddrV2>(&extreme).is_err());
        encoding::decode_from_slice::<AddrV2>(&extreme).unwrap_err();

        // Valid IPv6.
        let ipv6_bytes = hex!("02100102030405060708090a0b0c0d0e0f10");
        let want = AddrV2::Ipv6("102:304:506:708:90a:b0c:d0e:f10".parse::<Ipv6Addr>().unwrap());
        let ip: AddrV2 = deserialize(&ipv6_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&ipv6_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid IPv6, with bogus length.
        let bogus = hex!("020400");
        assert!(deserialize::<AddrV2>(&bogus).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&bogus).is_err());

        // Invalid IPv6, contains embedded IPv4.
        let embedded = hex!("021000000000000000000000ffff01020304");
        assert!(deserialize::<AddrV2>(&embedded).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&embedded).is_err());

        // Invalid IPv6, contains embedded TORv2.
        let torish = hex!("0210fd87d87eeb430102030405060708090a");
        assert!(deserialize::<AddrV2>(&torish).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&torish).is_err());

        // Valid TORv3.
        let tor_bytes =
            hex!("042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f");
        let want =
            AddrV2::TorV3(hex!("79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"));
        let ip: AddrV2 = deserialize(&tor_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&tor_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid TORv3, with bogus length.
        let invalid = hex!("040000");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Valid I2P.
        let i2p_bytes =
            hex!("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87");
        let want =
            AddrV2::I2p(hex!("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"));
        let i2p: AddrV2 = deserialize(&i2p_bytes).unwrap();
        assert_eq!(i2p, want);
        let ip: AddrV2 = encoding::decode_from_slice(&i2p_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid I2P, with bogus length.
        let invalid = hex!("050300");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Valid CJDNS.
        let cjdns_bytes = hex!("0610fc000001000200030004000500060007");
        let want = AddrV2::Cjdns("fc00:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap());
        let ip: AddrV2 = deserialize(&cjdns_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&cjdns_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid CJDNS, incorrect marker
        let invalid = hex!("0610fd000001000200030004000500060007");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Invalid CJDNS, with bogus length.
        let invalid = hex!("060100");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Unknown, with extreme length.
        let invalid = hex!("aafe0000000201020304050607");
        assert!(deserialize::<AddrV2>(&invalid).is_err());
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Unknown, with reasonable length.
        let unk_bytes = hex!("aa0401020304");
        let want = AddrV2::Unknown(170, hex!("01020304").to_vec());
        let ip: AddrV2 = deserialize(&unk_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&unk_bytes).unwrap();
        assert_eq!(ip, want);

        // Unknown, with zero length.
        let unk_bytes = hex!("aa00");
        let want = AddrV2::Unknown(170, vec![]);
        let ip: AddrV2 = deserialize(&unk_bytes).unwrap();
        assert_eq!(ip, want);
        let ip: AddrV2 = encoding::decode_from_slice(&unk_bytes).unwrap();
        assert_eq!(ip, want);
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
                    time: 0x4966_bc61,
                    port: 8333,
                    addr: AddrV2::Unknown(153, hex!("abab").to_vec())
                },
                AddrV2Message {
                    services: ServiceFlags::NETWORK_LIMITED
                        | ServiceFlags::WITNESS
                        | ServiceFlags::COMPACT_FILTERS,
                    time: 0x8376_6279,
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
        assert_eq!(result.unwrap_err(), UnroutableAddressError::Cjdns);
    }

    #[test]
    fn addrv2_to_ipaddr_torv3() {
        let addr = AddrV2::TorV3([0; 32]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UnroutableAddressError::TorV3);
    }

    #[test]
    fn addrv2_to_ipaddr_i2p() {
        let addr = AddrV2::I2p([0; 32]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UnroutableAddressError::I2p);
    }

    #[test]
    fn addrv2_to_ipaddr_unknown() {
        let addr = AddrV2::Unknown(42, vec![1, 2, 3, 4]);
        let result = IpAddr::try_from(addr);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), UnroutableAddressError::Unknown);
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
