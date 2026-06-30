// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network addresses.
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.
//!

#[cfg(feature = "encoding")]
use core::convert::Infallible;
use core::{fmt, iter};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use io::{Read, Write};

use crate::consensus::encode::{self, Decodable, Encodable, ReadExt, VarInt, WriteExt};
#[cfg(feature = "encoding")]
use crate::internal_macros::write_err;
use crate::p2p::ServiceFlags;

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
#[cfg(feature = "encoding")]
const IPV4_EMBEDDED_IPV6: [u16; 6] = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF];

impl Address {
    /// Create an address message for a socket
    pub fn new(socket: &SocketAddr, services: ServiceFlags) -> Address {
        let (address, port) = match *socket {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port()),
        };
        Address { address, port, services }
    }

    /// Extract socket address from an [Address] message.
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
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Address {
            services: Decodable::consensus_decode(r)?,
            address: read_be_address(r)?,
            port: u16::swap_bytes(Decodable::consensus_decode(r)?),
        })
    }
}

/// Read a big-endian address from reader.
fn read_be_address<R: Read + ?Sized>(r: &mut R) -> Result<[u16; 8], encode::Error> {
    let mut address = [0u16; 8];
    let mut buf = [0u8; 2];

    for word in &mut address {
        Read::read_exact(r, &mut buf)?;
        *word = u16::from_be_bytes(buf)
    }
    Ok(address)
}

#[cfg(feature = "encoding")]
fn address_from_u8(s: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes([s[0], s[1]]),
        u16::from_be_bytes([s[2], s[3]]),
        u16::from_be_bytes([s[4], s[5]]),
        u16::from_be_bytes([s[6], s[7]]),
        u16::from_be_bytes([s[8], s[9]]),
        u16::from_be_bytes([s[10], s[11]]),
        u16::from_be_bytes([s[12], s[13]]),
        u16::from_be_bytes([s[14], s[15]]),
    ]
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

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`Address`] type.
    #[derive(Debug, Clone)]
    pub struct AddressEncoder<'e>(
        encoding::Encoder3<
            crate::p2p::ServiceFlagsEncoder<'e>,
            encoding::ArrayEncoder<16>,
            encoding::ArrayEncoder<2>,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for Address {
    type Encoder<'e> = AddressEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        let mut address: [u8; 16] = [0; 16];
        for (index, value) in self.address.iter().enumerate() {
            let arr: [u8; 2] = value.to_be_bytes();
            address[index * 2] = arr[0];
            address[index * 2 + 1] = arr[1];
        }

        let enc = encoding::Encoder3::new(
            self.services.encoder(),
            encoding::ArrayEncoder::without_length_prefix(address),
            encoding::ArrayEncoder::without_length_prefix(self.port.to_be_bytes()),
        );

        AddressEncoder::new(enc)
    }
}

#[cfg(feature = "encoding")]
type AddressInnerDecoder = encoding::Decoder3<
    crate::p2p::ServiceFlagsDecoder,
    encoding::ArrayDecoder<16>,
    encoding::ArrayDecoder<2>,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The Decoder for [`Address`].
    #[derive(Debug, Default, Clone)]
    pub struct AddressDecoder(AddressInnerDecoder);

    fn end(
        result: Result<<AddressInnerDecoder as encoding::Decoder>::Output, <AddressInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Address, AddressDecoderError> {
        let (services, raw_address, port) = result.map_err(AddressDecoderError)?;
        let address = address_from_u8(raw_address);
        Ok(Address { services, address, port: u16::from_be_bytes(port) })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for Address {
    type Decoder = AddressDecoder;
}

/// An error decoding an [`Address`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressDecoderError(
    pub(crate) <AddressInnerDecoder as encoding::Decoder>::Error
);

#[cfg(feature = "encoding")]
impl From<Infallible> for AddressDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for AddressDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "address decoder error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for AddressDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        fn encode_addr<W: Write + ?Sized>(
            w: &mut W,
            network: u8,
            bytes: &[u8],
        ) -> Result<usize, io::Error> {
            let len = network.consensus_encode(w)?
                + VarInt::from(bytes.len()).consensus_encode(w)?
                + bytes.len();
            w.emit_slice(bytes)?;
            Ok(len)
        }
        Ok(match *self {
            AddrV2::Ipv4(ref addr) => encode_addr(w, 1, &addr.octets())?,
            AddrV2::Ipv6(ref addr) => encode_addr(w, 2, &addr.octets())?,
            AddrV2::TorV2(ref bytes) => encode_addr(w, 3, bytes)?,
            AddrV2::TorV3(ref bytes) => encode_addr(w, 4, bytes)?,
            AddrV2::I2p(ref bytes) => encode_addr(w, 5, bytes)?,
            AddrV2::Cjdns(ref addr) => encode_addr(w, 6, &addr.octets())?,
            AddrV2::Unknown(network, ref bytes) => encode_addr(w, network, bytes)?,
        })
    }
}

impl Decodable for AddrV2 {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let network_id = u8::consensus_decode(r)?;
        let len = VarInt::consensus_decode(r)?.0;
        if len > 512 {
            return Err(encode::Error::ParseFailed("IP must be <= 512 bytes"));
        }
        Ok(match network_id {
            1 => {
                if len != 4 {
                    return Err(encode::Error::ParseFailed("Invalid IPv4 address"));
                }
                let addr: [u8; 4] = Decodable::consensus_decode(r)?;
                AddrV2::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
            }
            2 => {
                if len != 16 {
                    return Err(encode::Error::ParseFailed("Invalid IPv6 address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                if addr[0..3] == ONION {
                    return Err(encode::Error::ParseFailed(
                        "OnionCat address sent with IPv6 network id",
                    ));
                }
                if addr[0..6] == [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF] {
                    return Err(encode::Error::ParseFailed(
                        "IPV4 wrapped address sent with IPv6 network id",
                    ));
                }
                AddrV2::Ipv6(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }
            3 => {
                if len != 10 {
                    return Err(encode::Error::ParseFailed("Invalid TorV2 address"));
                }
                let id = Decodable::consensus_decode(r)?;
                AddrV2::TorV2(id)
            }
            4 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("Invalid TorV3 address"));
                }
                let pubkey = Decodable::consensus_decode(r)?;
                AddrV2::TorV3(pubkey)
            }
            5 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("Invalid I2P address"));
                }
                let hash = Decodable::consensus_decode(r)?;
                AddrV2::I2p(hash)
            }
            6 => {
                if len != 16 {
                    return Err(encode::Error::ParseFailed("Invalid CJDNS address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                // check the first byte for the CJDNS marker
                if addr[0] >> 8 != 0xFC {
                    return Err(encode::Error::ParseFailed("Invalid CJDNS address"));
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

#[cfg(feature = "encoding")]
/// The encoder for the [`AddrV2`] type.
#[derive(Debug, Clone)]
pub struct AddrV2Encoder<'e> {
    network: Option<encoding::ArrayEncoder<1>>,
    size: Option<encoding::CompactSizeEncoder>,
    bytes4: Option<encoding::ArrayEncoder<4>>,
    bytes10: Option<encoding::ArrayEncoder<10>>,
    bytes16: Option<encoding::ArrayEncoder<16>>,
    bytes32: Option<encoding::ArrayEncoder<32>>,
    nbytes: Option<encoding::BytesEncoder<'e>>,
}

#[cfg(feature = "encoding")]
impl<'e> AddrV2Encoder<'e> {
    const EMPTY: Self = Self {
        network: None,
        size: None,
        bytes4: None,
        bytes10: None,
        bytes16: None,
        bytes32: None,
        nbytes: None,
    };

    fn new(addr: &'e AddrV2) -> Self {
        match addr {
            AddrV2::Ipv4(ip) => {
                let octets = ip.octets();
                Self {
                    network: Some(encoding::ArrayEncoder::without_length_prefix([1])),
                    size: Some(encoding::CompactSizeEncoder::new(4)),
                    bytes4: Some(encoding::ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::Ipv6(ip) => {
                let octets = ip.octets();
                Self {
                    network: Some(encoding::ArrayEncoder::without_length_prefix([2])),
                    size: Some(encoding::CompactSizeEncoder::new(16)),
                    bytes16: Some(encoding::ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::TorV2(bytes) => Self {
                network: Some(encoding::ArrayEncoder::without_length_prefix([3])),
                size: Some(encoding::CompactSizeEncoder::new(10)),
                bytes10: Some(encoding::ArrayEncoder::without_length_prefix(*bytes)),
                ..Self::EMPTY
            },
            AddrV2::TorV3(bytes) => Self {
                network: Some(encoding::ArrayEncoder::without_length_prefix([4])),
                size: Some(encoding::CompactSizeEncoder::new(32)),
                bytes32: Some(encoding::ArrayEncoder::without_length_prefix(*bytes)),
                ..Self::EMPTY
            },
            AddrV2::I2p(bytes) => Self {
                network: Some(encoding::ArrayEncoder::without_length_prefix([5])),
                size: Some(encoding::CompactSizeEncoder::new(32)),
                bytes32: Some(encoding::ArrayEncoder::without_length_prefix(*bytes)),
                ..Self::EMPTY
            },
            AddrV2::Cjdns(ip) => {
                let octets = ip.octets();
                Self {
                    network: Some(encoding::ArrayEncoder::without_length_prefix([6])),
                    size: Some(encoding::CompactSizeEncoder::new(16)),
                    bytes16: Some(encoding::ArrayEncoder::without_length_prefix(octets)),
                    ..Self::EMPTY
                }
            }
            AddrV2::Unknown(network, bytes) => Self {
                network: Some(encoding::ArrayEncoder::without_length_prefix([*network])),
                size: Some(encoding::CompactSizeEncoder::new(bytes.len())),
                nbytes: Some(encoding::BytesEncoder::without_length_prefix(bytes.as_slice())),
                ..Self::EMPTY
            },
        }
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encoder for AddrV2Encoder<'_> {
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
        if let Some(b) = &self.bytes10 {
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

    fn advance(&mut self) -> encoding::EncoderStatus {
        if self.network.is_some() && self.network.advance().has_finished() {
            self.network = None;
            return encoding::EncoderStatus::HasMore;
        }
        if self.size.is_some() && self.size.advance().has_finished() {
            self.size = None;
            return encoding::EncoderStatus::HasMore;
        }
        if self.bytes4.is_some() && self.bytes4.advance().has_finished() {
            self.bytes4 = None;
            return encoding::EncoderStatus::Finished;
        }
        if self.bytes10.is_some() && self.bytes10.advance().has_finished() {
            self.bytes10 = None;
            return encoding::EncoderStatus::Finished;
        }
        if self.bytes16.is_some() && self.bytes16.advance().has_finished() {
            self.bytes16 = None;
            return encoding::EncoderStatus::Finished;
        }
        if self.bytes32.is_some() && self.bytes32.advance().has_finished() {
            self.bytes32 = None;
            return encoding::EncoderStatus::Finished;
        }
        if self.nbytes.is_some() && self.nbytes.advance().has_finished() {
            self.nbytes = None;
            return encoding::EncoderStatus::Finished;
        }
        encoding::EncoderStatus::HasMore
    }
}

#[cfg(feature = "encoding")]
impl encoding::Encode for AddrV2 {
    type Encoder<'e> = AddrV2Encoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> { AddrV2Encoder::new(self) }
}

#[cfg(feature = "encoding")]
type AddrV2InnerDecoder = encoding::Decoder2<encoding::ArrayDecoder<1>, encoding::ByteVecDecoder>;

#[cfg(feature = "encoding")]
/// The decoder for the [`AddrV2`] type.
#[derive(Debug, Default, Clone)]
pub struct AddrV2Decoder(AddrV2InnerDecoder);

#[cfg(feature = "encoding")]
impl AddrV2Decoder {
    fn to_fixed_size<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], AddrV2DecoderError> {
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| AddrV2DecoderError::InvalidAddressLength { expected: N, got: len })
    }

    fn ipv6_from_bytes(bytes: [u8; 16]) -> Ipv6Addr {
        let address = address_from_u8(bytes);
        Ipv6Addr::new(
            address[0], address[1], address[2], address[3], address[4], address[5], address[6],
            address[7],
        )
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for AddrV2Decoder {
    type Output = AddrV2;
    type Error = AddrV2DecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<encoding::DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(AddrV2DecoderError::Decoder)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (network_id, bytes) = self.0.end().map_err(AddrV2DecoderError::Decoder)?;

        if bytes.len() > 512 {
            return Err(AddrV2DecoderError::InvalidAddressLength {
                expected: 512,
                got: bytes.len(),
            });
        }

        match network_id[0] {
            1 => {
                let addr = Self::to_fixed_size::<4>(bytes)?;
                Ok(AddrV2::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])))
            }
            2 => {
                let addr = Self::to_fixed_size::<16>(bytes)?;
                let segments = address_from_u8(addr);

                if segments[0..3] == ONION {
                    return Err(AddrV2DecoderError::WrappedOnionCat);
                }
                if segments[0..6] == IPV4_EMBEDDED_IPV6 {
                    return Err(AddrV2DecoderError::WrappedIpv4);
                }

                Ok(AddrV2::Ipv6(Self::ipv6_from_bytes(addr)))
            }
            3 => Ok(AddrV2::TorV2(Self::to_fixed_size::<10>(bytes)?)),
            4 => Ok(AddrV2::TorV3(Self::to_fixed_size::<32>(bytes)?)),
            5 => Ok(AddrV2::I2p(Self::to_fixed_size::<32>(bytes)?)),
            6 => {
                let addr = Self::to_fixed_size::<16>(bytes)?;
                if addr[0] != 0xFC {
                    return Err(AddrV2DecoderError::NotCjdns);
                }
                Ok(AddrV2::Cjdns(Self::ipv6_from_bytes(addr)))
            }
            network_id => Ok(AddrV2::Unknown(network_id, bytes)),
        }
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for AddrV2 {
    type Decoder = AddrV2Decoder;
}

/// An error decoding a [`AddrV2`] message.
#[cfg(feature = "encoding")]
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

#[cfg(feature = "encoding")]
impl From<Infallible> for AddrV2DecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for AddrV2DecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoder(err) => write_err!(f, "addrv2 error"; err),
            Self::InvalidAddressLength { expected, got } =>
                write!(f, "invalid length. expected {}, got {}", expected, got),
            Self::NotCjdns => write!(f, "CJDNS address must start with a reserved byte."),
            Self::WrappedOnionCat => write!(f, "OnionCat address sent as IPv6 is invalid."),
            Self::WrappedIpv4 => write!(f, "wrapped IPv4 sent as IPv6 is invalid."),
        }
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for AddrV2DecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decoder(err) => Some(err),
            Self::InvalidAddressLength { .. }
            | Self::NotCjdns
            | Self::WrappedOnionCat
            | Self::WrappedIpv4 => None,
        }
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
    pub port: u16,
}

impl AddrV2Message {
    /// Extract socket address from an [AddrV2Message] message.
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
        len += VarInt(self.services.to_u64()).consensus_encode(w)?;
        len += self.addr.consensus_encode(w)?;

        w.write_all(&self.port.to_be_bytes())?;
        len += 2; // port u16 is two bytes.

        Ok(len)
    }
}

impl Decodable for AddrV2Message {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(AddrV2Message {
            time: Decodable::consensus_decode(r)?,
            services: ServiceFlags::from(VarInt::consensus_decode(r)?.0),
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

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`AddrV2Message`] type.
    #[derive(Debug, Clone)]
    pub struct AddrV2MessageEncoder<'e>(
        encoding::Encoder4<
            encoding::ArrayEncoder<4>,
            encoding::CompactSizeEncoder,
            AddrV2Encoder<'e>,
            encoding::ArrayEncoder<2>,
        >
    );
}

#[cfg(feature = "encoding")]
impl encoding::Encode for AddrV2Message {
    type Encoder<'e> = AddrV2MessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AddrV2MessageEncoder::new(encoding::Encoder4::new(
            encoding::ArrayEncoder::without_length_prefix(self.time.to_le_bytes()),
            encoding::CompactSizeEncoder::new_u64(self.services.to_u64()),
            self.addr.encoder(),
            encoding::ArrayEncoder::without_length_prefix(self.port.to_be_bytes()),
        ))
    }
}

#[cfg(feature = "encoding")]
type AddrV2MessageInnerDecoder = encoding::Decoder4<
    encoding::ArrayDecoder<4>,
    encoding::CompactSizeU64Decoder,
    AddrV2Decoder,
    encoding::ArrayDecoder<2>,
>;

#[cfg(feature = "encoding")]
crate::decoder_newtype! {
    /// The decoder for the [`AddrV2Message`] type.
    #[derive(Debug, Default, Clone)]
    pub struct AddrV2MessageDecoder(AddrV2MessageInnerDecoder);

    fn end(
        result: Result<<AddrV2MessageInnerDecoder as encoding::Decoder>::Output, <AddrV2MessageInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<AddrV2Message, AddrV2MessageDecoderError> {
        let (time, services, addr, port) = result.map_err(AddrV2MessageDecoderError)?;
        Ok(AddrV2Message {
            time: u32::from_le_bytes(time),
            services: ServiceFlags::from(services),
            addr,
            port: u16::from_be_bytes(port),
        })
    }
}

#[cfg(feature = "encoding")]
impl encoding::Decode for AddrV2Message {
    type Decoder = AddrV2MessageDecoder;
}

/// An error decoding an [`AddrV2Message`].
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrV2MessageDecoderError(pub(crate) <AddrV2MessageInnerDecoder as encoding::Decoder>::Error);

#[cfg(feature = "encoding")]
impl From<Infallible> for AddrV2MessageDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for AddrV2MessageDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_err!(f, "addrv2 message error"; self.0)
    }
}

#[cfg(all(feature = "encoding", feature = "std"))]
impl std::error::Error for AddrV2MessageDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use hex::{test_hex_unwrap as hex, FromHex};

    use super::{AddrV2, AddrV2Message, Address};
    use crate::consensus::encode::{deserialize, serialize};
    use crate::p2p::ServiceFlags;

    #[test]
    fn serialize_address_test() {
        assert_eq!(
            serialize(&Address {
                services: ServiceFlags::NETWORK,
                address: [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001],
                port: 8333
            }),
            vec![
                1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
                0x20, 0x8d
            ]
        );
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
    fn test_socket_addr() {
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
    fn onion_test() {
        let onionaddr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from_str("FD87:D87E:EB43:edb1:8e4:3588:e546:35ca").unwrap()),
            1111,
        );
        let addr = Address::new(&onionaddr, ServiceFlags::NONE);
        assert!(addr.socket_addr().is_err());
    }

    #[test]
    fn serialize_addrv2_test() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L348

        let ip = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(serialize(&ip), hex!("010401020304"));

        let ip =
            AddrV2::Ipv6(Ipv6Addr::from_str("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b").unwrap());
        assert_eq!(serialize(&ip), hex!("02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b"));

        let ip = AddrV2::TorV2(FromHex::from_hex("f1f2f3f4f5f6f7f8f9fa").unwrap());
        assert_eq!(serialize(&ip), hex!("030af1f2f3f4f5f6f7f8f9fa"));

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

        let ip = AddrV2::Cjdns(Ipv6Addr::from_str("fc01:1:2:3:4:5:6:7").unwrap());
        assert_eq!(serialize(&ip), hex!("0610fc010001000200030004000500060007"));

        let ip = AddrV2::Unknown(170, hex!("01020304"));
        assert_eq!(serialize(&ip), hex!("aa0401020304"));
    }

    #[test]
    fn deserialize_addrv2_test() {
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
            AddrV2::Ipv6(Ipv6Addr::from_str("102:304:506:708:90a:b0c:d0e:f10").unwrap())
        );

        // Invalid IPv6, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("020400")).is_err());

        // Invalid IPv6, contains embedded IPv4.
        assert!(deserialize::<AddrV2>(&hex!("021000000000000000000000ffff01020304")).is_err());

        // Invalid IPv6, contains embedded TORv2.
        assert!(deserialize::<AddrV2>(&hex!("0210fd87d87eeb430102030405060708090a")).is_err());

        // Valid TORv2.
        let ip: AddrV2 = deserialize(&hex!("030af1f2f3f4f5f6f7f8f9fa")).unwrap();
        assert_eq!(ip, AddrV2::TorV2(FromHex::from_hex("f1f2f3f4f5f6f7f8f9fa").unwrap()));

        // Invalid TORv2, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("030700")).is_err());

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
        assert_eq!(ip, AddrV2::Cjdns(Ipv6Addr::from_str("fc00:1:2:3:4:5:6:7").unwrap()));

        // Invalid CJDNS, incorrect marker
        assert!(deserialize::<AddrV2>(&hex!("0610fd000001000200030004000500060007")).is_err());

        // Invalid CJDNS, with bogus length.
        assert!(deserialize::<AddrV2>(&hex!("060100")).is_err());

        // Unknown, with extreme length.
        assert!(deserialize::<AddrV2>(&hex!("aafe0000000201020304050607")).is_err());

        // Unknown, with reasonable length.
        let ip: AddrV2 = deserialize(&hex!("aa0401020304")).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, hex!("01020304")));

        // Unknown, with zero length.
        let ip: AddrV2 = deserialize(&hex!("aa00")).unwrap();
        assert_eq!(ip, AddrV2::Unknown(170, vec![]));
    }

    #[test]
    fn addrv2message_test() {
        let raw = hex!("0261bc6649019902abab208d79627683fd4804010409090909208d");
        let addresses: Vec<AddrV2Message> = deserialize(&raw).unwrap();

        assert_eq!(
            addresses,
            vec![
                AddrV2Message {
                    services: ServiceFlags::NETWORK,
                    time: 0x4966bc61,
                    port: 8333,
                    addr: AddrV2::Unknown(153, hex!("abab"))
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
}
