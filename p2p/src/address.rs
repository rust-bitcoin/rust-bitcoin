// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network addresses.
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.

use alloc::vec::Vec;
use core::{fmt, iter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, BytesEncoder, CompactSizeEncoder,
    CompactSizeU64Decoder, Decoder2, Decoder4, Encoder2, Encoder4, EncoderStatus,
};
use internals::array::ArrayExt;

use crate::ServiceFlags;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(no_inline)]
pub use self::error::{
    AddrV1MessageDecoderError, AddrV2DecoderError, AddrV2MessageDecoderError,
    AddrV2ToIpAddrError, AddrV2ToIpv4AddrError, AddrV2ToIpv6AddrError, AddressDecoderError,
    UnroutableAddressError,
};

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

fn address_from_u8(s: [u8; 16]) -> [u16; 8] {
    [
        u16::from_be_bytes(*s.sub_array::<0, 2>()),
        u16::from_be_bytes(*s.sub_array::<2, 2>()),
        u16::from_be_bytes(*s.sub_array::<4, 2>()),
        u16::from_be_bytes(*s.sub_array::<6, 2>()),
        u16::from_be_bytes(*s.sub_array::<8, 2>()),
        u16::from_be_bytes(*s.sub_array::<10, 2>()),
        u16::from_be_bytes(*s.sub_array::<12, 2>()),
        u16::from_be_bytes(*s.sub_array::<14, 2>()),
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
        self.socket_addr()
            .map(iter::once)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder for the [`Address`] type.
    #[derive(Debug, Clone)]
    pub struct AddressEncoder<'e>(encoding::Encoder3<
        crate::ServiceFlagsEncoder<'e>,
        encoding::ArrayEncoder<16>,
        encoding::ArrayEncoder<2>
    >);
}

impl encoding::Encode for Address {
    type Encoder<'e>
        = AddressEncoder<'e>
    where
        Self: 'e;

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

type AddressInnerDecoder = encoding::Decoder3<
    crate::ServiceFlagsDecoder,
    encoding::ArrayDecoder<16>,
    encoding::ArrayDecoder<2>,
>;

crate::decoder_newtype! {
    /// The Decoder for [`Address`].
    #[derive(Debug, Default, Clone)]
    pub struct AddressDecoder(AddressInnerDecoder);

    fn end(
        result: Result<(ServiceFlags, [u8; 16], [u8; 2]), <AddressInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<Address, AddressDecoderError> {
        let (services, raw_address, port) = result.map_err(AddressDecoderError)?;
        let address = address_from_u8(raw_address);
        Ok(Address { services, address, port: u16::from_be_bytes(port) })
    }
}

impl encoding::Decode for Address {
    type Decoder = AddressDecoder;
}

/// Data type received in an `addr` message.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddrV1Message {
    /// Time the peer was last seen.
    pub time: u32,
    /// Network address to research the peer.
    pub address: Address,
}

encoding::encoder_newtype_exact! {
    /// The encoder for an [`AddrV1Message`].
    #[derive(Debug, Clone)]
    pub struct AddrV1MessageEncoder<'e>(Encoder2<ArrayEncoder<4>, AddressEncoder<'e>>);
}

impl encoding::Encode for AddrV1Message {
    type Encoder<'e> = AddrV1MessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AddrV1MessageEncoder::new(Encoder2::new(
            ArrayEncoder::without_length_prefix(self.time.to_le_bytes()),
            self.address.encoder(),
        ))
    }
}

type AddrV1MessageInnerDecoder = Decoder2<ArrayDecoder<4>, AddressDecoder>;

crate::decoder_newtype! {
    /// The decoder for an [`AddrV1Message`].
    #[derive(Debug, Default, Clone)]
    pub struct AddrV1MessageDecoder(AddrV1MessageInnerDecoder);

    fn end(
        result: Result<([u8; 4], Address), <AddrV1MessageInnerDecoder as encoding::Decoder>::Error>
    ) -> Result<AddrV1Message, AddrV1MessageDecoderError> {
        let (time, address) = result.map_err(AddrV1MessageDecoderError)?;
        let time = u32::from_le_bytes(time);
        Ok(AddrV1Message { time, address })
    }
}

impl encoding::Decode for AddrV1Message {
    type Decoder = AddrV1MessageDecoder;
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
#[derive(Debug, Clone)]
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

    fn advance(&mut self) -> EncoderStatus {
        if self.network.is_some() && self.network.advance().has_finished() {
            self.network = None;
            return EncoderStatus::HasMore;
        }
        if self.size.is_some() && self.size.advance().has_finished() {
            self.size = None;
            return EncoderStatus::HasMore;
        }
        if self.bytes4.is_some() && self.bytes4.advance().has_finished() {
            self.bytes4 = None;
            return EncoderStatus::Finished;
        }
        if self.bytes16.is_some() && self.bytes16.advance().has_finished() {
            self.bytes16 = None;
            return EncoderStatus::Finished;
        }
        if self.bytes32.is_some() && self.bytes32.advance().has_finished() {
            self.bytes32 = None;
            return EncoderStatus::Finished;
        }
        if self.nbytes.is_some() && self.nbytes.advance().has_finished() {
            self.nbytes = None;
            return EncoderStatus::Finished;
        }
        EncoderStatus::HasMore
    }
}

impl<'e> encoding::ExactSizeEncoder for AddrV2Encoder<'e> {
    fn len(&self) -> usize {
        let mut len = 0;
        if let Some(network) = &self.network {
            len += network.len();
        }
        if let Some(cs) = &self.size {
            len += cs.len();
        }
        if let Some(b) = &self.bytes4 {
            len += b.len();
        }
        if let Some(b) = &self.bytes16 {
            len += b.len();
        }
        if let Some(b) = &self.bytes32 {
            len += b.len();
        }
        if let Some(b) = &self.nbytes {
            len += b.len();
        }
        len
    }
}

impl encoding::Encode for AddrV2 {
    type Encoder<'e> = AddrV2Encoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> { AddrV2Encoder::new(self) }
}

type AddrV2InnerDecoder = Decoder2<ArrayDecoder<1>, ByteVecDecoder>;

crate::decoder_newtype! {
    /// The decoder type for an [`AddrV2`] type.
    #[derive(Debug, Default, Clone)]
    pub struct AddrV2Decoder(AddrV2InnerDecoder);

    fn map_push_bytes_err(err: <AddrV2InnerDecoder as encoding::Decoder>::Error) -> AddrV2DecoderError {
        AddrV2DecoderError::Decoder(err)
    }

    fn end(
        result: Result<([u8; 1], Vec<u8>), <AddrV2InnerDecoder as encoding::Decoder>::Error>
    ) -> Result<AddrV2, AddrV2DecoderError> {
        let (net_type, addr_bytes) = result.map_err(AddrV2DecoderError::Decoder)?;
        if addr_bytes.len() > 512 {
            return Err(AddrV2DecoderError::InvalidAddressLength {
                expected: 512,
                got: addr_bytes.len(),
            });
        }
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
}

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
        addr_bytes.try_into().map_err(|e: Vec<u8>| AddrV2DecoderError::InvalidAddressLength {
            expected: N,
            got: e.len(),
        })
    }
}

impl encoding::Decode for AddrV2 {
    type Decoder = AddrV2Decoder;
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

impl ToSocketAddrs for AddrV2Message {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        self.socket_addr()
            .map(iter::once)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

encoding::encoder_newtype_exact! {
    /// The encoder type for an [`AddrV2Message`].
    #[derive(Debug, Clone)]
    pub struct AddrV2MessageEncoder<'e>(Encoder4<ArrayEncoder<4>, CompactSizeEncoder, AddrV2Encoder<'e>, ArrayEncoder<2>>);
}

impl encoding::Encode for AddrV2Message {
    type Encoder<'e> = AddrV2MessageEncoder<'e>;

    fn encoder(&self) -> Self::Encoder<'_> {
        AddrV2MessageEncoder::new(Encoder4::new(
            ArrayEncoder::without_length_prefix(self.time.to_le_bytes()),
            CompactSizeEncoder::new_u64(self.services.to_u64()),
            self.addr.encoder(),
            ArrayEncoder::without_length_prefix(self.port.to_be_bytes()),
        ))
    }
}

type AddrV2MessageInnerDecoder =
    Decoder4<ArrayDecoder<4>, CompactSizeU64Decoder, AddrV2Decoder, ArrayDecoder<2>>;

crate::decoder_newtype! {
    /// The decoder for an [`AddrV2Message`].
    #[derive(Debug, Default, Clone)]
    pub struct AddrV2MessageDecoder(AddrV2MessageInnerDecoder);

    fn end(
        result: Result<
            <AddrV2MessageInnerDecoder as encoding::Decoder>::Output,
            <AddrV2MessageInnerDecoder as encoding::Decoder>::Error,
        >
    ) -> Result<AddrV2Message, AddrV2MessageDecoderError> {
        let (time, services, addr, port) = result.map_err(AddrV2MessageDecoderError)?;
        let services = ServiceFlags(services);
        let time = u32::from_le_bytes(time);
        let port = u16::from_be_bytes(port);
        Ok(AddrV2Message { time, services, addr, port })
    }
}

impl encoding::Decode for AddrV2Message {
    type Decoder = AddrV2MessageDecoder;
}

/// Error types for address messages.
pub mod error {
    use core::convert::Infallible;
    use core::fmt;

    use internals::write_err;

    /// An error consensus decoding an [`Address`].
    ///
    /// [`Address`]: super::Address
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddressDecoderError(
        pub(super) <super::AddressInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for AddressDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for AddressDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            internals::write_err!(f, "address decoder error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AddressDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error occurring when decoding a [`AddrV1Message`].
    ///
    /// [`AddrV1Message`]: super::AddrV1Message
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddrV1MessageDecoderError(
        pub(super) <super::AddrV1MessageInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for AddrV1MessageDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for AddrV1MessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "addrv1 message error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AddrV1MessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
    }

    /// An error decoding a [`AddrV2`] message.
    ///
    /// [`AddrV2`]: super::AddrV2
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AddrV2DecoderError {
        /// Inner decoder failure.
        Decoder(<super::AddrV2InnerDecoder as encoding::Decoder>::Error),
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

    /// An error occurring when decoding a [`AddrV2Message`].
    ///
    /// [`AddrV2Message`]: super::AddrV2Message
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AddrV2MessageDecoderError(
        pub(super) <super::AddrV2MessageInnerDecoder as encoding::Decoder>::Error,
    );

    impl From<Infallible> for AddrV2MessageDecoderError {
        fn from(never: Infallible) -> Self { match never {} }
    }

    impl fmt::Display for AddrV2MessageDecoderError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_err!(f, "addrv2 message error"; self.0)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for AddrV2MessageDecoderError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
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
                Self::Unknown =>
                    write!(f, "unknown address type cannot be converted to IP addresses"),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for UnroutableAddressError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::TorV2 => None,
                Self::TorV3 => None,
                Self::I2p => None,
                Self::Cjdns => None,
                Self::Unknown => None,
            }
        }
    }

    /// Error types for [`AddrV2`] to [`IpAddr`] conversion.
    ///
    /// [`AddrV2`]: super::AddrV2
    /// [`IpAddr`]: super::IpAddr
    #[derive(Debug, PartialEq, Eq)]
    pub enum AddrV2ToIpAddrError {
        /// A [`AddrV2::TorV3`] address cannot be converted to a [`IpAddr`].
        ///
        /// [`AddrV2::TorV3`]: super::AddrV2::TorV3
        /// [`IpAddr`]: super::IpAddr
        TorV3,
        /// A [`AddrV2::I2p`] address cannot be converted to a [`IpAddr`].
        ///
        /// [`AddrV2::I2p`]: super::AddrV2::I2p
        /// [`IpAddr`]: super::IpAddr
        I2p,
        /// A [`AddrV2::Cjdns`] address cannot be converted to a [`IpAddr`],
        ///
        /// [`AddrV2::Cjdns`]: super::AddrV2::Cjdns
        /// [`IpAddr`]: super::IpAddr
        Cjdns,
        /// A [`AddrV2::Unknown`] address cannot be converted to a [`IpAddr`].
        ///
        /// [`AddrV2::Unknown`]: super::AddrV2::Unknown
        /// [`IpAddr`]: super::IpAddr
        Unknown,
    }

    impl fmt::Display for AddrV2ToIpAddrError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to IpAddr"),
                Self::I2p => write!(f, "I2P addresses cannot be converted to IpAddr"),
                Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to IpAddr"),
                Self::Unknown => write!(f, "Unknown address type cannot be converted to IpAddr"),
            }
        }
    }

    impl std::error::Error for AddrV2ToIpAddrError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::TorV3 => None,
                Self::I2p => None,
                Self::Cjdns => None,
                Self::Unknown => None,
            }
        }
    }

    /// Error types for [`AddrV2`] to [`Ipv4Addr`] conversion.
    ///
    /// [`AddrV2`]: super::AddrV2
    /// [`Ipv4Addr`]: super::Ipv4Addr
    #[derive(Debug, PartialEq, Eq)]
    pub enum AddrV2ToIpv4AddrError {
        /// A [`AddrV2::Ipv6`] address cannot be converted to a [`Ipv4Addr`].
        ///
        /// [`AddrV2::Ipv6`]: super::AddrV2::Ipv6
        /// [`Ipv4Addr`]: super::Ipv4Addr
        Ipv6,
        /// A [`AddrV2::TorV3`] address cannot be converted to a [`Ipv4Addr`].
        ///
        /// [`AddrV2::TorV3`]: super::AddrV2::TorV3
        /// [`Ipv4Addr`]: super::Ipv4Addr
        TorV3,
        /// A [`AddrV2::I2p`] address cannot be converted to a [`Ipv4Addr`].
        ///
        /// [`AddrV2::I2p`]: super::AddrV2::I2p
        /// [`Ipv4Addr`]: super::Ipv4Addr
        I2p,
        /// A [`AddrV2::Cjdns`] address cannot be converted to a [`Ipv4Addr`],
        ///
        /// [`AddrV2::Cjdns`]: super::AddrV2::Cjdns
        /// [`Ipv4Addr`]: super::Ipv4Addr
        Cjdns,
        /// A [`AddrV2::Unknown`] address cannot be converted to a [`Ipv4Addr`].
        ///
        /// [`AddrV2::Unknown`]: super::AddrV2::Unknown
        /// [`Ipv4Addr`]: super::Ipv4Addr
        Unknown,
    }

    impl fmt::Display for AddrV2ToIpv4AddrError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ipv6 => write!(f, "Ipv6 addresses cannot be converted to Ipv4Addr"),
                Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to Ipv4Addr"),
                Self::I2p => write!(f, "I2P addresses cannot be converted to Ipv4Addr"),
                Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to Ipv4Addr"),
                Self::Unknown => write!(f, "Unknown address type cannot be converted to Ipv4Addr"),
            }
        }
    }

    impl std::error::Error for AddrV2ToIpv4AddrError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Ipv6 => None,
                Self::TorV3 => None,
                Self::I2p => None,
                Self::Cjdns => None,
                Self::Unknown => None,
            }
        }
    }

    /// Error types for [`AddrV2`] to [`Ipv6Addr`] conversion.
    ///
    /// [`AddrV2`]: super::AddrV2
    /// [`Ipv6Addr`]: super::Ipv6Addr
    #[derive(Debug, PartialEq, Eq)]
    pub enum AddrV2ToIpv6AddrError {
        /// A [`AddrV2::Ipv4`] address cannot be converted to a [`Ipv6Addr`].
        ///
        /// [`AddrV2::Ipv4`]: super::AddrV2::Ipv4
        /// [`Ipv6Addr`]: super::Ipv6Addr
        Ipv4,
        /// A [`AddrV2::TorV3`] address cannot be converted to a [`Ipv6Addr`].
        ///
        /// [`AddrV2::TorV3`]: super::AddrV2::TorV3
        /// [`Ipv6Addr`]: super::Ipv6Addr
        TorV3,
        /// A [`AddrV2::I2p`] address cannot be converted to a [`Ipv6Addr`].
        ///
        /// [`AddrV2::I2p`]: super::AddrV2::I2p
        /// [`Ipv6Addr`]: super::Ipv6Addr
        I2p,
        /// A [`AddrV2::Cjdns`] address cannot be converted to a [`Ipv6Addr`].
        ///
        /// [`AddrV2::Cjdns`]: super::AddrV2::Cjdns
        /// [`Ipv6Addr`]: super::Ipv6Addr
        Cjdns,
        /// A [`AddrV2::Unknown`] address cannot be converted to a [`Ipv6Addr`].
        ///
        /// [`AddrV2::Unknown`]: super::AddrV2::Unknown
        /// [`Ipv6Addr`]: super::Ipv6Addr
        Unknown,
    }

    impl fmt::Display for AddrV2ToIpv6AddrError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ipv4 => write!(f, "Ipv4 addresses cannot be converted to Ipv6Addr"),
                Self::TorV3 => write!(f, "TorV3 addresses cannot be converted to Ipv6Addr"),
                Self::I2p => write!(f, "I2P addresses cannot be converted to Ipv6Addr"),
                Self::Cjdns => write!(f, "Cjdns addresses cannot be converted to Ipv6Addr"),
                Self::Unknown => write!(f, "Unknown address type cannot be converted to Ipv6Addr"),
            }
        }
    }

    impl std::error::Error for AddrV2ToIpv6AddrError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Ipv4 => None,
                Self::TorV3 => None,
                Self::I2p => None,
                Self::Cjdns => None,
                Self::Unknown => None,
            }
        }
    }
}

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
impl<'a> Arbitrary<'a> for AddrV1Message {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { time: u.arbitrary()?, address: u.arbitrary()? })
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
            1 => {
                let mut segments: [u16; 8] = u.arbitrary()?;
                if segments[0..3] == ONION || segments[0..6] == IPV4_EMBEDDED_IPV6 {
                    segments[0] ^= 1;
                }
                Ok(Self::Ipv6(Ipv6Addr::from(segments)))
            }
            2 => Ok(Self::TorV3(u.arbitrary()?)),
            3 => Ok(Self::I2p(u.arbitrary()?)),
            4 => {
                let mut segments: [u16; 8] = u.arbitrary()?;
                segments[0] = 0xFC00 | (segments[0] & 0x00FF);
                Ok(Self::Cjdns(Ipv6Addr::from(segments)))
            }
            _ => {
                let network = u.int_in_range(7..=u8::MAX)?;
                let mut bytes = Vec::<u8>::arbitrary(u)?;
                bytes.truncate(512);
                Ok(Self::Unknown(network, bytes))
            }
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

    use encoding::{Encode as _, Encoder as _, ExactSizeEncoder as _};
    use hex::hex;

    use super::*;
    use crate::hex;
    use crate::message::AddrV2Payload;

    #[test]
    fn encode_decode_address_roundtrip() {
        let sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        let addr = Address::new(&sock, ServiceFlags::NETWORK | ServiceFlags::WITNESS);
        let encoded_addr = encoding::encode_to_vec(&addr);
        let decoded_addr = encoding::decode_from_slice::<Address>(&encoded_addr).unwrap();

        assert_eq!(decoded_addr, addr);
    }

    #[test]
    fn serialize_address() {
        assert_eq!(
            encoding::encode_to_vec(&Address {
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
        let mut addr: Result<Address, _> = encoding::decode_from_slice(&[
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x0a, 0, 0, 1,
            0x20, 0x8d,
        ]);
        assert!(addr.is_ok());
        let full = addr.unwrap();
        assert!(matches!(full.socket_addr().unwrap(), SocketAddr::V4(_)));
        assert_eq!(full.services, ServiceFlags::NETWORK);
        assert_eq!(full.address, [0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
        assert_eq!(full.port, 8333);

        addr = encoding::decode_from_slice(&[
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
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), ip_bytes);

        let ip_bytes = hex!("02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
        let ip =
            AddrV2::Ipv6("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b".parse::<Ipv6Addr>().unwrap());
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), ip_bytes);

        let tor_bytes =
            hex!("042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
        let ip = AddrV2::TorV3(
            hex::decode_to_array::<32>(
                "53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88",
            )
            .unwrap(),
        );
        assert_eq!(encoding::encode_to_vec(&ip), tor_bytes);

        let i2p_bytes =
            hex!("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87");
        let ip = AddrV2::I2p(
            hex::decode_to_array::<32>(
                "a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87",
            )
            .unwrap(),
        );
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), i2p_bytes);

        let cjdns_bytes = hex!("0610fc010001000200030004000500060007");
        let ip = AddrV2::Cjdns("fc01:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap());
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), cjdns_bytes);

        let unk_bytes = hex!("aa0401020304");
        let ip = AddrV2::Unknown(170, hex!("01020304").to_vec());
        assert_eq!(encoding::encode_to_vec(&ip).as_slice(), unk_bytes);
    }

    #[test]
    fn deserialize_addrv2() {
        // Taken from https://github.com/bitcoin/bitcoin/blob/12a1c3ad1a43634d2a98717e49e3f02c4acea2fe/src/test/net_tests.cpp#L386

        // Valid IPv4.
        let ip_bytes = hex!("010401020304");
        let want = AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        let ip: AddrV2 = encoding::decode_from_slice(&ip_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid IPv4, valid length but address itself is shorter.
        let invalid = hex!("01040102");
        encoding::decode_from_slice::<AddrV2>(&invalid).unwrap_err();

        // Invalid IPv4, with bogus length.
        let invalid = hex!("010501020304");
        encoding::decode_from_slice::<AddrV2>(&invalid).unwrap_err();

        // Invalid IPv4, with extreme length.
        let extreme = hex!("01fd010201020304");
        encoding::decode_from_slice::<AddrV2>(&extreme).unwrap_err();

        // Valid IPv6.
        let ipv6_bytes = hex!("02100102030405060708090a0b0c0d0e0f10");
        let want = AddrV2::Ipv6("102:304:506:708:90a:b0c:d0e:f10".parse::<Ipv6Addr>().unwrap());
        let ip: AddrV2 = encoding::decode_from_slice(&ipv6_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid IPv6, with bogus length.
        let bogus = hex!("020400");
        assert!(encoding::decode_from_slice::<AddrV2>(&bogus).is_err());

        // Invalid IPv6, contains embedded IPv4.
        let embedded = hex!("021000000000000000000000ffff01020304");
        assert!(encoding::decode_from_slice::<AddrV2>(&embedded).is_err());

        // Invalid IPv6, contains embedded TORv2.
        let torish = hex!("0210fd87d87eeb430102030405060708090a");
        assert!(encoding::decode_from_slice::<AddrV2>(&torish).is_err());

        // Valid TORv3.
        let tor_bytes =
            hex!("042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f");
        let want =
            AddrV2::TorV3(hex!("79bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f"));
        let ip: AddrV2 = encoding::decode_from_slice(&tor_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid TORv3, with bogus length.
        let invalid = hex!("040000");
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Valid I2P.
        let i2p_bytes =
            hex!("0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87");
        let want =
            AddrV2::I2p(hex!("a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87"));
        let ip: AddrV2 = encoding::decode_from_slice(&i2p_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid I2P, with bogus length.
        let invalid = hex!("050300");
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Valid CJDNS.
        let cjdns_bytes = hex!("0610fc000001000200030004000500060007");
        let want = AddrV2::Cjdns("fc00:1:2:3:4:5:6:7".parse::<Ipv6Addr>().unwrap());
        let ip: AddrV2 = encoding::decode_from_slice(&cjdns_bytes).unwrap();
        assert_eq!(ip, want);

        // Invalid CJDNS, incorrect marker
        let invalid = hex!("0610fd000001000200030004000500060007");
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Invalid CJDNS, with bogus length.
        let invalid = hex!("060100");
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Unknown, with extreme length.
        let invalid = hex!("aafe0000000201020304050607");
        assert!(encoding::decode_from_slice::<AddrV2>(&invalid).is_err());

        // Unknown, with reasonable length.
        let unk_bytes = hex!("aa0401020304");
        let want = AddrV2::Unknown(170, hex!("01020304").to_vec());
        let ip: AddrV2 = encoding::decode_from_slice(&unk_bytes).unwrap();
        assert_eq!(ip, want);

        // Unknown, with zero length.
        let unk_bytes = hex!("aa00");
        let want = AddrV2::Unknown(170, vec![]);
        let ip: AddrV2 = encoding::decode_from_slice(&unk_bytes).unwrap();
        assert_eq!(ip, want);
    }

    #[test]
    fn addrv2message() {
        let raw = hex!("0261bc6649019902abab208d79627683fd4804010409090909208d");
        let addresses: AddrV2Payload = encoding::decode_from_slice(&raw).unwrap();

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

        assert_eq!(encoding::encode_to_vec(&addresses), raw);
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

    macro_rules! test_addrv2_encoder {
        (
            $test_name: ident,
            $addr: expr,
            $expected_bytes: expr$(,)?
        ) => {
            #[test]
            fn $test_name() {
                let addr = $addr;
                let expected_bytes = $expected_bytes;

                let mut encoder = addr.encoder();

                // Initial encoder len should match the expected_bytes
                let total_len = expected_bytes.len();
                assert_eq!(encoder.len(), total_len);

                // After each chunk, len() should reduce by the length of the chunk.
                let mut encoded = vec![];
                let mut bytes_consumed = 0;
                loop {
                    let chunk = encoder.current_chunk();
                    encoded.extend_from_slice(chunk);
                    let chunk_len = chunk.len();
                    assert_eq!(encoder.len(), total_len - bytes_consumed);

                    bytes_consumed += chunk_len;
                    if encoder.advance().has_finished() {
                        break;
                    }
                }
                assert_eq!(encoder.len(), 0);
                assert_eq!(encoded, expected_bytes);
            }
        };
    }

    test_addrv2_encoder!(
        addrv2_encoder_ipv4,
        AddrV2::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
        vec![0x01, 0x04, 1, 2, 3, 4]
    );
    test_addrv2_encoder!(
        addrv2_encoder_ipv6,
        AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        vec![0x02, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    test_addrv2_encoder!(addrv2_encoder_torv3, AddrV2::TorV3([0xAB; 32]), {
        let mut v = vec![0x04, 0x20];
        v.extend_from_slice(&[0xAB; 32]);
        v
    },);
    test_addrv2_encoder!(addrv2_encoder_i2p, AddrV2::I2p([0xCD; 32]), {
        let mut v = vec![0x05, 0x20];
        v.extend_from_slice(&[0xCD; 32]);
        v
    },);
    test_addrv2_encoder!(
        addrv2_encoder_cjdns,
        AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        vec![0x06, 0x10, 0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    test_addrv2_encoder!(
        addrv2_encoder_unknown,
        AddrV2::Unknown(0xFF, vec![0xDE, 0xAD]),
        vec![0xFF, 0x02, 0xDE, 0xAD]
    );
}
