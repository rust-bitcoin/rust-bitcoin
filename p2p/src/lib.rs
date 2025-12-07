// SPDX-License-Identifier: CC0-1.0

//! Rust Bitcoin Peer to Peer Message Types

#![no_std]
// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Pedantic lints that we enforce.
#![warn(clippy::return_self_not_must_use)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

mod consensus;
mod network_ext;

#[cfg(feature = "std")]
pub mod address;
#[cfg(feature = "std")]
pub mod message;
pub mod message_blockdata;
pub mod message_bloom;
pub mod message_compact_blocks;
pub mod message_filter;
#[cfg(feature = "std")]
pub mod message_network;

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::borrow::{Borrow, BorrowMut};
use core::str::FromStr;
use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::encode::{self, Decodable, Encodable};
use bitcoin::network::{Network, Params, TestnetVersion};
use hex::FromHex;
use internals::impl_to_hex_from_lower_hex;
use io::{BufRead, Write};

#[rustfmt::skip]
#[doc(inline)]
pub use self::network_ext::NetworkExt;

#[cfg(feature = "std")]
#[rustfmt::skip]
#[doc(inline)]
pub use self::{address::Address, message::CheckedData};

/// Version of the protocol as appearing in network version handshakes and some message headers.
///
/// This constant is used to signal to other peers which features you support. Increasing it implies
/// that your software also supports every feature prior to this version. Doing so without support
/// may lead to you incorrectly banning other peers or other peers banning you.
///
/// These are the features required for each version:
/// 70016 - Support receiving `wtxidrelay` message between `version` and `verack` message
/// 70015 - Support receiving invalid compact blocks from a peer without banning them
/// 70014 - Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
/// 70013 - Support `feefilter` message
/// 70012 - Support `sendheaders` message and announce new blocks via headers rather than inv
/// 70011 - Support NODE_BLOOM service flag and don't support bloom filter messages if it is not set
/// 70002 - Support `reject` message
/// 70001 - Support bloom filter messages `filterload`, `filterclear` `filteradd`, `merkleblock` and FILTERED_BLOCK inventory type
/// 60002 - Support `mempool` message
/// 60001 - Support `pong` message and nonce in `ping` message
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Support receiving `wtxidrelay` message between `version` and `verack` message
    pub const WTXID_RELAY_VERSION: Self = Self(70016);
    /// Support receiving invalid compact blocks from a peer without banning them
    pub const INVALID_CB_NO_BAN_VERSION: Self = Self(70015);
    /// Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
    pub const SHORT_IDS_BLOCKS_VERSION: Self = Self(70014);
    /// Support `feefilter` message
    pub const FEEFILTER_VERSION: Self = Self(70013);
    /// Support `sendheaders` message and announce new blocks via headers rather than inv
    pub const SENDHEADERS_VERSION: Self = Self(70012);
    /// Support `pong` message and nonce in `ping` message
    pub const BIP0031_VERSION: Self = Self(60001);
    /// All connections will be terminated below this version.
    pub const MIN_PEER_PROTO_VERSION: Self = Self(31800);
}

impl ProtocolVersion {
    /// Constructs a protocol version that is not well-known.
    pub fn from_nonstandard(version: u32) -> Self { Self(version) }
}

impl From<ProtocolVersion> for u32 {
    fn from(version: ProtocolVersion) -> Self { version.0 }
}

impl Encodable for ProtocolVersion {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ProtocolVersion {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(r)?))
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: Self = Self(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: Self = Self(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request. Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP-0064 for details on how this is implemented.
    pub const GETUTXO: Self = Self(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections. Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: Self = Self(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: Self = Self(1 << 3);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP-0157 and BIP-0158 for details on how this is implemented.
    pub const COMPACT_FILTERS: Self = Self(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP-0159 for details on how this is implemented.
    pub const NETWORK_LIMITED: Self = Self(1 << 10);

    /// P2P_V2 indicates that the node supports the P2P v2 encrypted transport protocol.
    /// See BIP-0324 for details on how this is implemented.
    pub const P2P_V2: Self = Self(1 << 11);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    #[must_use]
    pub fn add(&mut self, other: Self) -> Self {
        self.0 |= other.0;
        *self
    }

    /// Removes [ServiceFlags] from this.
    ///
    /// Returns itself.
    #[must_use]
    pub fn remove(&mut self, other: Self) -> Self {
        self.0 &= !other.0;
        *self
    }

    /// Checks whether [ServiceFlags] are included in this one.
    pub fn has(self, flags: Self) -> bool { (self.0 | flags.0) == self.0 }

    /// Gets the integer representation of this [`ServiceFlags`].
    pub fn to_u64(self) -> u64 { self.0 }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}
impl_to_hex_from_lower_hex!(ServiceFlags, |service_flags: &ServiceFlags| 16
    - service_flags.0.leading_zeros() as usize / 4);

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = *self;
        if flags == Self::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    let _ = flags.remove(ServiceFlags::$f);
                }
            };
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(WITNESS);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        write_flag!(P2P_V2);
        // If there are unknown flags left, we append them in hex.
        if flags != Self::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self { Self(f) }
}

impl From<ServiceFlags> for u64 {
    fn from(flags: ServiceFlags) -> Self { flags.0 }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self { self.add(rhs) }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) { let _ = self.add(rhs); }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self { self.remove(rhs) }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) { let _ = self.remove(rhs); }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(r)?))
    }
}
/// Network magic bytes to identify the cryptocurrency network the message was intended for.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct Magic([u8; 4]);

impl Magic {
    /// Bitcoin mainnet network magic bytes.
    pub const BITCOIN: Self = Self([0xF9, 0xBE, 0xB4, 0xD9]);
    /// Bitcoin testnet3 network magic bytes.
    pub const TESTNET3: Self = Self([0x0B, 0x11, 0x09, 0x07]);
    /// Bitcoin testnet4 network magic bytes.
    pub const TESTNET4: Self = Self([0x1c, 0x16, 0x3f, 0x28]);
    /// Bitcoin signet network magic bytes.
    pub const SIGNET: Self = Self([0x0A, 0x03, 0xCF, 0x40]);
    /// Bitcoin regtest network magic bytes.
    pub const REGTEST: Self = Self([0xFA, 0xBF, 0xB5, 0xDA]);

    /// Constructs a new network magic from bytes.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self { Self(bytes) }

    /// Gets network magic bytes.
    pub fn to_bytes(self) -> [u8; 4] { self.0 }

    /// Returns the magic bytes for the network defined by `params`.
    pub fn from_params(params: impl AsRef<Params>) -> Option<Self> {
        params.as_ref().network.try_into().ok()
    }
}

impl FromStr for Magic {
    type Err = ParseMagicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match <[u8; 4]>::from_hex(s) {
            Ok(magic) => Ok(Self::from_bytes(magic)),
            Err(e) => Err(ParseMagicError { error: e, magic: s.to_owned() }),
        }
    }
}

impl TryFrom<Network> for Magic {
    type Error = UnknownNetworkError;

    fn try_from(network: Network) -> Result<Self, Self::Error> {
        match network {
            Network::Bitcoin => Ok(Self::BITCOIN),
            Network::Testnet(TestnetVersion::V3) => Ok(Self::TESTNET3),
            Network::Testnet(TestnetVersion::V4) => Ok(Self::TESTNET4),
            Network::Signet => Ok(Self::SIGNET),
            Network::Regtest => Ok(Self::REGTEST),
            _ => Err(UnknownNetworkError(network)),
        }
    }
}

impl TryFrom<Magic> for Network {
    type Error = UnknownMagicError;

    fn try_from(magic: Magic) -> Result<Self, Self::Error> {
        match magic {
            Magic::BITCOIN => Ok(Self::Bitcoin),
            Magic::TESTNET3 => Ok(Self::Testnet(TestnetVersion::V3)),
            Magic::TESTNET4 => Ok(Self::Testnet(TestnetVersion::V4)),
            Magic::SIGNET => Ok(Self::Signet),
            Magic::REGTEST => Ok(Self::Regtest),
            _ => Err(UnknownMagicError(magic)),
        }
    }
}

impl fmt::Display for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        hex::fmt_hex_exact!(f, 4, &self.0, hex::Case::Lower)?;
        Ok(())
    }
}

impl fmt::Debug for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> { fmt::Display::fmt(self, f) }
}

impl fmt::LowerHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        hex::fmt_hex_exact!(f, 4, &self.0, hex::Case::Lower)?;
        Ok(())
    }
}
impl_to_hex_from_lower_hex!(Magic, |_| 8);

impl fmt::UpperHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        hex::fmt_hex_exact!(f, 4, &self.0, hex::Case::Upper)?;
        Ok(())
    }
}

impl Encodable for Magic {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for Magic {
    fn consensus_decode<R: BufRead + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        Ok(Self(Decodable::consensus_decode(reader)?))
    }
}

impl AsRef<[u8]> for Magic {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl AsRef<[u8; 4]> for Magic {
    fn as_ref(&self) -> &[u8; 4] { &self.0 }
}

impl AsMut<[u8]> for Magic {
    fn as_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

impl AsMut<[u8; 4]> for Magic {
    fn as_mut(&mut self) -> &mut [u8; 4] { &mut self.0 }
}

impl Borrow<[u8]> for Magic {
    fn borrow(&self) -> &[u8] { &self.0 }
}

impl Borrow<[u8; 4]> for Magic {
    fn borrow(&self) -> &[u8; 4] { &self.0 }
}

impl BorrowMut<[u8]> for Magic {
    fn borrow_mut(&mut self) -> &mut [u8] { &mut self.0 }
}

impl BorrowMut<[u8; 4]> for Magic {
    fn borrow_mut(&mut self) -> &mut [u8; 4] { &mut self.0 }
}

/// An error in parsing magic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseMagicError {
    /// The error that occurred when parsing the string.
    error: hex::HexToArrayError,
    /// The byte string that failed to parse.
    magic: String,
}

impl fmt::Display for ParseMagicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "failed to parse {} as network magic", self.magic)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseMagicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}

/// Error in creating a Network from Magic bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownMagicError(Magic);

impl fmt::Display for UnknownMagicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "unknown network magic {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownMagicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error in creating a Magic from a Network.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownNetworkError(Network);

impl fmt::Display for UnknownNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "unknown network {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ProtocolVersion {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> { Ok(Self(u.arbitrary()?)) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ServiceFlags {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> { Ok(Self(u.arbitrary()?)) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Magic {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> { Ok(Self(u.arbitrary()?)) }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use bitcoin::consensus::encode::{deserialize, serialize};

    use super::*;

    #[test]
    fn serialize_deserialize() {
        assert_eq!(serialize(&Magic::BITCOIN), &[0xf9, 0xbe, 0xb4, 0xd9]);
        let magic: Magic = Network::Bitcoin.try_into().unwrap();
        assert_eq!(serialize(&magic), &[0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(serialize(&Magic::TESTNET3), &[0x0b, 0x11, 0x09, 0x07]);
        let magic: Magic = Network::Testnet(TestnetVersion::V3).try_into().unwrap();
        assert_eq!(serialize(&magic), &[0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(serialize(&Magic::TESTNET4), &[0x1c, 0x16, 0x3f, 0x28]);
        let magic: Magic = Network::Testnet(TestnetVersion::V4).try_into().unwrap();
        assert_eq!(serialize(&magic), &[0x1c, 0x16, 0x3f, 0x28]);
        assert_eq!(serialize(&Magic::SIGNET), &[0x0a, 0x03, 0xcf, 0x40]);
        let magic: Magic = Network::Signet.try_into().unwrap();
        assert_eq!(serialize(&magic), &[0x0a, 0x03, 0xcf, 0x40]);
        assert_eq!(serialize(&Magic::REGTEST), &[0xfa, 0xbf, 0xb5, 0xda]);
        let magic: Magic = Network::Regtest.try_into().unwrap();
        assert_eq!(serialize(&magic), &[0xfa, 0xbf, 0xb5, 0xda]);

        assert_eq!(
            deserialize::<Magic>(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(),
            Network::Bitcoin.try_into().ok()
        );
        assert_eq!(
            deserialize::<Magic>(&[0x0b, 0x11, 0x09, 0x07]).ok(),
            Network::Testnet(TestnetVersion::V3).try_into().ok()
        );
        assert_eq!(
            deserialize::<Magic>(&[0x1c, 0x16, 0x3f, 0x28]).ok(),
            Network::Testnet(TestnetVersion::V4).try_into().ok()
        );
        assert_eq!(
            deserialize::<Magic>(&[0x0a, 0x03, 0xcf, 0x40]).ok(),
            Network::Signet.try_into().ok()
        );
        assert_eq!(
            deserialize::<Magic>(&[0xfa, 0xbf, 0xb5, 0xda]).ok(),
            Network::Regtest.try_into().ok()
        );
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
            ServiceFlags::P2P_V2,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(flags2.has(*f), *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO);
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        assert_eq!("ServiceFlags(P2P_V2)", ServiceFlags::P2P_V2.to_string());
        let flag = ServiceFlags::WITNESS
            | ServiceFlags::BLOOM
            | ServiceFlags::NETWORK
            | ServiceFlags::P2P_V2;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS|P2P_V2)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }

    #[test]
    fn magic_from_str() {
        let known_network_magic_strs = [
            ("f9beb4d9", Network::Bitcoin),
            ("0b110907", Network::Testnet(TestnetVersion::V3)),
            ("1c163f28", Network::Testnet(TestnetVersion::V4)),
            ("fabfb5da", Network::Regtest),
            ("0a03cf40", Network::Signet),
        ];

        for (magic_str, network) in &known_network_magic_strs {
            let magic: Magic = magic_str.parse::<Magic>().unwrap();
            assert_eq!(Network::try_from(magic).unwrap(), *network);
            assert_eq!(&magic.to_string(), magic_str);
        }
    }
}
