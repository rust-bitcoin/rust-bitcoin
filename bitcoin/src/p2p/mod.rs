// SPDX-License-Identifier: CC0-1.0

//! Bitcoin p2p network types.
//!
//! This module defines support for (de)serialization and network transport
//! of Bitcoin data and Bitcoin p2p network messages.

#[cfg(feature = "std")]
pub mod address;
#[cfg(feature = "std")]
pub mod message;
#[cfg(feature = "std")]
pub mod message_blockdata;
#[cfg(feature = "std")]
pub mod message_bloom;
#[cfg(feature = "std")]
pub mod message_compact_blocks;
#[cfg(feature = "std")]
pub mod message_filter;
#[cfg(feature = "std")]
pub mod message_network;

use core::str::FromStr;
use core::{fmt, ops};

use hex::FromHex;
use internals::{debug_from_display, write_err};

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::prelude::{Borrow, BorrowMut, String, ToOwned};
use crate::{io, Network};

#[rustfmt::skip]
#[doc(inline)]
#[cfg(feature = "std")]
pub use self::address::Address;

/// Version of the protocol as appearing in network message headers.
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
pub const PROTOCOL_VERSION: u32 = 70001;

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(self, flags: ServiceFlags) -> bool { (self.0 | flags.0) == self.0 }

    /// Gets the integer representation of this [`ServiceFlags`].
    pub fn to_u64(self) -> u64 { self.0 }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(&self.0, f) }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = *self;
        if flags == ServiceFlags::NONE {
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
                    flags.remove(ServiceFlags::$f);
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
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self { ServiceFlags(f) }
}

impl From<ServiceFlags> for u64 {
    fn from(flags: ServiceFlags) -> Self { flags.0 }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self { self.add(rhs) }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.add(rhs); }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self { self.remove(rhs) }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) { self.remove(rhs); }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(r)?))
    }
}
/// Network magic bytes to identify the cryptocurrency network the message was intended for.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct Magic([u8; 4]);

impl Magic {
    /// Bitcoin mainnet network magic bytes.
    pub const BITCOIN: Self = Self([0xF9, 0xBE, 0xB4, 0xD9]);
    /// Bitcoin testnet network magic bytes.
    pub const TESTNET: Self = Self([0x0B, 0x11, 0x09, 0x07]);
    /// Bitcoin signet network magic bytes.
    pub const SIGNET: Self = Self([0x0A, 0x03, 0xCF, 0x40]);
    /// Bitcoin regtest network magic bytes.
    pub const REGTEST: Self = Self([0xFA, 0xBF, 0xB5, 0xDA]);

    /// Create network magic from bytes.
    pub fn from_bytes(bytes: [u8; 4]) -> Magic { Magic(bytes) }

    /// Get network magic bytes.
    pub fn to_bytes(self) -> [u8; 4] { self.0 }
}

impl FromStr for Magic {
    type Err = ParseMagicError;

    fn from_str(s: &str) -> Result<Magic, Self::Err> {
        match <[u8; 4]>::from_hex(s) {
            Ok(magic) => Ok(Magic::from_bytes(magic)),
            Err(e) => Err(ParseMagicError { error: e, magic: s.to_owned() }),
        }
    }
}

impl From<Network> for Magic {
    fn from(network: Network) -> Magic {
        match network {
            // Note: new network entries must explicitly be matched in `try_from` below.
            Network::Bitcoin => Magic::BITCOIN,
            Network::Testnet => Magic::TESTNET,
            Network::Signet => Magic::SIGNET,
            Network::Regtest => Magic::REGTEST,
        }
    }
}

impl TryFrom<Magic> for Network {
    type Error = UnknownMagicError;

    fn try_from(magic: Magic) -> Result<Self, Self::Error> {
        match magic {
            // Note: any new network entries must be matched against here.
            Magic::BITCOIN => Ok(Network::Bitcoin),
            Magic::TESTNET => Ok(Network::Testnet),
            Magic::SIGNET => Ok(Network::Signet),
            Magic::REGTEST => Ok(Network::Regtest),
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
debug_from_display!(Magic);

impl fmt::LowerHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        hex::fmt_hex_exact!(f, 4, &self.0, hex::Case::Lower)?;
        Ok(())
    }
}

impl fmt::UpperHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        hex::fmt_hex_exact!(f, 4, &self.0, hex::Case::Upper)?;
        Ok(())
    }
}

impl Encodable for Magic {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for Magic {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        Ok(Magic(Decodable::consensus_decode(reader)?))
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
        write_err!(f, "failed to parse {} as network magic", self.magic; self.error)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
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
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!("ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)", flag.to_string());
    }

    #[test]
    fn magic_from_str() {
        let known_network_magic_strs = [
            ("f9beb4d9", Network::Bitcoin),
            ("0b110907", Network::Testnet),
            ("fabfb5da", Network::Regtest),
            ("0a03cf40", Network::Signet),
        ];

        for (magic_str, network) in &known_network_magic_strs {
            let magic: Magic = Magic::from_str(magic_str).unwrap();
            assert_eq!(Network::try_from(magic).unwrap(), *network);
            assert_eq!(&magic.to_string(), magic_str);
        }
    }
}
