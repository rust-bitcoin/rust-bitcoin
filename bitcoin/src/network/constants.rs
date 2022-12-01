// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network constants.
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network.
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::network::constants::Network;
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

use core::borrow::{Borrow, BorrowMut};
use core::convert::TryFrom;
use core::str::FromStr;
use core::{fmt, ops};

use bitcoin_internals::{debug_from_display, write_err};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::error::impl_std_error;
use crate::hashes::hex::{Error, FromHex};
use crate::io;
use crate::prelude::{String, ToOwned};

/// Version of the protocol as appearing in network message headers
/// This constant is used to signal to other peers which features you support.
/// Increasing it implies that your software also supports every feature prior to this version.
/// Doing so without support may lead to you incorrectly banning other peers or other peers banning you.
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

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet,
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::{Network, Magic};
    /// use std::convert::TryFrom;
    ///
    /// assert_eq!(Ok(Network::Bitcoin), Network::try_from(Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD9])));
    /// assert_eq!(None, Network::from_magic(Magic::from_bytes([0xFF, 0xFF, 0xFF, 0xFF])));
    /// ```
    pub fn from_magic(magic: Magic) -> Option<Network> { Network::try_from(magic).ok() }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::{Network, Magic};
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.magic(), Magic::from_bytes([0xF9, 0xBE, 0xB4, 0xD9]));
    /// ```
    pub fn magic(self) -> Magic { Magic::from(self) }

    /// Converts a `Network` to its equivalent `bitcoind -chain` argument name.
    ///
    /// ```bash,no_run
    /// $ bitcoin-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Network::Bitcoin => "main",
            Network::Testnet => "test",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }

    /// Converts a `bitcoind -chain` argument name to its equivalent `Network`.
    ///
    /// ```bash
    /// $ bitcoin-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        use Network::*;

        let network = match core_arg {
           "main" => Bitcoin,
           "test" => Testnet,
           "signet" => Signet, 
           "regtest" => Regtest,
           _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}
impl_std_error!(ParseNetworkError);

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Network::*;

        let network = match s {
            "bitcoin" => Bitcoin,
            "testnet" => Testnet,
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(s.to_owned())),
        };
        Ok(network)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Network::*;

        let s = match *self {
            Bitcoin => "bitcoin",
            Testnet => "testnet",
            Signet => "signet",
            Regtest => "regtest",
        };
        write!(f, "{}", s)
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

/// An error in parsing magic bytes.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParseMagicError {
    /// The error that occurred when parsing the string.
    error: Error,
    /// The byte string that failed to parse.
    magic: String,
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

/// Error in parsing magic from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownMagic(Magic);

impl TryFrom<Magic> for Network {
    type Error = UnknownMagic;

    fn try_from(magic: Magic) -> Result<Self, Self::Error> {
        match magic {
            // Note: any new network entries must be matched against here.
            Magic::BITCOIN => Ok(Network::Bitcoin),
            Magic::TESTNET => Ok(Network::Testnet),
            Magic::SIGNET => Ok(Network::Signet),
            Magic::REGTEST => Ok(Network::Regtest),
            _ => Err(UnknownMagic(magic)),
        }
    }
}

impl fmt::Display for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        bitcoin_internals::fmt_hex_exact!(f, 4, &self.0, bitcoin_internals::hex::Case::Lower)?;
        Ok(())
    }
}
debug_from_display!(Magic);

impl fmt::LowerHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        bitcoin_internals::fmt_hex_exact!(f, 4, &self.0, bitcoin_internals::hex::Case::Lower)?;
        Ok(())
    }
}

impl fmt::UpperHex for Magic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        bitcoin_internals::fmt_hex_exact!(f, 4, &self.0, bitcoin_internals::hex::Case::Upper)?;
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

impl fmt::Display for ParseMagicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network magic", self.magic; self.error)
    }
}
impl_std_error!(ParseMagicError, error);

impl fmt::Display for UnknownMagic {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "unknown network magic {}", self.0)
    }
}
impl_std_error!(UnknownMagic);

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::str::FromStr;

    use super::{Magic, Network, ServiceFlags};
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        assert_eq!(serialize(&Network::Bitcoin.magic()), &[0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(serialize(&Network::Testnet.magic()), &[0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(serialize(&Network::Signet.magic()), &[0x0a, 0x03, 0xcf, 0x40]);
        assert_eq!(serialize(&Network::Regtest.magic()), &[0xfa, 0xbf, 0xb5, 0xda]);

        assert_eq!(deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(), Some(Network::Bitcoin.magic()));
        assert_eq!(deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(), Some(Network::Testnet.magic()));
        assert_eq!(deserialize(&[0x0a, 0x03, 0xcf, 0x40]).ok(), Some(Network::Signet.magic()));
        assert_eq!(deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(), Some(Network::Regtest.magic()));
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::Signet);
        assert!("fakenet".parse::<Network>().is_err());
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
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![
            (Bitcoin, "bitcoin"),
            (Testnet, "testnet"),
            (Signet, "signet"),
            (Regtest, "regtest"),
        ];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
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
