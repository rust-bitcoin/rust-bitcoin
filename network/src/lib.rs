// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! The term "network" is overloaded, here [`Network`] refers to the specific
//! Bitcoin network we are operating on e.g., signet, regtest. The terms
//! "network" and "chain" are often used interchangeably for this concept.

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;
use core::str::FromStr;

use internals::write_err;
#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::prelude::{String, ToOwned};

/// What kind of network we are on.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkKind {
    /// The Bitcoin mainnet network.
    Main,
    /// Some kind of testnet network (testnet, signet, regtest).
    Test,
}

impl NetworkKind {
    /// Returns true if this is real mainnet bitcoin.
    pub const fn is_mainnet(self) -> bool { matches!(self, Self::Main) }
}

impl From<Network> for NetworkKind {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::Main,
            Network::Testnet(_) | Network::Signet | Network::Regtest => Self::Test,
        }
    }
}

/// The cryptocurrency network to act on.
///
/// This is an exhaustive enum, meaning that we cannot add any future networks without defining a
/// new, incompatible version of this type. If you are using this type directly and wish to support the
/// new network, this will be a breaking change to your APIs and likely require changes in your code.
///
/// If you are concerned about forward compatibility, consider using `T: Into<Params>` instead of
/// this type as a parameter to functions in your public API, or directly using the `Params` type.
// For extensive discussion on the usage of `non_exhaustive` please see:
// https://github.com/rust-bitcoin/rust-bitcoin/issues/2225
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet(TestnetVersion),
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
}

/// The testnet version to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum TestnetVersion {
    /// Testnet version 3.
    V3,
    /// Testnet version 4.
    V4,
}

#[cfg(feature = "serde")]
impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_display_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid network identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Network, E>
            where
                E: serde::de::Error,
            {
                Network::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

impl Network {
    /// Converts a `Network` to its equivalent `bitcoind -chain` argument name.
    ///
    /// ```bash
    /// $ bitcoin-23.0/bin/bitcoind --help | grep -C 3 '\-chain=<chain>'
    /// Chain selection options:
    ///
    /// -chain=<chain>
    /// Use the chain <chain> (default: main). Allowed values: main, test, signet, regtest
    /// ```
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Self::Bitcoin => "main",
            // For user-side compatibility, testnet3 is retained as test
            Self::Testnet(TestnetVersion::V3) => "test",
            Self::Testnet(TestnetVersion::V4) => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
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
            "test" => Testnet(TestnetVersion::V3),
            "testnet4" => Testnet(TestnetVersion::V4),
            "signet" => Signet,
            "regtest" => Regtest,
            _ => return Err(ParseNetworkError(core_arg.to_owned())),
        };
        Ok(network)
    }

    /// Returns a string representation of the `Network` enum variant.
    /// This is useful for displaying the network type as a string.
    const fn as_display_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Testnet(TestnetVersion::V3) => "testnet",
            Self::Testnet(TestnetVersion::V4) => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_display_str())
    }
}

/// An error in parsing network string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(String);

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write_err!(f, "failed to parse {} as network", self.0; self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" => Ok(Self::Bitcoin),
            // For user-side compatibility, testnet3 is retained as testnet
            "testnet" => Ok(Self::Testnet(TestnetVersion::V3)),
            "testnet4" => Ok(Self::Testnet(TestnetVersion::V4)),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ParseNetworkError(s.to_owned())),
        }
    }
}

impl AsRef<Self> for Network {
    fn as_ref(&self) -> &Self { self }
}

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(feature = "alloc")]
    pub use alloc::{string::{String, ToString}, borrow::ToOwned};
}
