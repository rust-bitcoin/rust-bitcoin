// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Rust Bitcoin Library
//!
//! This is a library for which supports the Bitcoin network protocol and associated
//! primitives. It is designed for Rust programs built to work with the Bitcoin
//! network.
//!
//! It is also written entirely in Rust to illustrate the benefits of strong type
//! safety, including ownership and lifetime, for financial and/or cryptographic
//! software.
//!

#![crate_name = "bitcoin"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]

// Experimental features we need
#![cfg_attr(all(test, feature = "unstable"), feature(test))]

// Clippy whitelist
#![cfg_attr(feature = "clippy", allow(needless_range_loop))] // suggests making a big mess of array newtypes
#![cfg_attr(feature = "clippy", allow(extend_from_slice))]   // `extend_from_slice` only available since 1.6

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

extern crate bitcoin_bech32;
extern crate bitcoin_hashes;
extern crate byteorder;
extern crate hex;
extern crate rand;
extern crate secp256k1;
#[cfg(feature = "serde")] extern crate serde;
#[cfg(feature = "strason")] extern crate strason;
#[cfg(all(test, feature = "unstable"))] extern crate test;
#[cfg(feature="bitcoinconsensus")] extern crate bitcoinconsensus;

#[cfg(test)]
#[macro_use]
mod test_macros;
#[macro_use]
mod internal_macros;
#[macro_use]
pub mod network;
pub mod blockdata;
pub mod util;
pub mod consensus;

pub use blockdata::block::Block;
pub use blockdata::block::BlockHeader;
pub use blockdata::script::Script;
pub use blockdata::transaction::Transaction;
pub use blockdata::transaction::TxIn;
pub use blockdata::transaction::TxOut;
pub use blockdata::transaction::OutPoint;
pub use blockdata::transaction::SigHashType;
pub use consensus::encode::VarInt;
pub use network::constants::Network;
pub use util::Error;
pub use util::address::Address;
pub use util::hash::BitcoinHash;
pub use util::key::PrivateKey;
pub use util::key::PublicKey;
pub use util::decimal::Decimal;
pub use util::decimal::UDecimal;
