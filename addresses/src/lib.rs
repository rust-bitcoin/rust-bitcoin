// SPDX-License-Identifier: CC0-1.0

//! # Bitcoin Addresses
//!
//! Bitcoin addresses do not appear on chain; rather, they are conventions used by Bitcoin (wallet)
//! software to communicate where coins should be sent and are based on the output type e.g., P2WPKH.
//!
//! This crate can be used in a no-std environment but requires an allocator.
//!
//! ref: <https://sprovoost.nl/2022/11/10/what-is-a-bitcoin-address/>

#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod witness_program;
pub mod witness_version;

/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
