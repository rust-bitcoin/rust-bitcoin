// SPDX-License-Identifier: CC0-1.0

//! Address-related constants.
//!
//! These constants describe the legacy Base58 prefixes used when encoding
//! Bitcoin addresses for different networks.

/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
