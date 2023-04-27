// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use hashes::Hash;
use internals::impl_array_newtype;

use crate::consensus::Params;
use crate::internal_macros::impl_array_newtype_stringify;
use crate::network::Network;

/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = units::weight::WITNESS_SCALE_FACTOR;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in ScriptBuf.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_array_newtype_stringify!(ChainHash, 32);

impl ChainHash {
    // Mainnet value can be verified at https://github.com/lightning/bolts/blob/master/00-introduction.md
    /// `ChainHash` for mainnet bitcoin.
    pub const BITCOIN: Self = Self([
        111, 226, 140, 10, 182, 241, 179, 114, 193, 166, 162, 70, 174, 99, 247, 79, 147, 30, 131,
        101, 225, 90, 8, 156, 104, 214, 25, 0, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for testnet bitcoin.
    pub const TESTNET: Self = Self([
        67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151,
        32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for signet bitcoin.
    pub const SIGNET: Self = Self([
        246, 30, 238, 59, 99, 163, 128, 164, 119, 160, 99, 175, 50, 178, 187, 201, 124, 159, 249,
        240, 31, 44, 66, 37, 233, 115, 152, 129, 8, 0, 0, 0,
    ]);
    /// `ChainHash` for regtest bitcoin.
    pub const REGTEST: Self = Self([
        6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94,
        51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15,
    ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub fn using_genesis_block(params: impl AsRef<Params>) -> Self {
        let network = params.as_ref().network;
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block_const(network: Network) -> Self {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}
