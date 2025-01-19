// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.

use hashes::sha256d;

use crate::block::{self, Block, Checked};
use crate::internal_macros::{impl_array_newtype, impl_array_newtype_stringify};
use crate::locktime::absolute;
use crate::network::{Network, Params};
use crate::opcodes::all::*;
use crate::pow::CompactTarget;
use crate::transaction::{self, OutPoint, Transaction, TxIn, TxOut};
use crate::witness::Witness;
use crate::{script, Amount, BlockHash, Sequence, TestnetVersion};

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
/// The maximum allowed redeem script size for a P2SH output.
pub const MAX_REDEEM_SCRIPT_SIZE: usize = primitives::script::MAX_REDEEM_SCRIPT_SIZE; // 520
/// The maximum allowed redeem script size of the witness script.
pub const MAX_WITNESS_SCRIPT_SIZE: usize = primitives::script::MAX_WITNESS_SCRIPT_SIZE; // 10_000
/// The maximum allowed size of any single witness stack element.
pub const MAX_STACK_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
/// This constant has ambiguous semantics. Please carefully check your intended use-case and define
/// a new constant reflecting that.
#[deprecated(since = "TBD", note = "use a more specific constant instead")]
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

// This is the 65 byte (uncompressed) pubkey used as the one-and-only output of the genesis transaction.
//
// ref: https://blockstream.info/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b?expand
// Note output script includes a leading 0x41 and trailing 0xac (added below using the `script::Builder`).
#[rustfmt::skip]
const GENESIS_OUTPUT_PK: [u8; 65] = [
    0x04,
    0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27,
    0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 0xb7, 0x10,
    0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6,
    0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde, 0xb6,
    0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4,
    0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, 0x12, 0xde,
    0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57,
    0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d, 0x5f
];

#[rustfmt::skip]
const TESTNET4_GENESIS_OUTPUT_PK: [u8; 33] = [0x00; 33];

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx(params: &Params) -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let (in_script, out_script) = {
        match params.network {
            Network::Testnet(TestnetVersion::V4) => (
                script::Builder::new()
                .push_int_unchecked(486604799)
                .push_int_non_minimal(4)
                .push_slice(b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e")
                .into_script(),
                script::Builder::new().push_slice(TESTNET4_GENESIS_OUTPUT_PK).push_opcode(OP_CHECKSIG).into_script(),

            ),
            _ => (
                script::Builder::new()
                .push_int_unchecked(486604799)
                .push_int_non_minimal(4)
                .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
                .into_script(),
                script::Builder::new().push_slice(GENESIS_OUTPUT_PK).push_opcode(OP_CHECKSIG).into_script(),
            ),
        }
    };

    ret.input.push(TxIn {
        previous_output: OutPoint::COINBASE_PREVOUT,
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    ret.output.push(TxOut { value: Amount::FIFTY_BTC, script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(params: impl AsRef<Params>) -> Block<Checked> {
    let params = params.as_ref();
    let transactions = vec![bitcoin_genesis_tx(params)];
    let hash: sha256d::Hash = transactions[0].compute_txid().into();
    let merkle_root: crate::TxMerkleNode = hash.into();
    let witness_root = block::compute_witness_root(&transactions);

    match params.network {
        Network::Bitcoin => Block::new_unchecked(
            block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
                merkle_root,
                time: 1231006505,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 2083236893,
            },
            transactions,
        )
        .assume_checked(witness_root),
        Network::Testnet(TestnetVersion::V3) => Block::new_unchecked(
            block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 414098458,
            },
            transactions,
        )
        .assume_checked(witness_root),
        Network::Testnet(TestnetVersion::V4) => Block::new_unchecked(
            block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
                merkle_root,
                time: 1714777860,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 393743547,
            },
            transactions,
        )
        .assume_checked(witness_root),
        Network::Signet => Block::new_unchecked(
            block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
                merkle_root,
                time: 1598918400,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 52613770,
            },
            transactions,
        )
        .assume_checked(witness_root),
        Network::Regtest => Block::new_unchecked(
            block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::GENESIS_PREVIOUS_BLOCK_HASH,
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
            },
            transactions,
        )
        .assume_checked(witness_root),
    }
}

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
    /// `ChainHash` for testnet3 bitcoin.
    #[deprecated(since = "0.33.0", note = "use `TESTNET3` instead")]
    pub const TESTNET: Self = Self([
        67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151,
        32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for testnet3 bitcoin.
    pub const TESTNET3: Self = Self([
        67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174, 186, 121, 151,
        32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0,
    ]);
    /// `ChainHash` for testnet4 bitcoin.
    pub const TESTNET4: Self = Self([
        67, 240, 139, 218, 176, 80, 227, 91, 86, 124, 134, 75, 145, 244, 127, 80, 174, 114, 90,
        226, 222, 83, 188, 251, 186, 242, 132, 218, 0, 0, 0, 0,
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
        match params.as_ref().network {
            Network::Bitcoin => Self::BITCOIN,
            Network::Testnet(TestnetVersion::V3) => Self::TESTNET3,
            Network::Testnet(TestnetVersion::V4) => Self::TESTNET4,
            Network::Signet => Self::SIGNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block_const(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::BITCOIN,
            Network::Testnet(TestnetVersion::V3) => Self::TESTNET3,
            Network::Testnet(TestnetVersion::V4) => Self::TESTNET4,
            Network::Signet => Self::SIGNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Converts genesis block hash into `ChainHash`.
    pub fn from_genesis_block_hash(block_hash: crate::BlockHash) -> Self {
        ChainHash(block_hash.to_byte_array())
    }
}

#[cfg(test)]
mod test {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::encode::serialize;
    use crate::network::params;
    use crate::Txid;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx(&Params::MAINNET);

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Txid::COINBASE_PREVOUT);
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, "50 BTC".parse::<Amount>().unwrap());
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(
            gen.compute_wtxid().to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn bitcoin_genesis_block_calling_convention() {
        // This is the best.
        let _ = genesis_block(&params::MAINNET);
        // this works and is ok too.
        let _ = genesis_block(Network::Bitcoin);
        let _ = genesis_block(Network::Bitcoin);
        // This works too, but is suboptimal because it inlines the const.
        let _ = genesis_block(Params::MAINNET);
        let _ = genesis_block(&Params::MAINNET);
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(&params::MAINNET);

        assert_eq!(gen.header().version, block::Version::ONE);
        assert_eq!(gen.header().prev_blockhash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
        assert_eq!(
            gen.header().merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );

        assert_eq!(gen.header().time, 1231006505);
        assert_eq!(gen.header().bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header().nonce, 2083236893);
        assert_eq!(
            gen.header().block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(&params::TESTNET3);
        assert_eq!(gen.header().version, block::Version::ONE);
        assert_eq!(gen.header().prev_blockhash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
        assert_eq!(
            gen.header().merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(gen.header().time, 1296688602);
        assert_eq!(gen.header().bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header().nonce, 414098458);
        assert_eq!(
            gen.header().block_hash().to_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(&params::SIGNET);
        assert_eq!(gen.header().version, block::Version::ONE);
        assert_eq!(gen.header().prev_blockhash, BlockHash::GENESIS_PREVIOUS_BLOCK_HASH);
        assert_eq!(
            gen.header().merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(gen.header().time, 1598918400);
        assert_eq!(gen.header().bits, CompactTarget::from_consensus(0x1e0377ae));
        assert_eq!(gen.header().nonce, 52613770);
        assert_eq!(
            gen.header().block_hash().to_string(),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block_const(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        #[allow(unreachable_patterns)] // This is specifically trying to catch later added variants.
        match network {
            Network::Bitcoin => {},
            Network::Testnet(TestnetVersion::V3) => {},
            Network::Testnet(TestnetVersion::V4) => {},
            Network::Signet => {},
            Network::Regtest => {},
            _ => panic!("update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Bitcoin;
        testnet_chain_hash_genesis_block, Network::Testnet(TestnetVersion::V3);
        testnet4_chain_hash_genesis_block, Network::Testnet(TestnetVersion::V4);
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block_const(Network::Bitcoin).to_string();
        let want = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        assert_eq!(got, want);
    }
}
