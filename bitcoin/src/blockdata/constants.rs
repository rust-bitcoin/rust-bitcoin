// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.

use hashes::{sha256d, Hash};

use crate::blockdata::block::{self, Block};
use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::script;
use crate::blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut};
use crate::blockdata::witness::Witness;
use crate::consensus::Params;
use crate::network::Network;
use crate::pow::CompactTarget;
use crate::{Amount, BlockHash};

/// Re-export everything from the [`primitives::constants`] module.
#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::primitives::constants::*;

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

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_int(486604799)
        .push_int_non_minimal(4)
        .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let out_script =
        script::Builder::new().push_slice(GENESIS_OUTPUT_PK).push_opcode(OP_CHECKSIG).into_script();
    ret.output.push(TxOut { value: Amount::from_sat(50 * 100_000_000), script_pubkey: out_script });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(params: impl AsRef<Params>) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].compute_txid().into();
    let merkle_root = hash.into();
    match params.as_ref().network {
        Network::Bitcoin => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 1231006505,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 2083236893,
            },
            txdata,
        },
        Network::Testnet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 414098458,
            },
            txdata,
        },
        Network::Signet => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 1598918400,
                bits: CompactTarget::from_consensus(0x1e0377ae),
                nonce: 52613770,
            },
            txdata,
        },
        Network::Regtest => Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 1296688602,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 2,
            },
            txdata,
        },
        _ => panic!("TODO: Handle non_exhaustive"),
    }
}

#[cfg(test)]
mod test {
    use alloc::format;
    use core::str::FromStr;

    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::encode::serialize;
    use crate::consensus::params;
    #[allow(unused_imports)] // Less maintenance to just import this in tests.
    use crate::prelude::*;
    use crate::Txid;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, transaction::Version::ONE);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Txid::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, Amount::from_str("50 BTC").unwrap());
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
        let _ = genesis_block(&Network::Bitcoin);
        let _ = genesis_block(Network::Bitcoin);
        // This works too, but is suboptimal because it inlines the const.
        let _ = genesis_block(Params::MAINNET);
        let _ = genesis_block(&Params::MAINNET);
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(&params::MAINNET);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, BlockHash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );

        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 2083236893);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(&params::TESTNET);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, BlockHash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(
            gen.header.block_hash().to_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(&params::SIGNET);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, BlockHash::all_zeros());
        assert_eq!(
            gen.header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(gen.header.time, 1598918400);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0377ae));
        assert_eq!(gen.header.nonce, 52613770);
        assert_eq!(
            gen.header.block_hash().to_string(),
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
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            _ => panic!("Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants"),
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
        testnet_chain_hash_genesis_block, Network::Testnet;
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
