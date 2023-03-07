//! Regression tests for _most_ types that implement `serde::Serialize`.
//!
//! For remaining types see: ./serde_opcodes.rs
//!
//! If you find a type defined in `rust-bitcoin` that implements `Serialize` and does _not_ have a
//! regression test please add it.
//!
//! Types/tests were found using, and are ordered by, the output of: `git grep -l Serialize`.
//!

// In tests below `deserialize` is consensus deserialize while `serialize` is serde serialize, that
// is why we have two different serialized data files for tests that use binary serialized input.
//
// To create a file with the expected serialized data do something like:
//
//  use std::fs::File;
//  use std::io::Write;
//  let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
//  let got = serialize(&script).unwrap();
//  let mut file = File::create("/tmp/script_bincode").unwrap();
//  file.write_all(&got).unwrap();

#![cfg(feature = "serde")]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;

use bincode::serialize;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, KeySource};
use bitcoin::blockdata::locktime::{absolute, relative};
use bitcoin::blockdata::witness::Witness;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::psbt::raw::{self, Key, Pair, ProprietaryKey};
use bitcoin::psbt::{Input, Output, Psbt, PsbtSighashType};
use bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use bitcoin::taproot::{self, ControlBlock, LeafVersion, TapTree, TaprootBuilder};
use bitcoin::{
    ecdsa, Address, Block, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Target,
    Transaction, TxIn, TxOut, Txid, Work,
};

/// Implicitly does regression test for `BlockHeader` also.
#[test]
fn serde_regression_block() {
    let segwit = include_bytes!(
        "data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw"
    );
    let block: Block = deserialize(segwit).unwrap();
    let got = serialize(&block).unwrap();
    // The cast is required because Rust 1.41.1 throws the following error without it:
    // the trait `std::array::LengthAtMost32` is not implemented for `[u8; 5123]`
    let want = include_bytes!("data/serde/block_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_absolute_lock_time_height() {
    let t = absolute::LockTime::from_height(741521).expect("valid height");
    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde/absolute_lock_time_blocks_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_absolute_lock_time_time() {
    let seconds: u32 = 1653195600; // May 22nd, 5am UTC.
    let t = absolute::LockTime::from_time(seconds).expect("valid time");
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/absolute_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_height() {
    let t = relative::LockTime::from(relative::Height::from(0xCAFE_u16));
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/relative_lock_time_blocks_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_time() {
    let t = relative::LockTime::from(relative::Time::from_512_second_intervals(0xFACE_u16));
    let got = serialize(&t).unwrap();

    let want = include_bytes!("data/serde/relative_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_script() {
    let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
    let got = serialize(&script).unwrap();
    let want = include_bytes!("data/serde/script_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_txin() {
    let ser = include_bytes!("data/serde/txin_ser");
    let txin: TxIn = deserialize(ser).unwrap();

    let got = serialize(&txin).unwrap();
    let want = include_bytes!("data/serde/txin_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_txout() {
    let txout =
        TxOut { value: 0xDEADBEEFCAFEBABE, script_pubkey: ScriptBuf::from(vec![0u8, 1u8, 2u8]) };
    let got = serialize(&txout).unwrap();
    let want = include_bytes!("data/serde/txout_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_transaction() {
    let ser = include_bytes!("data/serde/transaction_ser");
    let tx: Transaction = deserialize(ser).unwrap();
    let got = serialize(&tx).unwrap();
    let want = include_bytes!("data/serde/transaction_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_witness() {
    let w0 = Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105")
        .unwrap();
    let w1 = Vec::from_hex("000000").unwrap();
    let vec = vec![w0, w1];
    let witness = Witness::from_slice(&vec);

    let got = serialize(&witness).unwrap();
    let want = include_bytes!("data/serde/witness_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_address() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = PublicKey::from_str(s.trim()).unwrap();
    let addr = Address::p2pkh(&pk, Network::Bitcoin);

    let got = serialize(&addr).unwrap();
    let want = include_bytes!("data/serde/address_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_priv_key() {
    let s = include_str!("data/serde/extended_priv_key");
    let key = ExtendedPrivKey::from_str(s.trim()).unwrap();
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_priv_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_pub_key() {
    let s = include_str!("data/serde/extended_pub_key");
    let key = ExtendedPubKey::from_str(s.trim()).unwrap();
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_pub_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_ecdsa_sig() {
    let s = include_str!("data/serde/ecdsa_sig_hex");
    let sig = ecdsa::Signature {
        sig: secp256k1::ecdsa::Signature::from_str(s.trim()).unwrap(),
        hash_ty: EcdsaSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/ecdsa_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_control_block() {
    let s = include_str!("data/serde/control_block_hex");
    let block = ControlBlock::decode(&Vec::<u8>::from_hex(s.trim()).unwrap()).unwrap();
    let got = serialize(&block).unwrap();

    let want = include_bytes!("data/serde/control_block_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_child_number() {
    let num = ChildNumber::Normal { index: 0xDEADBEEF };
    let got = serialize(&num).unwrap();
    let want = include_bytes!("data/serde/child_number_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_private_key() {
    let sk = PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
    let got = serialize(&sk).unwrap();
    let want = include_bytes!("data/serde/private_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_public_key() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = PublicKey::from_str(s.trim()).unwrap();
    let got = serialize(&pk).unwrap();
    let want = include_bytes!("data/serde/public_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_psbt() {
    let tx = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
                    .parse::<Txid>()
                    .unwrap(),
                vout: 1,
            },
            script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                .unwrap(),
            sequence: Sequence::from_consensus(4294967295),
            witness: Witness::from_slice(&[Vec::from_hex(
                "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105",
            )
            .unwrap()]),
        }],
        output: vec![TxOut {
            value: 190303501938,
            script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587")
                .unwrap(),
        }],
    };
    let unknown: BTreeMap<raw::Key, Vec<u8>> =
        vec![(raw::Key { type_value: 1, key: vec![0, 1] }, vec![3, 4, 5])].into_iter().collect();
    let key_source = ("deadbeef".parse().unwrap(), "m/0'/1".parse().unwrap());
    let keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = vec![(
        "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
        key_source.clone(),
    )]
    .into_iter()
    .collect();

    let proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = vec![(
        raw::ProprietaryKey {
            prefix: "prefx".as_bytes().to_vec(),
            subtype: 42,
            key: "test_key".as_bytes().to_vec(),
        },
        vec![5, 6, 7],
    )]
    .into_iter()
    .collect();

    let psbt = Psbt {
        version: 0,
        xpub: {
            let s = include_str!("data/serde/extended_pub_key");
            let xpub = ExtendedPubKey::from_str(s.trim()).unwrap();
            vec![(xpub, key_source)].into_iter().collect()
        },
        unsigned_tx: {
            let mut unsigned = tx.clone();
            unsigned.input[0].script_sig = ScriptBuf::new();
            unsigned.input[0].witness = Witness::default();
            unsigned
        },
        proprietary: proprietary.clone(),
        unknown: unknown.clone(),

        inputs: vec![Input {
            non_witness_utxo: Some(tx),
            witness_utxo: Some(TxOut {
                value: 190303501938,
                script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
            }),
            sighash_type: Some(PsbtSighashType::from(EcdsaSighashType::from_str("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY").unwrap())),
            redeem_script: Some(vec![0x51].into()),
            witness_script: None,
            partial_sigs: vec![(
                "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
                "304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe701".parse().unwrap(),
            )].into_iter().collect(),
            bip32_derivation: keypaths.clone().into_iter().collect(),
            final_script_witness: Some(Witness::from_slice(&[vec![1, 3], vec![5]])),
            ripemd160_preimages: vec![(ripemd160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
            sha256_preimages: vec![(sha256::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
            hash160_preimages: vec![(hash160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
            hash256_preimages: vec![(sha256d::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),
            ..Default::default()
        }],
        outputs: vec![Output {
            bip32_derivation: keypaths.into_iter().collect(),
            proprietary,
            unknown,
            ..Default::default()
        }],
    };

    let got = serialize(&psbt).unwrap();
    let want = include_bytes!("data/serde/psbt_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_raw_pair() {
    let pair = Pair {
        key: Key { type_value: 1u8, key: vec![0u8, 1u8, 2u8, 3u8] },
        value: vec![0u8, 1u8, 2u8, 3u8],
    };
    let got = serialize(&pair).unwrap();
    let want = include_bytes!("data/serde/raw_pair_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_proprietary_key() {
    let key = ProprietaryKey {
        prefix: vec![0u8, 1u8, 2u8, 3u8],
        subtype: 1u8,
        key: vec![0u8, 1u8, 2u8, 3u8],
    };
    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/proprietary_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taproot_sig() {
    let s = include_str!("data/serde/taproot_sig_hex");
    let sig = taproot::Signature {
        sig: secp256k1::schnorr::Signature::from_str(s.trim()).unwrap(),
        hash_ty: TapSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/taproot_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taptree() {
    let ver = LeafVersion::from_consensus(0).unwrap();
    let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);
    let mut builder = TaprootBuilder::new().add_leaf_with_ver(1, script.clone(), ver).unwrap();
    builder = builder.add_leaf(1, script).unwrap();
    let tree = TapTree::try_from(builder).unwrap();

    let got = serialize(&tree).unwrap();
    let want = include_bytes!("data/serde/taptree_bincode") as &[_];
    assert_eq!(got, want)
}

// Used to get a 256 bit integer as a byte array.
fn le_bytes() -> [u8; 32] {
    let x: u128 = 0xDEAD_BEEF_CAFE_BABE_DEAD_BEEF_CAFE_BABE;
    let y: u128 = 0xCAFE_DEAD_BABE_BEEF_CAFE_DEAD_BABE_BEEF;

    let mut bytes = [0_u8; 32];

    bytes[..16].copy_from_slice(&x.to_le_bytes());
    bytes[16..].copy_from_slice(&y.to_le_bytes());

    bytes
}

#[test]
fn serde_regression_work() {
    let work = Work::from_le_bytes(le_bytes());
    let got = serialize(&work).unwrap();
    let want = include_bytes!("data/serde/u256_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_target() {
    let target = Target::from_le_bytes(le_bytes());
    let got = serialize(&target).unwrap();
    let want = include_bytes!("data/serde/u256_bincode") as &[_];
    assert_eq!(got, want)
}
