//! Regression tests for _most_ types that implement `serde::Serialize`.
//!
//! For remaining types see: ./serde_opcodes.rs
//!
//! If you find a type defined in `rust-bitcoin` that implements `Serialize` and does _not_ have a
//! regression test please add it.
//!
//! Types/tests were found using, and are ordered by, the output of: `git grep -l Serialize`.
//!

// To create a file with the expected serialized data do something like:
//
//  use std::fs::File;
//  use std::io::Write;
//  let script = WitnessScriptBuf::from(vec![0u8, 1u8, 2u8]);
//  let got = serialize(&script).unwrap();
//  let mut file = File::create("/tmp/script_bincode").unwrap();
//  file.write_all(&got).unwrap();

#![cfg(feature = "serde")]

use bincode::serialize;
use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::locktime::{absolute, relative};
use bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use bitcoin::taproot::{self, ControlBlock, LeafVersion, TapTree, TaprootBuilder};
use bitcoin::witness::Witness;
use bitcoin::{
    ecdsa, hex, Address, LegacyPublicKey, NetworkKind, OutPoint, ScriptSigBuf, TapScriptBuf, Txid,
    WifKey,
};

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
    let t = absolute::LockTime::from_mtp(seconds).expect("valid time");

    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde/absolute_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_height() {
    let t = relative::LockTime::from(relative::NumberOfBlocks::from(0xCAFE_u16));

    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde/relative_lock_time_blocks_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_relative_lock_time_time() {
    let t = relative::LockTime::from(relative::NumberOf512Seconds::from_512_second_intervals(
        0xFACE_u16,
    ));

    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde/relative_lock_time_seconds_bincode") as &[_];
    assert_eq!(got, want);
}

#[test]
fn serde_regression_script() {
    let script = ScriptSigBuf::from(vec![0u8, 1u8, 2u8]);

    let got = serialize(&script).unwrap();
    let want = include_bytes!("data/serde/script_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_out_point() {
    let out_point = OutPoint {
        txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
            .parse::<Txid>()
            .unwrap(),
        vout: 1,
    };

    let got = serialize(&out_point).unwrap();
    let want = include_bytes!("data/serde/out_point_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_witness() {
    let w0 =
        hex::decode_to_vec("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105")
            .unwrap();
    let w1 = hex::decode_to_vec("000000").unwrap();
    let vec = [w0, w1];
    let witness = Witness::from_slice(&vec);

    let got = serialize(&witness).unwrap();
    let want = include_bytes!("data/serde/witness_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_address() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = s.trim().parse::<LegacyPublicKey>().unwrap();
    let addr = Address::p2pkh(pk, NetworkKind::Main);

    let got = serialize(&addr).unwrap();
    let want = include_bytes!("data/serde/address_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_priv_key() {
    let s = include_str!("data/serde/extended_priv_key");
    let key = s.trim().parse::<Xpriv>().unwrap();

    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_priv_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_extended_pub_key() {
    let s = include_str!("data/serde/extended_pub_key");
    let key = s.trim().parse::<Xpub>().unwrap();

    let got = serialize(&key).unwrap();
    let want = include_bytes!("data/serde/extended_pub_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_ecdsa_sig() {
    let s = include_str!("data/serde/ecdsa_sig_hex");
    let sig = ecdsa::Signature {
        signature: s.trim().parse::<secp256k1::ecdsa::Signature>().unwrap(),
        sighash_type: EcdsaSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/ecdsa_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_control_block() {
    let s = include_str!("data/serde/control_block_hex");
    let block = ControlBlock::decode(&hex::decode_to_vec(s.trim()).unwrap()).unwrap();

    let got = serialize(&block).unwrap();
    let want = include_bytes!("data/serde/control_block_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_child_number() {
    let num = ChildNumber::from_raw(0xDEADBEEF);

    let got = serialize(&num).unwrap();
    let want = include_bytes!("data/serde/child_number_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_private_key() {
    let sk = WifKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();

    let got = serialize(&sk).unwrap();
    let want = include_bytes!("data/serde/private_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_public_key() {
    let s = include_str!("data/serde/public_key_hex");
    let pk = s.trim().parse::<LegacyPublicKey>().unwrap();

    let got = serialize(&pk).unwrap();
    let want = include_bytes!("data/serde/public_key_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taproot_sig() {
    let s = include_str!("data/serde/taproot_sig_hex");
    let sig = taproot::Signature {
        signature: s.trim().parse::<secp256k1::schnorr::Signature>().unwrap(),
        sighash_type: TapSighashType::All,
    };

    let got = serialize(&sig).unwrap();
    let want = include_bytes!("data/serde/taproot_sig_bincode") as &[_];
    assert_eq!(got, want)
}

#[test]
fn serde_regression_taptree() {
    let ver = LeafVersion::from_consensus(0).unwrap();
    let script = TapScriptBuf::from(vec![0u8, 1u8, 2u8]);
    let mut builder = TaprootBuilder::new().add_leaf_with_ver(1, script.clone(), ver).unwrap();
    builder = builder.add_leaf(1, script).unwrap();
    let tree = TapTree::try_from(builder).unwrap();

    let got = serialize(&tree).unwrap();
    let want = include_bytes!("data/serde/taptree_bincode") as &[_];
    assert_eq!(got, want)
}
