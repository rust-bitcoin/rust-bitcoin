// Rust Bitcoin Library - Written in 2023 by Tobin Harding <me@tobin.cc>
// SPDX-License-Identifier: CC0-1.0

//! Test vectors from [BIP143]
//!
//! [BIP143]: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>

use std::str::FromStr;

use bitcoin::consensus;
use bitcoin::hashes::hex::FromHex;
use bitcoin::script::Script;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::secp256k1::{self, ecdsa, Message, Secp256k1};
use bitcoin::{PublicKey, PrivateKey, Transaction, Network, ScriptBuf, Witness};

/// When we serialize in DER format we do not append the sighash type to the end of
/// the string. We do append it during `Witness::push_bitcoin_signature()`. BIP143 is not
/// consistent, sometimes the serialized string has the sighash type and sometimes not, as can be
/// seen by use of `assert_eq!(sig.serialized_der().to_string(), "XYZ")` below.
// TODO(tcharding): Consider patching the BIP143 to make sig serializations uniform.
fn serialize_sig(sig: ecdsa::Signature, ty: EcdsaSighashType) -> String {
    format!("{}{:02x}", sig.serialize_der(), ty.to_u32())
}

/// When we use `consensus::serialize_hex` to serialize a [`Script`] that represents a scriptPubkey
/// we prepend the length byte however all the strings appearing in BIP143 do not prepend the length
/// byte. This function is a helper and also a single place to document this.
fn serialize_script_pubkey(script_pubkey: &Script) -> String {
    script_pubkey.to_hex_string()
}

// Implements the BIP143 Native P2WPKH example. See also `sighash::tests::bip143_p2wpkh`.
#[test]
fn bip143_p2wpkh() {
    let secp = Secp256k1::new();
    let unsigned_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

    let tx_bytes = Vec::from_hex(unsigned_tx).expect("failed to parse unsigned transaction hex");
    let mut tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    // Sanity checks.
    assert_eq!(tx.version, 1);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);

    //   txin:      02 fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f 00000000 00 eeffffff
    //                 ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a 01000000 00 ffffffff
    //   txout:     02 202cb20600000000 1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac
    //                 9093510d00000000 1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac
    //   nLockTime: 11000000

    let input_0 = consensus::serialize_hex(&tx.input[0]);
    assert_eq!(input_0, "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff");
    let input_1 = consensus::serialize_hex(&tx.input[1]);
    assert_eq!(input_1, "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff");
    let output_0 = consensus::serialize_hex(&tx.output[0]);
    assert_eq!(output_0, "202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac");
    let output_1 = consensus::serialize_hex(&tx.output[1]);
    assert_eq!(output_1, "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac");
    let lock = consensus::serialize_hex(&tx.lock_time);
    assert_eq!(lock, "11000000");

    // The first input comes from an ordinary P2PK:
    //   scriptPubKey : 2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac value: 6.25
    //   private key  : bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866

    let sk = "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866";
    let secp_sk_0 = secp256k1::SecretKey::from_str(sk).expect("failed to parse input 0 sk");
    let secp_pk_0 = PublicKey::new(secp_sk_0.public_key(&secp));
    let script_pubkey_0 = ScriptBuf::new_p2pk(&secp_pk_0);
    assert_eq!(serialize_script_pubkey(script_pubkey_0.as_script()), "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac");

    // The second input comes from a P2WPKH witness program:
    //   scriptPubKey : 00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1, value: 6
    //   private key  : 619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
    //   public key   : 025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357

    let sk = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
    let secp_sk_1 = secp256k1::SecretKey::from_str(sk).expect("failed to parse input 0 sk");
    let secp_pk_1 = secp_sk_1.public_key(&secp);
    assert_eq!(secp_pk_1.to_string(), "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");

    let sk = PrivateKey::new(secp_sk_1, Network::Bitcoin);
    let pk_1 = sk.public_key(&secp);
    let pkh = pk_1.wpubkey_hash().expect("failed to get witness pubkey hash");
    let script_pubkey_1 = ScriptBuf::new_v0_p2wpkh(&pkh);
    assert_eq!(serialize_script_pubkey(script_pubkey_1.as_script()), "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1");

    // cache.segwit_cache() values are tested with the same test vectors in `sighash::tests::bip143_p2wpkh`
    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::All;

    let sighash_0 = cache.legacy_signature_hash(0, script_pubkey_0.as_script(), ty.to_u32()).expect("failed to get legacy sighash");
    let script_code = bitcoin::bip143::ScriptCode::new_p2wpkh(&script_pubkey_1).expect("not p2wpkh");

    let value = 600_000_000;
    let sighash_1 = cache.segwit_signature_hash(1, &script_code, value, ty).unwrap();

    //   hash preimage: 0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000
    //
    //   nVersion:     01000000
    //   hashPrevouts: 96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37
    //   hashSequence: 52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b
    //   outpoint:     ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000
    //   scriptCode:   1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac
    //   amount:       0046c32300000000
    //   nSequence:    ffffffff
    //   hashOutputs:  863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5
    //   nLockTime:    11000000
    //   nHashType:    01000000
    //
    //   sigHash:      c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670

    assert_eq!(consensus::serialize_hex(&script_code), "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");
    assert_eq!(consensus::serialize_hex(&tx.input[1].previous_output), "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000");
    assert_eq!(consensus::serialize_hex(&sighash_1), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");

    let msg = Message::from_slice(sighash_0.as_ref()).expect("failed to parse sighash");
    let sig_0 = secp.sign_ecdsa(&msg, &secp_sk_0);

    //   signature:    304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee

    let msg = Message::from_slice(sighash_1.as_ref()).expect("failed to parse sighash");
    let sig_1 = secp.sign_ecdsa(&msg, &secp_sk_1);
    let der_1 = sig_1.serialize_der();
    assert_eq!(der_1.to_string(), "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee");

    // The serialized signed transaction is: 01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000
    //
    //   nVersion:  01000000
    //   marker:    00
    //   flag:      01
    //   txin:      02 fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f 00000000 494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01 eeffffff
    //                 ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a 01000000 00 ffffffff
    //   txout:     02 202cb20600000000 1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac
    //                 9093510d00000000 1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac
    //   witness    00
    //              02 47304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01 21025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357
    //   nLockTime: 11000000

    tx.input[0].script_sig = ScriptBuf::p2pk_script_sig(sig_0);
    assert_eq!(consensus::serialize_hex(&tx.input[0]), "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffff");

    let mut witness = Witness::new();
    witness.push_bitcoin_signature(&der_1, ty);
    witness.push(&pk_1.to_bytes());
    assert_eq!(consensus::serialize_hex(&witness), "0247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");

    tx.input[1].witness = witness;
    assert_eq!(consensus::serialize_hex(&tx.input[1]), "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff");

    let signed_tx = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    let tx_bytes = Vec::from_hex(signed_tx).expect("failed to parse signed transaction hex");
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    assert_eq!(tx, want_signed_tx);
}

// Implements the BIP143 P2SH-P2WPKH example. See also `sighash::tests::bip143_p2wpkh_nested_in_p2sh`.
#[test]
fn bip143_p2wpkh_nested_in_p2sh() {
    let secp = Secp256k1::new();
    let unsigned_tx = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";

    let tx_bytes = Vec::from_hex(unsigned_tx).expect("failed to parse unsigned transaction hex");
    let mut tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    // Sanity checks.
    assert_eq!(tx.version, 1);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    //     txin:      01 db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477 01000000 00 feffffff
    //     txout:     02 b8b4eb0b00000000 1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac
    //                   0008af2f00000000 1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac
    //     nLockTime: 92040000

    let input_0 = consensus::serialize_hex(&tx.input[0]);
    assert_eq!(input_0, "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff");
    let output_0 = consensus::serialize_hex(&tx.output[0]);
    assert_eq!(output_0, "b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac");
    let output_1 = consensus::serialize_hex(&tx.output[1]);
    assert_eq!(output_1, "0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac");
    let lock = consensus::serialize_hex(&tx.lock_time);
    assert_eq!(lock, "92040000");

    //   The input comes from a P2SH-P2WPKH witness program:
    //     scriptPubKey : a9144733f37cf4db86fbc2efed2500b4f4e49f31202387, value: 10
    //     redeemScript : 001479091972186c449eb1ded22b78e40d009bdf0089
    //     private key  : eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf
    //     public key   : 03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873

    // secp256k1 keys
    let sk = "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf";
    let secp_sk = secp256k1::SecretKey::from_str(sk).expect("failed to parse sk");
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");

    // bitcoin keys
    let sk = PrivateKey::new(secp_sk, Network::Bitcoin);
    let pk = sk.public_key(&secp);
    let pkh = pk.wpubkey_hash().expect("failed to get witness pubkey hash");
    let redeem_script = ScriptBuf::new_v0_p2wpkh(&pkh);
    assert_eq!(serialize_script_pubkey(redeem_script.as_script()), "001479091972186c449eb1ded22b78e40d009bdf0089");

    let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    assert_eq!(script_pubkey.as_script().to_hex_string(), "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387");

    let value = 1_000_000_000;

    // cache.segwit_cache() values are tested with the same test vectors in `sighash::tests::bip143_p2wpkh_nested_in_p2sh`
    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::All;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wpkh(&redeem_script).expect("not p2wpkh");
    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();

    //   hash preimage: 01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000

    //     nVersion:     01000000
    //     hashPrevouts: b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a
    //     hashSequence: 18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198
    //     outpoint:     db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000
    //     scriptCode:   1976a91479091972186c449eb1ded22b78e40d009bdf008988ac
    //     amount:       00ca9a3b00000000
    //     nSequence:    feffffff
    //     hashOutputs:  de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83
    //     nLockTime:    92040000
    //     nHashType:    01000000

    //   sigHash:      64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6

    assert_eq!(consensus::serialize_hex(&script_code), "1976a91479091972186c449eb1ded22b78e40d009bdf008988ac");
    assert_eq!(consensus::serialize_hex(&tx.input[0].previous_output), "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a547701000000");
    assert_eq!(consensus::serialize_hex(&sighash), "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6");

    //   signature:    3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let sig = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig, ty), "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");
    let der = sig.serialize_der();

    //   The serialized signed transaction is: 01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000
    //     nVersion:  01000000
    //     marker:    00
    //     flag:      01
    //     txin:      01 db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477 01000000 1716001479091972186c449eb1ded22b78e40d009bdf0089 feffffff
    //     txout:     02 b8b4eb0b00000000 1976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac
    //                   0008af2f00000000 1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac
    //     witness    02 473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01 2103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873
    //     nLockTime: 92040000

    let mut witness = Witness::new();
    witness.push_bitcoin_signature(&der, ty);
    witness.push(&pk.to_bytes());
    assert_eq!(consensus::serialize_hex(&witness), "02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");

    tx.input[0].witness = witness;
    tx.input[0].script_sig = ScriptBuf::p2sh_p2wpkh_script_sig(pkh);

    assert_eq!(consensus::serialize_hex(&tx.input[0]), "db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff");

    let signed_tx = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000";
    let tx_bytes = Vec::from_hex(signed_tx).expect("failed to parse signed transaction hex");
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    assert_eq!(tx, want_signed_tx);
}

// Implements the BIP143 Native P2WSH example part 1. See also `sighash::tests::bip143_p2wsh_part_1`.
//
// This example shows how OP_CODESEPARATOR and out-of-range SIGHASH_SINGLE are processed.
#[test]
fn bip143_p2wsh_part_1() {
    let secp = Secp256k1::new();

    // The following is an unsigned transaction:
    //     0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000

    let unsigned_tx = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000";

    let tx_bytes = Vec::from_hex(unsigned_tx).expect("failed to parse unsigned transaction hex");
    let mut tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    // Sanity checks.
    assert_eq!(tx.version, 1);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 1);

    //     nVersion:  01000000
    //     txin:      02 fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e 00000000 00 ffffffff
    //                   0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8 00000000 00 ffffffff
    //     txout:     01 00f2052a01000000 1976a914a30741f8145e5acadf23f751864167f32e0963f788ac
    //     nLockTime: 00000000

    let input_0 = consensus::serialize_hex(&tx.input[0]);
    assert_eq!(input_0, "fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff");
    let input_1 = consensus::serialize_hex(&tx.input[1]);
    assert_eq!(input_1, "0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff");
    let output_0 = consensus::serialize_hex(&tx.output[0]);
    assert_eq!(output_0, "00f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac");
    let lock = consensus::serialize_hex(&tx.lock_time);
    assert_eq!(lock, "00000000");

    //   The first input comes from an ordinary P2PK:
    //     scriptPubKey: 21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac value: 1.5625
    //     private key:  b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c

    let sk = "b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c";
    let secp_sk_0 = secp256k1::SecretKey::from_str(sk).expect("failed to parse input 0 sk");
    let secp_pk_0 = PublicKey::new(secp_sk_0.public_key(&secp));
    let script_pubkey_0 = ScriptBuf::new_p2pk(&secp_pk_0);
    assert_eq!(serialize_script_pubkey(script_pubkey_0.as_script()), "21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac");

    // cache.segwit_cache() values are tested with the same test vectors in `sighash::tests::bip143_p2sh_part_1`
    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::All;

    let sighash = cache.legacy_signature_hash(0, script_pubkey_0.as_script(), ty.to_u32()).expect("failed to get legacy sighash");

    //     signature:    304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201 (SIGHASH_ALL)

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let input_0_sig = secp.sign_ecdsa(&msg, &secp_sk_0);
    assert_eq!(serialize_sig(input_0_sig, ty), "304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201");

    //   The second input comes from a native P2WSH witness program:
    //     scriptPubKey : 00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0, value: 49
    //     witnessScript: 21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
    //                    <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae> CHECKSIGVERIFY CODESEPARATOR <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465> CHECKSIG

    // TODO(tcharding): Patch BIP143 to include the pushes e.g.,
    //  PUSHBYTES_33 <026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae> CHECKSIGVERIFY CODESEPARATOR PUSHBYTES_33 <0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465> CHECKSIG

    let witness_script = ScriptBuf::from_hex("21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac").expect("failed to parse witness script");
    let script_pubkey_1 = witness_script.to_v0_p2wsh();
    assert_eq!(serialize_script_pubkey(script_pubkey_1.as_script()), "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0");

    //   To sign it with a nHashType of 3 (SIGHASH_SINGLE):
    //   scriptCode:  4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
    //                                                                                        ^^
    //                (please note that the not-yet-executed OP_CODESEPARATOR is not removed from the scriptCode)
    //   preimage:    01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f8000000004721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000
    //   sigHash:     82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391
    //   public key:  026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae
    //   private key: 8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd
    //   signature:   3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703

    let ty = EcdsaSighashType::Single;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "4721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");

    let value = 4_900_000_000;
    let sighash = cache.segwit_signature_hash(1, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391");

    let sk = "8e02b539b1500aa7c81cf3fed177448a546f19d2be416c0c61ff28e577d8d0cd";
    let input_1_secp_sk_0 = secp256k1::SecretKey::from_str(sk).expect("failed to parse sk");
    let input_1_secp_pk_0 = input_1_secp_sk_0.public_key(&secp);
    assert_eq!(input_1_secp_pk_0.to_string(), "026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880ae");

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let input_1_sig_0 = secp.sign_ecdsa(&msg, &input_1_secp_sk_0);
    assert_eq!(serialize_sig(input_1_sig_0, ty), "3044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e2703");

    //   scriptCode:  23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac
    //                (everything up to the last executed OP_CODESEPARATOR, including that OP_CODESEPARATOR, are removed)
    //   preimage:    01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d4100000000000000000000000000000000000000000000000000000000000000000815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000023210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac0011102401000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000003000000
    //   sigHash:     fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47
    //   public key:  0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465
    //   private key: 86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec
    //   signature:   304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503

    let script_code = bitcoin::bip143::ScriptCode::__new_p2wsh_remove_op_codeseparator(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac");

    let value = 4_900_000_000;
    let sighash = cache.segwit_signature_hash(1, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47");

    let sk = "86bf2ed75935a0cbef03b89d72034bb4c189d381037a5ac121a70016db8896ec";
    let input_1_secp_sk_1 = secp256k1::SecretKey::from_str(sk).expect("failed to parse sk");
    let input_1_secp_pk_1 = input_1_secp_sk_1.public_key(&secp);
    assert_eq!(input_1_secp_pk_1.to_string(), "0255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465");

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let input_1_sig_1 = secp.sign_ecdsa(&msg, &input_1_secp_sk_1);
    assert_eq!(serialize_sig(input_1_sig_1, ty), "304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503");

    tx.input[0].script_sig = ScriptBuf::p2pk_script_sig(input_0_sig);

    let mut witness = Witness::new();

    // Note we push sigs in reverse order to how they appear in the redeem script.
    witness.push_bitcoin_signature(&input_1_sig_1.serialize_der(), ty);
    witness.push_bitcoin_signature(&input_1_sig_0.serialize_der(), ty);
    witness.push(witness_script.as_bytes());

    tx.input[1].witness = witness;
    tx.input[1].script_sig = ScriptBuf::default();

    //   The serialized signed transaction is: 01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000
    let signed_tx = "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000";
    let tx_bytes = Vec::from_hex(signed_tx).expect("failed to parse signed transaction hex");
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    assert_eq!(tx, want_signed_tx);
}

// Implements the BIP143 Native P2WSH example part 2. See also `sighash::tests::bip143_p2wsh_part_2`.
//
// This example shows how unexecuted OP_CODESEPARATOR is processed, and SINGLE|ANYONECANPAY does not commit to the input index
#[test]
fn bip143_p2wsh_part_2() {
    let secp = Secp256k1::new();

    // The following is an unsigned transaction:
    //     0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000
    let unsigned_tx = "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000";

    let tx_bytes = Vec::from_hex(unsigned_tx).expect("failed to parse unsigned transaction hex");
    let mut tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    // Sanity checks.
    assert_eq!(tx.version, 1);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);

    //     nVersion:  01000000
    //     txin:      02 e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc001 00000000 00 ffffffff
    //                   80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b 00000000 00 ffffffff
    //     txout:     02 8096980000000000 1976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac
    //                   8096980000000000 1976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac
    //     nLockTime: 00000000

    let input_0 = consensus::serialize_hex(&tx.input[0]);
    assert_eq!(input_0, "e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff");
    let input_1 = consensus::serialize_hex(&tx.input[1]);
    assert_eq!(input_1, "80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff");
    let output_0 = consensus::serialize_hex(&tx.output[0]);
    assert_eq!(output_0, "80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac");
    let output_1 = consensus::serialize_hex(&tx.output[1]);
    assert_eq!(output_1, "80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac");
    let lock = consensus::serialize_hex(&tx.lock_time);
    assert_eq!(lock, "00000000");

    //   The first input comes from a native P2WSH witness program:
    //     scriptPubKey: 0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d value: 0.16777215
    //     witnessScript:0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                   0 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG

    let witness_script_0 = ScriptBuf::from_hex("0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac").expect("failed to parse redeem script");
    let script_pubkey_0 = witness_script_0.to_v0_p2wsh();
    assert_eq!(serialize_script_pubkey(script_pubkey_0.as_script()), "0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d");

    //   The second input comes from a native P2WSH witness program:
    //     scriptPubKey: 0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537 value: 0.16777215
    //     witnessScript:5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                   1 IF CODESEPARATOR ENDIF <0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98> CHECKSIG

    let witness_script_1 = ScriptBuf::from_hex("5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac").expect("failed to parse witness script");
    let script_pubkey_1 = witness_script_1.to_v0_p2wsh();
    assert_eq!(serialize_script_pubkey(script_pubkey_1.as_script()), "0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537");

    //   To sign it with a nHashType of 0x83 (SINGLE|ANYONECANPAY):
    //   outpoint:    e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc00100000000
    //   scriptCode:  270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                (since the OP_CODESEPARATOR is not executed, nothing is removed from the scriptCode)
    //   hashOutputs: b258eaf08c39fbe9fbac97c15c7e7adeb8df142b0df6f83e017f349c2b6fe3d2
    //   preimage:    0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc00100000000270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98acffffff0000000000ffffffffb258eaf08c39fbe9fbac97c15c7e7adeb8df142b0df6f83e017f349c2b6fe3d20000000083000000
    //   sigHash:     e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a
    //   public key:  0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98
    //   private key: f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d
    //   signature:   3045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683

    let ty = EcdsaSighashType::SinglePlusAnyoneCanPay;
    // cache.segwit_cache() values are tested with the same test vectors in `sighash::tests::bip143_p2sh_part_2`
    let mut cache = SighashCache::new(&tx);

    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script_0);
    assert_eq!(consensus::serialize_hex(&script_code), "270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac");

    let value = 16_777_215;
    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a");

    let sk = "f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d";
    let secp_sk_0 = secp256k1::SecretKey::from_str(sk).expect("failed to parse sk");
    let secp_pk_0 = secp_sk_0.public_key(&secp);
    assert_eq!(secp_pk_0.to_string(), "0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98");

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let sig_0 = secp.sign_ecdsa(&msg, &secp_sk_0);
    assert_eq!(serialize_sig(sig_0, ty), "3045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683");

    //   outpoint:    80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b00000000
    //   scriptCode:  2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                (everything up to the last executed OP_CODESEPARATOR, including that OP_CODESEPARATOR, are removed)
    //   hashOutputs: 91ea93dd77f702b738ebdbf3048940a98310e869a7bb8fa2c6cb3312916947ca
    //   preimage:    010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b000000002468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98acffffff0000000000ffffffff91ea93dd77f702b738ebdbf3048940a98310e869a7bb8fa2c6cb3312916947ca0000000083000000
    //   sigHash:     cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54
    //   public key:  0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98
    //   private key: f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d
    //   signature:   30440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83

    let script_code = bitcoin::bip143::ScriptCode::__new_p2wsh_remove_op_codeseparator(&witness_script_1);
    assert_eq!(consensus::serialize_hex(&script_code), "2468210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac");

    let value = 16_777_215;
    let sighash = cache.segwit_signature_hash(1, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54");

    let sk = "f52b3484edd96598e02a9c89c4492e9c1e2031f471c49fd721fe68b3ce37780d";
    let secp_sk_1 = secp256k1::SecretKey::from_str(sk).expect("failed to parse sk");
    let secp_pk_1 = secp_sk_1.public_key(&secp);
    assert_eq!(secp_pk_1.to_string(), "0392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98");

    let msg = Message::from_slice(sighash.as_ref()).expect("failed to parse sighash");
    let sig_1 = secp.sign_ecdsa(&msg, &secp_sk_1);
    assert_eq!(serialize_sig(sig_1, ty), "30440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83");

    let mut witness = Witness::new();
    witness.push_bitcoin_signature(&sig_0.serialize_der(), ty);
    witness.push(witness_script_0.as_bytes());
    tx.input[0].witness = witness;
    tx.input[0].script_sig = ScriptBuf::default();

    let mut witness = Witness::new();
    witness.push_bitcoin_signature(&sig_1.serialize_der(), ty);
    witness.push(witness_script_1.as_bytes());
    tx.input[1].witness = witness;
    tx.input[1].script_sig = ScriptBuf::default();

    //   The serialized signed transaction is:
    //   01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000
    //     nVersion:  01000000
    //     marker:    00
    //     flag:      01
    //     txin:      02 e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc001 00000000 00 ffffffff
    //                   80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b 00000000 00 ffffffff
    //     txout:     02 8096980000000000 1976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac
    //                   8096980000000000 1976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac
    //     witness    02 483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683 270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                02 4730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83 275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //     nLockTime: 00000000

    let signed_tx = "01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000";

    let tx_bytes = Vec::from_hex(signed_tx).expect("failed to parse signed transaction hex");
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    assert_eq!(tx, want_signed_tx);

    //   Since SINGLE|ANYONECANPAY does not commit to the input index, the signatures are still valid when the input-output pairs are swapped:
    //   0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000
    //     nVersion:  01000000
    //     marker:    00
    //     flag:      01
    //     txin:      02 80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b 00000000 00 ffffffff
    //                   e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc001 00000000 00 ffffffff
    //     txout:     02 8096980000000000 1976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac
    //                   8096980000000000 1976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac
    //     witness    02 4730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83 275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //                02 483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683 270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac
    //     nLockTime: 00000000

    let signed_tx = "0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000";
    let tx_bytes = Vec::from_hex(signed_tx).expect("failed to parse signed transaction hex");
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).expect("failed to deserialize tx bytes");

    let mut swapped = tx.clone();
    swapped.input[0] = tx.input[1].clone();
    swapped.input[1] = tx.input[0].clone();
    swapped.output[0] = tx.output[1].clone();
    swapped.output[1] = tx.output[0].clone();

    assert_eq!(swapped, want_signed_tx);
}

// Implements the BIP143 Native P2SH-P2WSH example. See also `sighash::tests::bip143_p2wsh_nested_in_p2sh`.
//
// This example is a P2SH-P2WSH 6-of-6 multisig witness program signed with 6 different SIGHASH types.
//
// FIXME: This function only works if we create a new cache before each signing - that's is a bug!
#[test]
fn bip143_p2wsh_nested_in_p2sh() {
    let secp = Secp256k1::new();
    let unsigned_tx = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000";

    let tx_bytes = Vec::from_hex(unsigned_tx).unwrap();
    let mut tx: Transaction = consensus::deserialize(&tx_bytes).unwrap();

    // Sanity checks.
    assert_eq!(tx.version, 1);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    //   nVersion:  01000000
    //   txin:      01 36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e 01000000 00 ffffffff
    //   txout:     02 00e9a43500000000 1976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac
    //                 c0832f0500000000 1976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac
    //   nLockTime: 00000000

    let input_0 = consensus::serialize_hex(&tx.input[0]);
    assert_eq!(input_0, "36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff");
    let output_0 = consensus::serialize_hex(&tx.output[0]);
    assert_eq!(output_0, "00e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688ac");
    let output_1 = consensus::serialize_hex(&tx.output[1]);
    assert_eq!(output_1, "c0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac");
    let lock = consensus::serialize_hex(&tx.lock_time);
    assert_eq!(lock, "00000000");

    // The input comes from a P2SH-P2WSH 6-of-6 multisig witness program:
    //   scriptPubKey : a9149993a429037b5d912407a71c252019287b8d27a587, value: 9.87654321
    //   redeemScript : 0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54
    //   witnessScript: 56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae

    let witness_script = ScriptBuf::from_hex("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae").unwrap();
    let redeem_script = ScriptBuf::from_hex("0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54").unwrap();

    let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
    assert_eq!(serialize_script_pubkey(script_pubkey.as_script()), "a9149993a429037b5d912407a71c252019287b8d27a587");

    let value = 987_654_321;

    // hash preimage for ALL: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa03bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504436641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000001000000
    //   nVersion:     01000000
    //   hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    //   hashSequence: 3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc
    //   nLockTime:    00000000
    //   nHashType:    01000000
    // sigHash:      185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c
    // public key:   0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3
    // private key:  730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6
    // signature:    304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01

    let sk = "730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3");

    // cache.segwit_cache() values are tested with the same test vectors in `sighash::tests::bip143_p2wsh_nested_in_p2sh`
    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::All;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);

    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_0 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_0, ty), "304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01");

    // hash preimage for NONE: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000002000000
    //   nVersion:     01000000
    //   hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    //   hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  0000000000000000000000000000000000000000000000000000000000000000
    //   nLockTime:    00000000
    //   nHashType:    02000000
    // sigHash:        e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36
    // public key:     03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b
    // private key:    11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3
    // signature:      3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502

    let sk = "11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b");

    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::None;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_1 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_1, ty), "3044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502");

    // hash preimage for SINGLE: 0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000003000000
    //   nVersion:     01000000
    //   hashPrevouts: 74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0
    //   hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708
    //   nLockTime:    00000000
    //   nHashType:    03000000
    // sigHash:        1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea
    // public key:     034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a
    // private key:    77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661
    // signature:      3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403

    let sk = "77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a");

    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::Single;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_2 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_2, ty), "3044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403");

    // hash preimage for ALL|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000081000000
    //   nVersion:     01000000
    //   hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    //   hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc
    //   nLockTime:    00000000
    //   nHashType:    81000000
    // sigHash:        2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e
    // public key:     033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4
    // private key:    14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49
    // signature:      3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381

    let sk = "14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4");

    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::AllPlusAnyoneCanPay;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_3 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_3, ty), "3045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381");

    // hash preimage for NONE|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000082000000
    //   nVersion:     01000000
    //   hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    //   hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  0000000000000000000000000000000000000000000000000000000000000000
    //   nLockTime:    00000000
    //   nHashType:    82000000
    // sigHash:        781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a
    // public key:     03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16
    // private key:    fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323
    // signature:      3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882

    let sk = "fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16");

    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::NonePlusAnyoneCanPay;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_4 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_4, ty), "3045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a0882");

    // hash preimage for SINGLE|ANYONECANPAY: 010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56aeb168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000083000000
    //   nVersion:     01000000
    //   hashPrevouts: 0000000000000000000000000000000000000000000000000000000000000000
    //   hashSequence: 0000000000000000000000000000000000000000000000000000000000000000
    //   outpoint:     36641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000
    //   scriptCode:   cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
    //   amount:       b168de3a00000000
    //   nSequence:    ffffffff
    //   hashOutputs:  9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f708
    //   nLockTime:    00000000
    //   nHashType:    83000000
    // sigHash:        511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b
    // public key:     02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b
    // private key:    428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890
    // signature:      30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783

    let sk = "428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890";
    let secp_sk = secp256k1::SecretKey::from_str(sk).unwrap();
    let secp_pk = secp_sk.public_key(&secp);
    assert_eq!(secp_pk.to_string(), "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b");

    let mut cache = SighashCache::new(&tx);
    let ty = EcdsaSighashType::SinglePlusAnyoneCanPay;
    let script_code = bitcoin::bip143::ScriptCode::new_p2wsh(&witness_script);
    assert_eq!(consensus::serialize_hex(&script_code), "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae");

    let sighash = cache.segwit_signature_hash(0, &script_code, value, ty).unwrap();
    assert_eq!(consensus::serialize_hex(&sighash), "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b");

    let msg = Message::from_slice(sighash.as_ref()).unwrap();
    let sig_5 = secp.sign_ecdsa(&msg, &secp_sk);
    assert_eq!(serialize_sig(sig_5, ty), "30440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783");

    let mut witness = Witness::new();

    // ref: https://github.com/libbitcoin/libbitcoin-system/wiki/P2SH(P2WSH)-Transactions#p2shp2wsh-witness
    witness.push([]);           // Push empty chunk.
    witness.push_bitcoin_signature(&sig_0.serialize_der(), EcdsaSighashType::All);
    witness.push_bitcoin_signature(&sig_1.serialize_der(), EcdsaSighashType::None);
    witness.push_bitcoin_signature(&sig_2.serialize_der(), EcdsaSighashType::Single);
    witness.push_bitcoin_signature(&sig_3.serialize_der(), EcdsaSighashType::AllPlusAnyoneCanPay);
    witness.push_bitcoin_signature(&sig_4.serialize_der(), EcdsaSighashType::NonePlusAnyoneCanPay);
    witness.push_bitcoin_signature(&sig_5.serialize_der(), EcdsaSighashType::SinglePlusAnyoneCanPay);
    witness.push(witness_script.as_bytes());

    tx.input[0].witness = witness;
    tx.input[0].script_sig = ScriptBuf::p2sh_p2wsh_script_sig(&witness_script);

    // The serialized signed transaction is: 0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000
    let signed_tx = "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000";
    let tx_bytes = Vec::from_hex(signed_tx).unwrap();
    let want_signed_tx: Transaction = consensus::deserialize(&tx_bytes).unwrap();

    assert_eq!(tx, want_signed_tx);
}
