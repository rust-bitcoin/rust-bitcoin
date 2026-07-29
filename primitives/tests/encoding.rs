// SPDX-License-Identifier: CC0-1.0

//! Test the consensus encoding implementations for types in `primitives`.

#![cfg(feature = "alloc")]
#![cfg(feature = "hex")]

use bitcoin_primitives::merkle_tree::TxMerkleNode;
use bitcoin_primitives::transaction::{
    OutPoint, Transaction, TransactionDecoderError, TxIn, TxOut, Version,
};
use bitcoin_primitives::{
    absolute, Amount, Block, BlockHash, BlockHeader, BlockTime, BlockVersion, CompactTarget,
    ScriptPubKeyBuf, ScriptSigBuf, Sequence, Witness,
};
use encoding::{check_encode, Decode as _, Decoder as _};
use hex::hex;

const TC_TXID_BYTES: [u8; 32] = [
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
    8, 7, 6, 5, 4, 3, 2, 1,
];
const TC_VOUT_BYTES: [u8; 4] = [1, 0, 0, 0];
const TC_SCRIPT_BYTES: [u8; 3] = [1, 2, 3];
const TC_SEQ_MAX_BYTES: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const TC_LOCK_TIME_ZERO_BYTES: [u8; 4] = [0, 0, 0, 0];
const TC_ONE_SAT_BYTES: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const TC_SEGWIT_MARKER_AND_FLAG: [u8; 2] = [0, 1];
const TC_WITNESS_ELEM_LEN_AND_DATA: [u8; 4] = [3, 1, 2, 3];

macro_rules! concat_slices {
    ($($chunk:expr),*) => {
        {
            let mut result = Vec::new();
            $(result.extend_from_slice($chunk);)*
            result
        }
    }
}

fn tc_out_point() -> OutPoint {
    let s = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20:1";
    s.parse::<OutPoint>().unwrap()
}

fn tc_script_pubkey() -> ScriptPubKeyBuf { ScriptPubKeyBuf::from_bytes(TC_SCRIPT_BYTES.to_vec()) }

fn tc_script_sig() -> ScriptSigBuf { ScriptSigBuf::from_bytes(TC_SCRIPT_BYTES.to_vec()) }

fn tx_out() -> TxOut { TxOut { amount: Amount::ONE_SAT, script_pubkey: tc_script_pubkey() } }

fn segwit_tx_in() -> TxIn {
    let data = [&TC_SCRIPT_BYTES[..]];
    let witness = Witness::from_iter(data);
    TxIn {
        previous_output: tc_out_point(),
        script_sig: tc_script_sig(),
        sequence: Sequence::MAX,
        witness,
    }
}

#[test]
fn transaction_encode_decode_roundtrip() {
    // Create two different inputs to avoid duplicate input rejection
    let tx_in_1 = segwit_tx_in();
    let mut tx_in_2 = segwit_tx_in();
    tx_in_2.previous_output.vout = 2;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![tx_in_1, tx_in_2],
        outputs: vec![tx_out(), tx_out()],
    };

    let encoded = encoding::encode_to_vec(&tx);

    let mut decoder = Transaction::decoder();
    let mut slice = encoded.as_slice();
    decoder.push_bytes(&mut slice).unwrap();
    let decoded = decoder.end().unwrap();

    assert_eq!(tx, decoded);
}

#[test]
fn encode_out_point() {
    let out_point = tc_out_point();
    check_encode(&out_point, &concat_slices!(&TC_TXID_BYTES, &TC_VOUT_BYTES));
}

#[test]
fn encode_tx_out() {
    let out = tx_out();
    check_encode(&out, &concat_slices!(&TC_ONE_SAT_BYTES, &[3u8], &TC_SCRIPT_BYTES));
}

#[test]
fn encode_tx_in() {
    let txin = segwit_tx_in();
    check_encode(
        &txin,
        &concat_slices!(
            &TC_TXID_BYTES,
            &TC_VOUT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &TC_SEQ_MAX_BYTES
        ),
    );
}

#[test]
fn encode_segwit_transaction() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![segwit_tx_in()],
        outputs: vec![tx_out()],
    };

    check_encode(
        &tx,
        &concat_slices!(
            &[2u8, 0, 0, 0],
            &TC_SEGWIT_MARKER_AND_FLAG,
            &[1u8],
            &TC_TXID_BYTES,
            &TC_VOUT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &TC_SEQ_MAX_BYTES,
            &[1u8],
            &TC_ONE_SAT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &[1u8],
            &TC_WITNESS_ELEM_LEN_AND_DATA,
            &TC_LOCK_TIME_ZERO_BYTES
        ),
    );
}

#[test]
fn encode_non_segwit_transaction() {
    let mut tx_in = segwit_tx_in();
    tx_in.witness = Witness::default();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![tx_in],
        outputs: vec![tx_out()],
    };

    check_encode(
        &tx,
        &concat_slices!(
            &[2u8, 0, 0, 0],
            &[1u8],
            &TC_TXID_BYTES,
            &TC_VOUT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &TC_SEQ_MAX_BYTES,
            &[1u8],
            &TC_ONE_SAT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &TC_LOCK_TIME_ZERO_BYTES
        ),
    );
}

#[test]
fn encode_block() {
    let seconds: u32 = 1_653_195_600; // Arbitrary timestamp: May 22nd, 5am UTC.

    let header = BlockHeader {
        version: BlockVersion::TWO,
        prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0xcd; 32]),
        time: BlockTime::from(seconds),
        bits: CompactTarget::from_consensus(0xbeef),
        nonce: 0xcafe,
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        inputs: vec![segwit_tx_in()],
        outputs: vec![tx_out()],
    };

    let block = Block::new_unchecked(header, vec![tx]);
    check_encode(
        &block,
        &concat_slices!(
            // The block version.
            &[2u8, 0, 0, 0],
            // The previous block's blockhash.
            &[
                171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171,
                171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171
            ],
            &[
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205,
                205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205, 205
            ],
            // The block time.
            &[80, 195, 137, 98],
            // The target (bits).
            &[239, 190, 0, 0],
            // The nonce.
            &[254, 202, 0, 0],
            // The transaction list length prefix.
            &[1u8],
            // The transaction (same as tested above).
            &[2u8, 0, 0, 0],
            &TC_SEGWIT_MARKER_AND_FLAG,
            &[1u8],
            &TC_TXID_BYTES,
            &TC_VOUT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &TC_SEQ_MAX_BYTES,
            &[1u8],
            &TC_ONE_SAT_BYTES,
            &[3u8],
            &TC_SCRIPT_BYTES,
            &[1u8],
            &TC_WITNESS_ELEM_LEN_AND_DATA,
            &TC_LOCK_TIME_ZERO_BYTES
        ),
    );
}

#[test]
fn decode_segwit_transaction() {
    let tx_bytes = hex!(
        "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
        00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
        100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
        0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
        55d3bcb8627d085e94553e62f057dcc00000000"
    );
    let mut decoder = Transaction::decoder();
    let mut slice = tx_bytes.as_slice();
    decoder.push_bytes(&mut slice).unwrap();
    let tx = decoder.end().unwrap();

    // Attempt various truncations
    for i in [1, 10, 20, 50, 100, tx_bytes.len() / 2, tx_bytes.len()] {
        let mut decoder = Transaction::decoder();
        let mut slice = &tx_bytes[..tx_bytes.len() - i];
        // push_bytes will not fail because the data is not invalid, just truncated
        decoder.push_bytes(&mut slice).unwrap();
        // ...but end() will fail because we will be in some incomplete state
        decoder.end().unwrap_err();
    }

    // All these tests aren't really needed because if they fail, the hash check at the end
    // will also fail. But these will show you where the failure is so I'll leave them in.
    assert_eq!(tx.version, Version::TWO);
    assert_eq!(tx.inputs.len(), 1);
    // In particular this one is easy to get backward -- in bitcoin hashes are encoded
    // as little-endian 256-bit numbers rather than as data strings.
    assert_eq!(
        format!("{:x}", tx.inputs[0].previous_output.txid),
        "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859".to_string()
    );
    assert_eq!(tx.inputs[0].previous_output.vout, 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.lock_time, absolute::LockTime::ZERO);

    assert_eq!(
        format!("{:x}", tx.compute_txid()),
        "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206".to_string()
    );
    assert_eq!(
        format!("{:x}", tx.compute_wtxid()),
        "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5".to_string()
    );
}

#[test]
fn decode_nonsegwit_transaction() {
    let tx_bytes = hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000");

    let mut decoder = Transaction::decoder();
    let mut slice = tx_bytes.as_slice();
    decoder.push_bytes(&mut slice).unwrap();
    let tx = decoder.end().unwrap();

    // All these tests aren't really needed because if they fail, the hash check at the end
    // will also fail. But these will show you where the failure is so I'll leave them in.
    assert_eq!(tx.version, Version::ONE);
    assert_eq!(tx.inputs.len(), 1);
    // In particular this one is easy to get backward -- in bitcoin hashes are encoded
    // as little-endian 256-bit numbers rather than as data strings.
    assert_eq!(
        format!("{:x}", tx.inputs[0].previous_output.txid),
        "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
    );
    assert_eq!(tx.inputs[0].previous_output.vout, 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.lock_time, absolute::LockTime::ZERO);

    assert_eq!(
        format!("{:x}", tx.compute_txid()),
        "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
    );
    assert_eq!(
        format!("{:x}", tx.compute_wtxid()),
        "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
    );
}

#[test]
fn decode_segwit_without_witnesses_errors() {
    // A SegWit-serialized transaction with 1 input but no witnesses for any input.
    let tx_bytes = hex!(
        "02000000\
         0001\
         01\
         0000000000000000000000000000000000000000000000000000000000000000\
         00000000\
         00\
         ffffffff\
         01\
         0100000000000000\
         00\
         00\
         00000000"
    );

    let mut slice = tx_bytes.as_slice();
    let err = Transaction::decoder()
        .push_bytes(&mut slice)
        .expect_err("segwit tx with no witnesses should error");

    assert!(matches!(err, TransactionDecoderError { .. }));
}

#[test]
fn decode_zero_inputs() {
    // Test transaction with no inputs (but with one output to satisfy validation).
    let block: u32 = 741_521;
    let original_tx = Transaction {
        version: Version::ONE,
        lock_time: absolute::LockTime::from_height(block).expect("valid height"),
        inputs: vec![],
        outputs: vec![TxOut { amount: Amount::ONE_SAT, script_pubkey: ScriptPubKeyBuf::new() }],
    };

    let encoded = encoding::encode_to_vec(&original_tx);
    let decoded_tx = encoding::decode_from_slice(&encoded).unwrap();

    assert_eq!(original_tx, decoded_tx);
}
