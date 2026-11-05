// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "compat")]

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute, block, compat, opcodes, script, transaction, Amount, Block, BlockHash, CompactTarget,
    Network, OutPoint, Script, ScriptBuf, ScriptHash, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, WScriptHash, Witness, WitnessCommitment, WitnessMerkleNode, WitnessVersion, Wtxid,
};
use bitcoin_primitives_stable::encoding::encode_to_vec;

#[test]
fn hashes() {
    macro_rules! check {
        ($ty:ty, $stable:ty, $len:expr) => {
            let bytes = core::array::from_fn::<_, $len, _>(|i| i as u8);
            let unstable = <$ty>::from_byte_array(bytes);
            let stable = unstable.to_stable();
            assert_eq!(stable.to_byte_array(), bytes);
            assert_eq!(<$ty>::from_stable(stable), unstable);
            let stable = <$stable>::from_byte_array(bytes);
            assert_eq!(<$ty>::from_stable(stable).to_stable(), stable);
        };
    }

    check!(BlockHash, compat::BlockHash, 32);
    check!(Txid, compat::Txid, 32);
    check!(Wtxid, compat::Wtxid, 32);
    check!(TxMerkleNode, compat::merkle_tree::TxMerkleNode, 32);
    check!(WitnessMerkleNode, compat::merkle_tree::WitnessMerkleNode, 32);
    check!(WitnessCommitment, compat::WitnessCommitment, 32);
    check!(ScriptHash, compat::script::ScriptHash, 20);
    check!(WScriptHash, compat::script::WScriptHash, 32);
}

#[test]
fn versions() {
    for version in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
        let unstable = transaction::Version(version);
        let stable = unstable.to_stable();
        assert_eq!(stable.to_u32().to_le_bytes(), version.to_le_bytes());
        assert_eq!(transaction::Version::from_stable(stable), unstable);

        let unstable = block::Version::from_consensus(version);
        let stable = unstable.to_stable();
        assert_eq!(stable.to_consensus(), version);
        assert_eq!(block::Version::from_stable(stable), unstable);
    }

    for version in 0..=16 {
        let unstable = WitnessVersion::try_from(version).unwrap();
        let stable = unstable.to_stable();
        assert_eq!(stable.to_num(), version);
        assert_eq!(WitnessVersion::from_stable(stable), unstable);
    }
}

#[test]
fn opcodes_and_outpoints() {
    for byte in 0..=255 {
        let unstable = opcodes::Opcode::from(byte);
        let stable = unstable.to_stable();
        assert_eq!(stable.to_u8(), byte);
        assert_eq!(opcodes::Opcode::from_stable(stable), unstable);
    }

    for vout in [0, 1, u32::MAX] {
        let unstable = OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout };
        let stable = unstable.to_stable();
        assert_eq!(stable.vout, vout);
        assert_eq!(stable.txid.to_byte_array(), [0x42; 32]);
        assert_eq!(OutPoint::from_stable(stable), unstable);
    }
    assert_eq!(OutPoint::null().to_stable(), compat::OutPoint::COINBASE_PREVOUT);
}

#[test]
fn scripts() {
    macro_rules! check {
        ($tag:ty) => {
            for bytes in [vec![], vec![0x51], vec![0x4c], vec![0; 10_001]] {
                let unstable = ScriptBuf::from_bytes(bytes.clone());
                let stable = unstable.as_script().to_stable::<$tag>();
                assert_eq!(stable.as_bytes(), bytes);
                assert_eq!(stable.as_bytes().as_ptr(), unstable.as_bytes().as_ptr());
                assert_eq!(Script::from_stable(stable), unstable.as_script());

                let ptr = unstable.as_bytes().as_ptr();
                let stable = unstable.to_stable::<$tag>();
                assert_eq!(stable.as_bytes(), bytes);
                assert_eq!(stable.as_bytes().as_ptr(), ptr);
                let unstable = ScriptBuf::from_stable(stable);
                assert_eq!(unstable.as_bytes(), bytes);
                assert_eq!(unstable.as_bytes().as_ptr(), ptr);
            }
        };
    }

    check!(compat::script::RedeemScriptTag);
    check!(compat::script::ScriptPubKeyTag);
    check!(compat::script::ScriptSigTag);
    check!(compat::script::SignetBlockScriptTag);
    check!(compat::script::TapScriptTag);
    check!(compat::script::WitnessScriptTag);
    check!(compat::script::ScriptCodeTag);
}

#[test]
fn pushes() {
    for bytes in [vec![], vec![0x51], vec![0; 521]] {
        let unstable = script::PushBytesBuf::try_from(bytes.clone()).unwrap();
        let stable = unstable.as_push_bytes().to_stable();
        assert_eq!(stable.as_bytes(), bytes);
        assert_eq!(stable.as_bytes().as_ptr(), unstable.as_bytes().as_ptr());
        assert_eq!(script::PushBytes::from_stable(stable), unstable.as_push_bytes());

        let ptr = unstable.as_bytes().as_ptr();
        let stable = unstable.to_stable();
        assert_eq!(stable.as_bytes(), bytes);
        assert_eq!(stable.as_bytes().as_ptr(), ptr);
        let unstable = script::PushBytesBuf::from_stable(stable);
        assert_eq!(unstable.as_bytes(), bytes);
        assert_eq!(unstable.as_bytes().as_ptr(), ptr);
    }
}

#[test]
fn witnesses() {
    for elements in [vec![], vec![vec![]], vec![vec![1, 2], vec![], vec![3; 253], vec![4; 65_536]]]
    {
        let unstable = Witness::from_slice(&elements);
        let stable = unstable.clone().to_stable();
        assert_eq!(stable.to_vec(), elements);
        assert_eq!(stable.size(), unstable.size());
        assert_eq!(Witness::from_stable(stable), unstable);
    }
}

#[test]
fn units_reexports() {
    let _: compat::block::BlockHeight = compat::BlockHeight::from_u32(1);
    let _: compat::block::BlockMtp = compat::BlockMtp::from_u32(500_000_000);
    let _: compat::block::BlockHeightInterval = compat::BlockHeightInterval::from_u32(1);
    let _: compat::block::BlockMtpInterval = compat::BlockMtpInterval::from_u32(1);
}

#[test]
fn inputs() {
    for sequence in [0, 1, 0x0040_0000, 0x8000_0000, u32::MAX] {
        let unstable = TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout: 7 },
            script_sig: ScriptBuf::from_bytes(vec![0x4c]),
            sequence: Sequence(sequence),
            witness: Witness::from_slice(&[vec![], vec![0x51; 253]]),
        };
        let stable = unstable.clone().to_stable();
        assert_eq!(encode_to_vec(&stable), serialize(&unstable));
        assert_eq!(TxIn::from_stable(stable), unstable);
    }
    let unstable = TxIn::default();
    assert_eq!(TxIn::from_stable(unstable.clone().to_stable()), unstable);
}

#[test]
fn headers() {
    for time in [0, 499_999_999, 500_000_000, u32::MAX] {
        let unstable = block::Header {
            version: block::Version::from_consensus(i32::MIN),
            prev_blockhash: BlockHash::from_byte_array([0x42; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x24; 32]),
            time,
            bits: CompactTarget::from_consensus(u32::MAX),
            nonce: u32::MAX,
        };
        let stable = unstable.to_stable();
        assert_eq!(encode_to_vec(&stable), serialize(&unstable));
        assert_eq!(stable.block_hash().to_byte_array(), unstable.block_hash().to_byte_array());
        assert_eq!(block::Header::from_stable(stable), unstable);
    }
}

fn transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(500_000_000),
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout: 7 },
                script_sig: ScriptBuf::from_bytes(vec![0x4c]),
                sequence: Sequence(0x0040_0001),
                witness: Witness::from_slice(&[vec![], vec![0x51; 253]]),
            },
            TxIn::default(),
        ],
        output: vec![
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() },
            TxOut {
                value: Amount::from_sat(compat::Amount::MAX_MONEY.to_sat()),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x51, 0xff]),
            },
        ],
    }
}

#[test]
fn outputs() {
    for sat in [0, 1, compat::Amount::MAX_MONEY.to_sat()] {
        let unstable = TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let ptr = unstable.script_pubkey.as_bytes().as_ptr();
        let stable = unstable.clone().to_stable().unwrap();
        assert_eq!(stable.amount.to_sat(), sat);
        assert_eq!(encode_to_vec(&stable), serialize(&unstable));
        assert_eq!(TxOut::from_stable(stable), unstable);
        let stable = unstable.to_stable().unwrap();
        assert_eq!(stable.script_pubkey.as_bytes().as_ptr(), ptr);
    }
}

#[test]
fn output_errors_preserve_input() {
    for sat in [compat::Amount::MAX_MONEY.to_sat() + 1, u64::MAX] {
        let unstable = TxOut {
            value: Amount::from_sat(sat),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let expected = unstable.clone();
        let ptr = unstable.script_pubkey.as_bytes().as_ptr();
        let error = unstable.to_stable().unwrap_err();
        assert_eq!(error.input(), &expected);
        assert_eq!(error.location(), None);
        assert_eq!(error.input().script_pubkey.as_bytes().as_ptr(), ptr);
        let original = error.into_input();
        assert_eq!(original, expected);
    }
    assert!(TxOut::NULL.to_stable().is_err());
}

#[test]
fn transactions() {
    for version in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
        for lock_time in [0, 499_999_999, 500_000_000, u32::MAX] {
            let mut unstable = transaction();
            unstable.version = transaction::Version(version);
            unstable.lock_time = absolute::LockTime::from_consensus(lock_time);
            let stable = unstable.clone().to_stable().unwrap();
            assert_eq!(encode_to_vec(&stable), serialize(&unstable));
            assert_eq!(
                stable.compute_txid().to_byte_array(),
                unstable.compute_txid().to_byte_array()
            );
            assert_eq!(
                stable.compute_wtxid().to_byte_array(),
                unstable.compute_wtxid().to_byte_array()
            );
            assert_eq!(Transaction::from_stable(stable), unstable);
        }
    }

    let mut unstable = transaction();
    unstable.input.clear();
    unstable.output.clear();
    let stable = unstable.clone().to_stable().unwrap();
    assert_eq!(encode_to_vec(&stable), serialize(&unstable));
    assert_eq!(Transaction::from_stable(stable), unstable);

    let mut unstable = transaction();
    for input in &mut unstable.input {
        input.witness.clear();
    }
    unstable.output.push(unstable.output[1].clone());
    let stable = unstable.clone().to_stable().unwrap();
    assert_eq!(encode_to_vec(&stable), serialize(&unstable));
    assert_eq!(Transaction::from_stable(stable), unstable);
}

#[test]
fn transaction_errors_preserve_input() {
    for index in 0..2 {
        let mut unstable = transaction();
        unstable.output[index].value = Amount::from_sat(compat::Amount::MAX_MONEY.to_sat() + 1);
        let expected = unstable.clone();
        let inputs_ptr = unstable.input.as_ptr();
        let outputs_ptr = unstable.output.as_ptr();
        let witness_ptr = unstable.input[0].witness.iter().nth(1).unwrap().as_ptr();
        let error = unstable.to_stable().unwrap_err();
        assert_eq!(error.input(), &expected);
        assert_eq!(
            error.location(),
            Some(compat::AmountConversionLocation::TransactionOutput { output_index: index })
        );
        assert!(error.to_string().contains(&format!("output at index {index}")));
        let original = error.into_input();
        assert_eq!(serialize(&original), serialize(&expected));
        assert_eq!(original.input.as_ptr(), inputs_ptr);
        assert_eq!(original.output.as_ptr(), outputs_ptr);
        assert_eq!(original.input[0].witness.iter().nth(1).unwrap().as_ptr(), witness_ptr);
    }
}

#[test]
fn blocks() {
    for network in [Network::Bitcoin, Network::Testnet, Network::Signet, Network::Regtest] {
        let unstable = bitcoin::constants::genesis_block(network);
        let stable: compat::Block<compat::BlockUnchecked> = unstable.clone().to_stable().unwrap();
        assert_eq!(encode_to_vec(&stable), serialize(&unstable));
        assert_eq!(stable.block_hash().to_byte_array(), unstable.block_hash().to_byte_array());
        assert_eq!(Block::from_stable(stable.clone()), unstable);
        assert!(stable.validate().is_ok());
    }

    let mut unstable = bitcoin::constants::genesis_block(Network::Bitcoin);
    unstable.txdata = vec![transaction()];
    let stable = unstable.clone().to_stable().unwrap();
    assert_eq!(encode_to_vec(&stable), serialize(&unstable));
    assert_eq!(Block::from_stable(stable.clone()), unstable);
    assert!(stable.validate().is_err());

    unstable.txdata.clear();
    let stable = unstable.clone().to_stable().unwrap();
    assert_eq!(encode_to_vec(&stable), serialize(&unstable));
    assert_eq!(Block::from_stable(stable), unstable);
}

#[test]
fn block_errors_preserve_input() {
    for index in 0..2 {
        let mut unstable = bitcoin::constants::genesis_block(Network::Bitcoin);
        unstable.txdata = vec![transaction(), transaction()];
        unstable.txdata[index].output[1].value = Amount::from_sat(u64::MAX);
        let expected = unstable.clone();
        let transactions_ptr = unstable.txdata.as_ptr();
        let outputs_ptr = unstable.txdata[index].output.as_ptr();
        let error = unstable.to_stable().unwrap_err();
        assert_eq!(error.input(), &expected);
        assert_eq!(
            error.location(),
            Some(compat::AmountConversionLocation::BlockTransactionOutput {
                transaction_index: index,
                output_index: 1,
            })
        );
        assert!(error
            .to_string()
            .contains(&format!("transaction index {index} and output index 1")));
        let original = error.into_input();
        assert_eq!(serialize(&original), serialize(&expected));
        assert_eq!(original.txdata.as_ptr(), transactions_ptr);
        assert_eq!(original.txdata[index].output.as_ptr(), outputs_ptr);
    }
}

#[test]
fn conversion_error_display() {
    let error = TxOut::NULL.to_stable().unwrap_err();
    assert!(error.to_string().contains("cannot convert to stable type"));
    assert_eq!(error.out_of_range_error(), &Amount::from_sat(u64::MAX).to_stable().unwrap_err());
    #[cfg(feature = "std")]
    {
        use std::error::Error;

        assert_eq!(
            error.source().unwrap().to_string(),
            Amount::from_sat(u64::MAX).to_stable().unwrap_err().to_string()
        );
    }
}
