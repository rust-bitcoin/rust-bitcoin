// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "compat")]

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{
    block, compat, opcodes, script, transaction, BlockHash, CompactTarget, OutPoint, Script,
    ScriptBuf, ScriptHash, Sequence, TxIn, TxMerkleNode, Txid, WScriptHash, Witness,
    WitnessCommitment, WitnessMerkleNode, WitnessVersion, Wtxid,
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
