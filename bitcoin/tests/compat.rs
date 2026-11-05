// SPDX-License-Identifier: CC0-1.0

//! Tests conversion to and from the stable types provided by the `compat` layer.

#![cfg(feature = "compat")]

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_DUP, OP_EQUAL, OP_EQUALVERIFY};
use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytes, PushBytesBuf};
use bitcoin::{
    block, compat, transaction, BlockHash, CompactTarget, OutPoint, Script, ScriptBuf, ScriptHash,
    Sequence, TxIn, TxMerkleNode, Txid, WScriptHash, Witness, WitnessCommitment, WitnessMerkleNode,
    WitnessVersion, Wtxid,
};

#[test]
fn hash_types() {
    macro_rules! check {
        ($($ty:ident, $stable:ty, $len:literal);* $(;)?) => {
            $(
                let bytes: [u8; $len] = core::array::from_fn(|i| i as u8);
                let unstable = $ty::from_byte_array(bytes);

                let stable: $stable = unstable.to_stable();
                assert_eq!(stable.to_byte_array(), bytes);
                assert_eq!($ty::from_stable(stable), unstable);
            )*
        };
    }

    check! {
        BlockHash, compat::BlockHash, 32;
        TxMerkleNode, compat::merkle_tree::TxMerkleNode, 32;
        WitnessMerkleNode, compat::merkle_tree::WitnessMerkleNode, 32;
        WitnessCommitment, compat::WitnessCommitment, 32;
        Txid, compat::Txid, 32;
        Wtxid, compat::Wtxid, 32;
        ScriptHash, compat::script::ScriptHash, 20;
        WScriptHash, compat::script::WScriptHash, 32;
    }
}

#[test]
fn block_version() {
    for version in [i32::MIN, -1, 0, 1, 0x2000_0000, i32::MAX] {
        let unstable = block::Version::from_consensus(version);

        let stable = unstable.to_stable();
        assert_eq!(stable.to_consensus(), version);
        assert_eq!(block::Version::from_stable(stable), unstable);
    }
}

#[test]
fn transaction_version() {
    assert_eq!(transaction::Version::ONE.to_stable(), compat::TransactionVersion::ONE);
    assert_eq!(transaction::Version::TWO.to_stable(), compat::TransactionVersion::TWO);

    // Stable versions are unsigned, conversion preserves the consensus encoding.
    for version in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
        let unstable = transaction::Version(version);

        let stable = unstable.to_stable();
        assert_eq!(stable.to_u32().to_le_bytes(), version.to_le_bytes());
        assert_eq!(transaction::Version::from_stable(stable), unstable);
    }
}

#[test]
fn witness_version() {
    for version in 0..=16 {
        let unstable = WitnessVersion::try_from(version).unwrap();

        let stable = unstable.to_stable();
        assert_eq!(stable.to_num(), version);
        assert_eq!(WitnessVersion::from_stable(stable), unstable);
    }
}

#[test]
fn opcode() {
    for byte in 0..=u8::MAX {
        let unstable = Opcode::from(byte);

        let stable = unstable.to_stable();
        assert_eq!(stable.to_u8(), byte);
        assert_eq!(Opcode::from_stable(stable), unstable);
    }
}

#[test]
fn script() {
    let unstable = ScriptBuf::from_bytes(vec![0x51, 0x4c, 0xff]);

    let stable: &compat::ScriptPubKey = unstable.as_script().to_stable();
    assert_eq!(stable.as_bytes(), unstable.as_bytes());
    assert_eq!(Script::from_stable(stable), unstable.as_script());

    // The same script can be converted to a stable script with any tag.
    let stable: compat::ScriptPubKeyBuf = unstable.clone().to_stable();
    assert_eq!(stable.as_bytes(), unstable.as_bytes());
    assert_eq!(ScriptBuf::from_stable(stable), unstable);

    let stable: compat::WitnessScriptBuf = unstable.clone().to_stable();
    assert_eq!(stable.as_bytes(), unstable.as_bytes());
    assert_eq!(ScriptBuf::from_stable(stable), unstable);
}

#[test]
fn script_builder() {
    let unstable = Builder::new().push_opcode(OP_DUP).push_opcode(OP_EQUAL);

    let stable: compat::script::Builder<compat::script::ScriptPubKeyTag> =
        unstable.clone().to_stable();
    assert_eq!(stable.as_script().as_bytes(), unstable.as_bytes());

    let unstable = Builder::from_stable(stable);
    assert_eq!(unstable.as_bytes(), [OP_DUP.to_u8(), OP_EQUAL.to_u8()]);
    // The pre-1.0 builder tracks the last opcode, check it survives the conversion.
    assert_eq!(unstable.push_verify().as_bytes(), [OP_DUP.to_u8(), OP_EQUALVERIFY.to_u8()]);
}

#[test]
fn push_bytes() {
    for bytes in [vec![], vec![0x51], vec![0xab; 521]] {
        let unstable = PushBytesBuf::try_from(bytes.clone()).unwrap();

        let stable = unstable.as_push_bytes().to_stable();
        assert_eq!(stable.as_bytes(), bytes);
        assert_eq!(PushBytes::from_stable(stable), unstable.as_push_bytes());

        let stable = unstable.clone().to_stable();
        assert_eq!(stable.as_bytes(), bytes);
        assert_eq!(PushBytesBuf::from_stable(stable), unstable);
    }
}

#[test]
fn witness() {
    let empty: Vec<Vec<u8>> = vec![];
    for elements in [empty, vec![vec![]], vec![vec![1, 2], vec![], vec![3; 253]]] {
        let unstable = Witness::from_slice(&elements);

        let stable = unstable.clone().to_stable();
        assert_eq!(stable.to_vec(), elements);
        assert_eq!(Witness::from_stable(stable), unstable);
    }
}

#[test]
fn out_point() {
    let unstable = OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout: 7 };

    let stable = unstable.to_stable();
    assert_eq!(stable.txid.to_byte_array(), [0x42; 32]);
    assert_eq!(stable.vout, 7);
    assert_eq!(OutPoint::from_stable(stable), unstable);

    assert_eq!(OutPoint::null().to_stable(), compat::OutPoint::COINBASE_PREVOUT);
}

#[test]
fn tx_in() {
    let unstable = TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([0x42; 32]), vout: 7 },
        script_sig: ScriptBuf::from_bytes(vec![0x51]),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::from_slice(&[vec![], vec![0xab; 72]]),
    };

    let stable = unstable.clone().to_stable();
    assert_eq!(stable.previous_output, unstable.previous_output.to_stable());
    assert_eq!(stable.script_sig.as_bytes(), unstable.script_sig.as_bytes());
    assert_eq!(stable.sequence, unstable.sequence.to_stable());
    assert_eq!(stable.witness, unstable.witness.clone().to_stable());
    assert_eq!(TxIn::from_stable(stable), unstable);
}

#[test]
fn block_header() {
    for time in [0, 1_231_006_505, u32::MAX] {
        let unstable = block::Header {
            version: block::Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array([0x42; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x24; 32]),
            time,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 2_083_236_893,
        };

        let stable = unstable.to_stable();
        // The block hash commits to the consensus encoding of every field.
        assert_eq!(stable.block_hash(), unstable.block_hash().to_stable());
        assert_eq!(block::Header::from_stable(stable), unstable);
    }
}
