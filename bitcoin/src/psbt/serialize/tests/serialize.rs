//! Test code for the `psbt::serialize` module.

#![allow(unused_imports)] // FIXME: Too tired to work this out now.

use crate::psbt::serialize::{Deserialize as _, Serialize as _};
use crate::psbt::PsbtSighashType;
use crate::script::{ScriptBuf, ScriptBufExt as _};
use crate::taproot::{LeafVersion, TapNodeHash, TapTree, TaprootBuilder};

// Composes tree matching a given depth map, filled with dumb script leafs,
// each of which consists of a single push-int op code, with int value
// increased for each consecutive leaf.
pub fn compose_taproot_builder<'map>(
    opcode: u8,
    depth_map: impl IntoIterator<Item = &'map u8>,
) -> TaprootBuilder {
    let mut val = opcode;
    let mut builder = TaprootBuilder::new();
    for depth in depth_map {
        let script = ScriptBuf::from_hex(&format!("{:02x}", val)).unwrap();
        builder = builder.add_leaf(*depth, script).unwrap();
        let (new_val, _) = val.overflowing_add(1);
        val = new_val;
    }
    builder
}

#[test]
fn taptree_hidden() {
    let dummy_hash = TapNodeHash::from_byte_array([0x12; 32]);
    let mut builder = compose_taproot_builder(0x51, &[2, 2, 2]);
    builder = builder
        .add_leaf_with_ver(
            3,
            ScriptBuf::from_hex("b9").unwrap(),
            LeafVersion::from_consensus(0xC2).unwrap(),
        )
        .unwrap();
    builder = builder.add_hidden_node(3, dummy_hash).unwrap();
    assert!(TapTree::try_from(builder).is_err());
}

#[test]
fn taptree_roundtrip() {
    let mut builder = compose_taproot_builder(0x51, &[2, 2, 2, 3]);
    builder = builder
        .add_leaf_with_ver(
            3,
            ScriptBuf::from_hex("b9").unwrap(),
            LeafVersion::from_consensus(0xC2).unwrap(),
        )
        .unwrap();
    let tree = TapTree::try_from(builder).unwrap();
    let tree_prime = TapTree::deserialize(&tree.serialize()).unwrap();
    assert_eq!(tree, tree_prime);
}

#[test]
fn can_deserialize_non_standard_psbt_sighash_type() {
    let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
    let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
    assert!(sighash.is_ok())
}
