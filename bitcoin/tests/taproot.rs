//! Tests for taproot types. Data lives in `tests/data`, which is excluded when publishing.

use bitcoin::ext::*;
use bitcoin::key::TapTweak as _;
use bitcoin::taproot::{
    ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash, TaprootBuilder,
};
use bitcoin::{Address, KnownHrp, ScriptPubKeyBuf, TapScriptBuf, XOnlyPublicKey};

#[test]
fn bip_341_tests() {
    fn process_script_trees(
        v: &serde_json::Value,
        mut builder: TaprootBuilder,
        leaves: &mut Vec<(TapScriptBuf, LeafVersion)>,
        depth: u8,
    ) -> TaprootBuilder {
        if v.is_null() {
            // nothing to push
        } else if v.is_array() {
            for leaf in v.as_array().unwrap() {
                builder = process_script_trees(leaf, builder, leaves, depth + 1);
            }
        } else {
            let script =
                TapScriptBuf::from_hex_no_length_prefix(v["script"].as_str().unwrap()).unwrap();
            let ver =
                LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
            leaves.push((script.clone(), ver));
            builder = builder.add_leaf_with_ver(depth, script, ver).unwrap();
        }
        builder
    }

    let data = bip_341_read_json();
    // Check the version of data
    assert!(data["version"] == 1);

    for arr in data["scriptPubKey"].as_array().unwrap() {
        let internal_key =
            arr["given"]["internalPubkey"].as_str().unwrap().parse::<XOnlyPublicKey>().unwrap();
        // process the tree
        let script_tree = &arr["given"]["scriptTree"];
        let mut merkle_root = None;
        if script_tree.is_null() {
            assert!(arr["intermediary"]["merkleRoot"].is_null());
        } else {
            merkle_root = Some(
                arr["intermediary"]["merkleRoot"].as_str().unwrap().parse::<TapNodeHash>().unwrap(),
            );
            let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
            let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
            let mut builder = TaprootBuilder::new();
            let mut leaves = vec![];
            builder = process_script_trees(script_tree, builder, &mut leaves, 0);
            let spend_info = builder.finalize(internal_key).unwrap();
            for (i, script_ver) in leaves.iter().enumerate() {
                let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                let expected_ctrl_blk =
                    ControlBlock::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap();

                let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                assert_eq!(leaf_hash.to_string(), expected_leaf_hash);
                assert_eq!(ctrl_blk, expected_ctrl_blk);
            }
        }
        let expected_output_key = arr["intermediary"]["tweakedPubkey"]
            .as_str()
            .unwrap()
            .parse::<XOnlyPublicKey>()
            .unwrap();
        let expected_tweak =
            arr["intermediary"]["tweak"].as_str().unwrap().parse::<TapTweakHash>().unwrap();
        let expected_spk = ScriptPubKeyBuf::from_hex_no_length_prefix(
            arr["expected"]["scriptPubKey"].as_str().unwrap(),
        )
        .unwrap();
        let expected_addr = arr["expected"]["bip350Address"]
            .as_str()
            .unwrap()
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();

        let tweak = TapTweakHash::from_key_and_merkle_root(internal_key, merkle_root);
        let output_key = internal_key.tap_tweak(merkle_root);
        let addr = Address::p2tr(internal_key, merkle_root, KnownHrp::Mainnet);
        let spk = addr.script_pubkey();

        // Compare just the key bytes, not the parity
        assert_eq!(
            expected_output_key.serialize().0,
            output_key.to_x_only_public_key().serialize().0
        );
        assert_eq!(expected_tweak, tweak);
        assert_eq!(expected_addr, addr);
        assert_eq!(expected_spk, spk);
    }
}

fn bip_341_read_json() -> serde_json::Value {
    let json_str = include_str!("data/bip341_tests.json");
    serde_json::from_str(json_str).expect("JSON was not well-formatted")
}
