// SPDX-License-Identifier: CC0-1.0

use core::str::FromStr;

use hex_lit::hex;

use super::*;
use crate::address::script_pubkey::{
    BuilderExt as _, ScriptBufExt as _, ScriptExt as _, ScriptExtPrivate as _,
};
use crate::consensus::encode::{deserialize, serialize};
use crate::crypto::key::{PublicKey, XOnlyPublicKey};
use crate::FeeRate;

#[test]
#[rustfmt::skip]
fn script() {
    let mut comp = vec![];
    let mut script = Builder::new();
    assert_eq!(script.as_bytes(), &comp[..]);

    // small ints
    script = script.push_int(1);  comp.push(81u8); assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_int(0);  comp.push(0u8);  assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_int(4);  comp.push(84u8); assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_int(-1); comp.push(79u8); assert_eq!(script.as_bytes(), &comp[..]);
    // forced scriptint
    script = script.push_int_non_minimal(4); comp.extend([1u8, 4].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
    // big ints
    script = script.push_int(17); comp.extend([1u8, 17].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_int(10000); comp.extend([2u8, 16, 39].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
    // notice the sign bit set here, hence the extra zero/128 at the end
    script = script.push_int(10000000); comp.extend([4u8, 128, 150, 152, 0].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_int(-10000000); comp.extend([4u8, 128, 150, 152, 128].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);

    // data
    script = script.push_slice(b"NRA4VR"); comp.extend([6u8, 78, 82, 65, 52, 86, 82].iter().cloned()); assert_eq!(script.as_bytes(), &comp[..]);

    // keys
    const KEYSTR1: &str = "21032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
    let key = PublicKey::from_str(&KEYSTR1[2..]).unwrap();
    script = script.push_key(key); comp.extend_from_slice(&hex!(KEYSTR1)); assert_eq!(script.as_bytes(), &comp[..]);
    const KEYSTR2: &str = "41042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
    let key = PublicKey::from_str(&KEYSTR2[2..]).unwrap();
    script = script.push_key(key); comp.extend_from_slice(&hex!(KEYSTR2)); assert_eq!(script.as_bytes(), &comp[..]);

    // opcodes
    script = script.push_opcode(OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script.as_bytes(), &comp[..]);
    script = script.push_opcode(OP_CHECKSIG); comp.push(0xACu8); assert_eq!(script.as_bytes(), &comp[..]);
}

#[test]
fn p2pk_pubkey_bytes_valid_key_and_valid_script_returns_expected_key() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let p2pk = Script::builder().push_key(key).push_opcode(OP_CHECKSIG).into_script();
    let actual = p2pk.p2pk_pubkey_bytes().unwrap();
    assert_eq!(actual.to_vec(), key.to_bytes());
}

#[test]
fn p2pk_pubkey_bytes_no_checksig_returns_none() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let no_checksig = Script::builder().push_key(key).into_script();
    assert_eq!(no_checksig.p2pk_pubkey_bytes(), None);
}

#[test]
fn p2pk_pubkey_bytes_emptry_script_returns_none() {
    let empty_script = Script::builder().into_script();
    assert!(empty_script.p2pk_pubkey_bytes().is_none());
}

#[test]
fn p2pk_pubkey_bytes_no_key_returns_none() {
    // scripts with no key should return None
    let no_push_bytes = Script::builder().push_opcode(OP_CHECKSIG).into_script();
    assert!(no_push_bytes.p2pk_pubkey_bytes().is_none());
}

#[test]
fn p2pk_pubkey_bytes_different_op_code_returns_none() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let different_op_code = Script::builder().push_key(key).push_opcode(OP_NOP).into_script();
    assert!(different_op_code.p2pk_pubkey_bytes().is_none());
}

#[test]
fn p2pk_pubkey_bytes_incorrect_key_size_returns_none() {
    // 63 byte key
    let malformed_key = b"21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1";
    let invalid_p2pk_script =
        Script::builder().push_slice(malformed_key).push_opcode(OP_CHECKSIG).into_script();
    assert!(invalid_p2pk_script.p2pk_pubkey_bytes().is_none());
}

#[test]
fn p2pk_pubkey_bytes_invalid_key_returns_some() {
    let malformed_key = b"21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1ux";
    let invalid_key_script =
        Script::builder().push_slice(malformed_key).push_opcode(OP_CHECKSIG).into_script();
    assert!(invalid_key_script.p2pk_pubkey_bytes().is_some());
}

#[test]
fn p2pk_pubkey_bytes_compressed_key_returns_expected_key() {
    let compressed_key_str = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
    let key = PublicKey::from_str(compressed_key_str).unwrap();
    let p2pk = Script::builder().push_key(key).push_opcode(OP_CHECKSIG).into_script();
    let actual = p2pk.p2pk_pubkey_bytes().unwrap();
    assert_eq!(actual.to_vec(), key.to_bytes());
}

#[test]
fn p2pk_public_key_valid_key_and_valid_script_returns_expected_key() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let p2pk = Script::builder().push_key(key).push_opcode(OP_CHECKSIG).into_script();
    let actual = p2pk.p2pk_public_key().unwrap();
    assert_eq!(actual, key);
}

#[test]
fn p2pk_public_key_no_checksig_returns_none() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let no_checksig = Script::builder().push_key(key).into_script();
    assert_eq!(no_checksig.p2pk_public_key(), None);
}

#[test]
fn p2pk_public_key_empty_script_returns_none() {
    let empty_script = Script::builder().into_script();
    assert!(empty_script.p2pk_public_key().is_none());
}

#[test]
fn p2pk_public_key_no_key_returns_none() {
    let no_push_bytes = Script::builder().push_opcode(OP_CHECKSIG).into_script();
    assert!(no_push_bytes.p2pk_public_key().is_none());
}

#[test]
fn p2pk_public_key_different_op_code_returns_none() {
    let key_str = "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
    let key = PublicKey::from_str(key_str).unwrap();
    let different_op_code = Script::builder().push_key(key).push_opcode(OP_NOP).into_script();
    assert!(different_op_code.p2pk_public_key().is_none());
}

#[test]
fn p2pk_public_key_incorrect_size_returns_none() {
    let malformed_key = b"21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1";
    let malformed_key_script =
        Script::builder().push_slice(malformed_key).push_opcode(OP_CHECKSIG).into_script();
    assert!(malformed_key_script.p2pk_public_key().is_none());
}

#[test]
fn p2pk_public_key_invalid_key_returns_none() {
    let malformed_key = b"21032e58afe51f9ed8ad3cc7897f634d881fdbe49816429ded8156bebd2ffd1ux";
    let invalid_key_script =
        Script::builder().push_slice(malformed_key).push_opcode(OP_CHECKSIG).into_script();
    assert!(invalid_key_script.p2pk_public_key().is_none());
}

#[test]
fn p2pk_public_key_compressed_key_returns_some() {
    let compressed_key_str = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
    let key = PublicKey::from_str(compressed_key_str).unwrap();
    let p2pk = Script::builder().push_key(key).push_opcode(OP_CHECKSIG).into_script();
    let actual = p2pk.p2pk_public_key().unwrap();
    assert_eq!(actual, key);
}

#[test]
fn script_x_only_key() {
    // Notice the "20" which prepends the keystr. That 20 is hexadecimal for "32". The Builder automatically adds the 32 opcode
    // to our script in order to give a heads up to the script compiler that it should add the next 32 bytes to the stack.
    // From: https://github.com/bitcoin-core/btcdeb/blob/e8c2750c4a4702768c52d15640ed03bf744d2601/doc/tapscript-example.md?plain=1#L43
    const KEYSTR: &str = "209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be";
    let x_only_key = XOnlyPublicKey::from_str(&KEYSTR[2..]).unwrap();
    let script = Builder::new().push_x_only_key(x_only_key);
    assert_eq!(script.into_bytes(), &hex!(KEYSTR) as &[u8]);
}

#[test]
fn script_builder() {
    // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
    let script = Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(hex!("16e1ae70ff0fa102905d4af297f6912bda6cce19"))
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    assert_eq!(script.to_hex_string(), "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac");
}

#[test]
fn script_generators() {
    let pubkey =
        PublicKey::from_str("0234e6a79c5359c613762d537e0e19d86c77c1666d8c9ab050f23acd198e97f93e")
            .unwrap();
    assert!(ScriptBuf::new_p2pk(pubkey).is_p2pk());

    let pubkey_hash = pubkey.pubkey_hash();
    assert!(ScriptBuf::new_p2pkh(pubkey_hash).is_p2pkh());

    let wpubkey_hash = pubkey.wpubkey_hash().unwrap();
    assert!(ScriptBuf::new_p2wpkh(wpubkey_hash).is_p2wpkh());

    let script = Builder::new().push_opcode(OP_NUMEQUAL).push_verify().into_script();
    let script_hash = script.script_hash().expect("script is less than 520 bytes");
    let p2sh = ScriptBuf::new_p2sh(script_hash);
    assert!(p2sh.is_p2sh());
    assert_eq!(script.to_p2sh().unwrap(), p2sh);

    let wscript_hash = script.wscript_hash().expect("script is less than 10,000 bytes");
    let p2wsh = ScriptBuf::new_p2wsh(wscript_hash);
    assert!(p2wsh.is_p2wsh());
    assert_eq!(script.to_p2wsh().unwrap(), p2wsh);

    // Test data are taken from the second output of
    // 2ccb3a1f745eb4eefcf29391460250adda5fab78aaddb902d25d3cd97d9d8e61 transaction
    let data = hex!("aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a");
    let op_return = ScriptBuf::new_op_return(data);
    assert!(op_return.is_op_return());
    assert_eq!(
        op_return.to_hex_string(),
        "6a24aa21a9ed20280f53f2d21663cac89e6bd2ad19edbabb048cda08e73ed19e9268d0afea2a"
    );
}

#[test]
fn script_builder_verify() {
    let simple = Builder::new().push_verify().into_script();
    assert_eq!(simple.to_hex_string(), "69");
    let simple2 = Builder::from(vec![]).push_verify().into_script();
    assert_eq!(simple2.to_hex_string(), "69");

    let nonverify = Builder::new().push_verify().push_verify().into_script();
    assert_eq!(nonverify.to_hex_string(), "6969");
    let nonverify2 = Builder::from(vec![0x69]).push_verify().into_script();
    assert_eq!(nonverify2.to_hex_string(), "6969");

    let equal = Builder::new().push_opcode(OP_EQUAL).push_verify().into_script();
    assert_eq!(equal.to_hex_string(), "88");
    let equal2 = Builder::from(vec![0x87]).push_verify().into_script();
    assert_eq!(equal2.to_hex_string(), "88");

    let numequal = Builder::new().push_opcode(OP_NUMEQUAL).push_verify().into_script();
    assert_eq!(numequal.to_hex_string(), "9d");
    let numequal2 = Builder::from(vec![0x9c]).push_verify().into_script();
    assert_eq!(numequal2.to_hex_string(), "9d");

    let checksig = Builder::new().push_opcode(OP_CHECKSIG).push_verify().into_script();
    assert_eq!(checksig.to_hex_string(), "ad");
    let checksig2 = Builder::from(vec![0xac]).push_verify().into_script();
    assert_eq!(checksig2.to_hex_string(), "ad");

    let checkmultisig = Builder::new().push_opcode(OP_CHECKMULTISIG).push_verify().into_script();
    assert_eq!(checkmultisig.to_hex_string(), "af");
    let checkmultisig2 = Builder::from(vec![0xae]).push_verify().into_script();
    assert_eq!(checkmultisig2.to_hex_string(), "af");

    let trick_slice = Builder::new()
        .push_slice([0xae]) // OP_CHECKMULTISIG
        .push_verify()
        .into_script();
    assert_eq!(trick_slice.to_hex_string(), "01ae69");
    let trick_slice2 = Builder::from(vec![0x01, 0xae]).push_verify().into_script();
    assert_eq!(trick_slice2.to_hex_string(), "01ae69");
}

#[test]
fn script_serialize() {
    let hex_script = hex!("6c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52");
    let script: Result<ScriptBuf, _> = deserialize(&hex_script);
    assert!(script.is_ok());
    assert_eq!(serialize(&script.unwrap()), &hex_script as &[u8]);
}

#[test]
fn scriptint_round_trip() {
    fn build_scriptint(n: i64) -> Vec<u8> {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, n);
        assert!(len <= 8);
        buf[..len].to_vec()
    }

    assert_eq!(build_scriptint(-1), vec![0x81]);
    assert_eq!(build_scriptint(255), vec![255, 0]);
    assert_eq!(build_scriptint(256), vec![0, 1]);
    assert_eq!(build_scriptint(257), vec![1, 1]);
    assert_eq!(build_scriptint(511), vec![255, 1]);
    let test_vectors = [
        10,
        100,
        255,
        256,
        1000,
        10000,
        25000,
        200000,
        5000000,
        1000000000,
        (1 << 31) - 1,
        -((1 << 31) - 1),
    ];
    for &i in test_vectors.iter() {
        assert_eq!(
            Ok(i),
            PushBytes::read_scriptint(
                <&PushBytes>::try_from(build_scriptint(i).as_slice()).unwrap()
            )
        );
        assert_eq!(
            Ok(-i),
            PushBytes::read_scriptint(
                <&PushBytes>::try_from(build_scriptint(-i).as_slice()).unwrap()
            )
        );
        assert_eq!(Ok(i), read_scriptint_non_minimal(&build_scriptint(i)));
        assert_eq!(Ok(-i), read_scriptint_non_minimal(&build_scriptint(-i)));
    }
    assert!(PushBytes::read_scriptint(
        <&PushBytes>::try_from(build_scriptint(1 << 31).as_slice()).unwrap()
    )
    .is_err());
    assert!(PushBytes::read_scriptint(
        <&PushBytes>::try_from(build_scriptint(-(1 << 31)).as_slice()).unwrap()
    )
    .is_err());
    assert!(read_scriptint_non_minimal(&build_scriptint(1 << 31)).is_err());
    assert!(read_scriptint_non_minimal(&build_scriptint(-(1 << 31))).is_err());
}

#[test]
fn non_minimal_scriptints() {
    assert_eq!(
        PushBytes::read_scriptint(<[_; 2] as AsRef<PushBytes>>::as_ref(&[0x80, 0x00])),
        Ok(0x80)
    );
    assert_eq!(
        PushBytes::read_scriptint(<[_; 2] as AsRef<PushBytes>>::as_ref(&[0xff, 0x00])),
        Ok(0xff)
    );
    assert_eq!(
        PushBytes::read_scriptint(<[_; 3] as AsRef<PushBytes>>::as_ref(&[0x8f, 0x00, 0x00])),
        Err(Error::NonMinimalPush)
    );
    assert_eq!(
        PushBytes::read_scriptint(<[_; 2] as AsRef<PushBytes>>::as_ref(&[0x7f, 0x00])),
        Err(Error::NonMinimalPush)
    );

    assert_eq!(read_scriptint_non_minimal(&[0x80, 0x00]), Ok(0x80));
    assert_eq!(read_scriptint_non_minimal(&[0xff, 0x00]), Ok(0xff));
    assert_eq!(read_scriptint_non_minimal(&[0x8f, 0x00, 0x00]), Ok(0x8f));
    assert_eq!(read_scriptint_non_minimal(&[0x7f, 0x00]), Ok(0x7f));
}

#[test]
fn script_hashes() {
    let script = ScriptBuf::from_hex("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").unwrap();
    assert_eq!(
        script.script_hash().unwrap().to_string(),
        "8292bcfbef1884f73c813dfe9c82fd7e814291ea"
    );
    assert_eq!(
        script.wscript_hash().unwrap().to_string(),
        "3e1525eb183ad4f9b3c5fa3175bdca2a52e947b135bbb90383bf9f6408e2c324"
    );
    assert_eq!(
        ScriptBuf::from_hex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac")
            .unwrap()
            .tapscript_leaf_hash()
            .to_string(),
        "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
    );
}

#[test]
fn provably_unspendable_test() {
    // p2pk
    assert!(!ScriptBuf::from_hex("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").unwrap().is_op_return());
    assert!(!ScriptBuf::from_hex("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").unwrap().is_op_return());
    // p2pkhash
    assert!(!ScriptBuf::from_hex("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac")
        .unwrap()
        .is_op_return());
    assert!(ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87")
        .unwrap()
        .is_op_return());
}

#[test]
fn op_return_test() {
    assert!(ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87")
        .unwrap()
        .is_op_return());
    assert!(!ScriptBuf::from_hex("76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac")
        .unwrap()
        .is_op_return());
    assert!(!ScriptBuf::from_hex("").unwrap().is_op_return());
}

#[test]
fn standard_op_return_test() {
    assert!(ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87")
        .unwrap()
        .is_standard_op_return());
    assert!(ScriptBuf::from_hex("6a48656c6c6f2c2074686973206973206d7920666972737420636f6e747269627574696f6e20746f207275737420626974636f696e2e20506c6561736520617070726f7665206d79205052206672656e")
        .unwrap()
        .is_standard_op_return());

    assert!(!ScriptBuf::from_hex("6a48656c6c6f2c2074686973206973206d7920666972737420636f6e747269627574696f6e20746f207275737420626974636f696e2e20506c6561736520617070726f7665206d79205052206672656e21")
        .unwrap()
        .is_standard_op_return());
}

#[test]
fn multisig() {
    // First multisig? 1-of-2
    // In block 164467, txid 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1
    assert!(
        ScriptBuf::from_hex("514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae")
            .unwrap()
            .is_multisig()
    );
    // 2-of-2
    assert!(
        ScriptBuf::from_hex("5221021c4ac2ecebc398e390e07f045aac5cc421f82f0739c1ce724d3d53964dc6537d21023a2e9155e0b62f76737605504819a2b4e5ce20653f6c397d7a178ae42ba702f452ae")
            .unwrap()
            .is_multisig()
    );

    // Extra opcode after OP_CHECKMULTISIG
    assert!(
        !ScriptBuf::from_hex("5221021c4ac2ecebc398e390e07f045aac5cc421f82f0739c1ce724d3d53964dc6537d21023a2e9155e0b62f76737605504819a2b4e5ce20653f6c397d7a178ae42ba702f452ae52")
            .unwrap()
            .is_multisig()
    );
    // Required sigs > num pubkeys
    assert!(
        !ScriptBuf::from_hex("5321021c4ac2ecebc398e390e07f045aac5cc421f82f0739c1ce724d3d53964dc6537d21023a2e9155e0b62f76737605504819a2b4e5ce20653f6c397d7a178ae42ba702f452ae")
            .unwrap()
            .is_multisig()
    );
    // Num pubkeys != pushnum
    assert!(
        !ScriptBuf::from_hex("5221021c4ac2ecebc398e390e07f045aac5cc421f82f0739c1ce724d3d53964dc6537d21023a2e9155e0b62f76737605504819a2b4e5ce20653f6c397d7a178ae42ba702f453ae")
            .unwrap()
            .is_multisig()
    );

    // Taproot hash from another test
    assert!(!ScriptBuf::from_hex(
        "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac"
    )
    .unwrap()
    .is_multisig());
    // OP_RETURN from another test
    assert!(!ScriptBuf::from_hex("6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87")
        .unwrap()
        .is_multisig());
}

#[test]
#[cfg(feature = "serde")]
fn script_json_serialize() {
    use serde_json;

    let original = ScriptBuf::from_hex("827651a0698faaa9a8a7a687").unwrap();
    let json = serde_json::to_value(&original).unwrap();
    assert_eq!(json, serde_json::Value::String("827651a0698faaa9a8a7a687".to_owned()));
    let des = serde_json::from_value::<ScriptBuf>(json).unwrap();
    assert_eq!(original, des);
}

#[test]
fn script_asm() {
    assert_eq!(
        ScriptBuf::from_hex("6363636363686868686800").unwrap().to_asm_string(),
        "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0"
    );
    assert_eq!(
        ScriptBuf::from_hex("6363636363686868686800").unwrap().to_asm_string(),
        "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0"
    );
    assert_eq!(ScriptBuf::from_hex("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac").unwrap().to_asm_string(),
               "OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG");
    // Elements Alpha peg-out transaction with some signatures removed for brevity. Mainly to test PUSHDATA1
    assert_eq!(ScriptBuf::from_hex("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").unwrap().to_asm_string(),
               "OP_0 OP_PUSHBYTES_71 304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401 OP_0 OP_PUSHDATA1 552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae");
    // Various weird scripts found in transaction 6d7ed9914625c73c0288694a6819196a27ef6c08f98e1270d975a8e65a3dc09a
    // which triggerred overflow bugs on 32-bit machines in script formatting in the past.
    assert_eq!(
        ScriptBuf::from_hex("01").unwrap().to_asm_string(),
        "OP_PUSHBYTES_1 <push past end>"
    );
    assert_eq!(
        ScriptBuf::from_hex("0201").unwrap().to_asm_string(),
        "OP_PUSHBYTES_2 <push past end>"
    );
    assert_eq!(ScriptBuf::from_hex("4c").unwrap().to_asm_string(), "<unexpected end>");
    assert_eq!(
        ScriptBuf::from_hex("4c0201").unwrap().to_asm_string(),
        "OP_PUSHDATA1 <push past end>"
    );
    assert_eq!(ScriptBuf::from_hex("4d").unwrap().to_asm_string(), "<unexpected end>");
    assert_eq!(
        ScriptBuf::from_hex("4dffff01").unwrap().to_asm_string(),
        "OP_PUSHDATA2 <push past end>"
    );
    assert_eq!(
        ScriptBuf::from_hex("4effffffff01").unwrap().to_asm_string(),
        "OP_PUSHDATA4 <push past end>"
    );
}

#[test]
fn script_buf_collect() {
    assert_eq!(&core::iter::empty::<Instruction<'_>>().collect::<ScriptBuf>(), Script::new());
    let script = ScriptBuf::from_hex("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").unwrap();
    assert_eq!(script.instructions().collect::<Result<ScriptBuf, _>>().unwrap(), script);
}

#[test]
fn script_p2sh_p2p2k_template() {
    // random outputs I picked out of the mempool
    assert!(ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac")
        .unwrap()
        .is_p2pkh());
    assert!(!ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac")
        .unwrap()
        .is_p2sh());
    assert!(!ScriptBuf::from_hex("76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ad")
        .unwrap()
        .is_p2pkh());
    assert!(!ScriptBuf::from_hex("").unwrap().is_p2pkh());
    assert!(ScriptBuf::from_hex("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87")
        .unwrap()
        .is_p2sh());
    assert!(!ScriptBuf::from_hex("a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87")
        .unwrap()
        .is_p2pkh());
    assert!(!ScriptBuf::from_hex("a314acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87")
        .unwrap()
        .is_p2sh());
}

#[test]
fn script_p2pk() {
    assert!(ScriptBuf::from_hex(
        "21021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51ac"
    )
    .unwrap()
    .is_p2pk());
    assert!(ScriptBuf::from_hex("410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac").unwrap().is_p2pk());
}

#[test]
fn p2sh_p2wsh_conversion() {
    // Test vectors taken from Core tests/data/script_tests.json
    // bare p2wsh
    let witness_script = ScriptBuf::from_hex("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac").unwrap();
    let expected_witout =
        ScriptBuf::from_hex("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64")
            .unwrap();
    assert!(witness_script.to_p2wsh().unwrap().is_p2wsh());
    assert_eq!(witness_script.to_p2wsh().unwrap(), expected_witout);

    // p2sh
    let redeem_script = ScriptBuf::from_hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap();
    let expected_p2shout =
        ScriptBuf::from_hex("a91491b24bf9f5288532960ac687abb035127b1d28a587").unwrap();
    assert!(redeem_script.to_p2sh().unwrap().is_p2sh());
    assert_eq!(redeem_script.to_p2sh().unwrap(), expected_p2shout);

    // p2sh-p2wsh
    let witness_script = ScriptBuf::from_hex("410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8ac").unwrap();
    let expected_witout =
        ScriptBuf::from_hex("0020b95237b48faaa69eb078e1170be3b5cbb3fddf16d0a991e14ad274f7b33a4f64")
            .unwrap();
    let expected_out =
        ScriptBuf::from_hex("a914f386c2ba255cc56d20cfa6ea8b062f8b5994551887").unwrap();
    assert!(witness_script.to_p2sh().unwrap().is_p2sh());
    assert_eq!(witness_script.to_p2wsh().unwrap(), expected_witout);
    assert_eq!(witness_script.to_p2wsh().unwrap().to_p2sh().unwrap(), expected_out);
}

macro_rules! unwrap_all {
    ($($var:ident),*) => {
        $(
            let $var = $var.unwrap();
        )*
    }
}

#[test]
fn test_iterator() {
    let zero = ScriptBuf::from_hex("00").unwrap();
    let zeropush = ScriptBuf::from_hex("0100").unwrap();

    let nonminimal = ScriptBuf::from_hex("4c0169b2").unwrap(); // PUSHDATA1 for no reason
    let minimal = ScriptBuf::from_hex("0169b2").unwrap(); // minimal
    let nonminimal_alt = ScriptBuf::from_hex("026900b2").unwrap(); // non-minimal number but minimal push (should be OK)

    let v_zero: Result<Vec<_>, Error> = zero.instruction_indices_minimal().collect();
    let v_zeropush: Result<Vec<_>, Error> = zeropush.instruction_indices_minimal().collect();

    let v_min: Result<Vec<_>, Error> = minimal.instruction_indices_minimal().collect();
    let v_nonmin: Result<Vec<_>, Error> = nonminimal.instruction_indices_minimal().collect();
    let v_nonmin_alt: Result<Vec<_>, Error> =
        nonminimal_alt.instruction_indices_minimal().collect();
    let slop_v_min: Result<Vec<_>, Error> = minimal.instruction_indices().collect();
    let slop_v_nonmin: Result<Vec<_>, Error> = nonminimal.instruction_indices().collect();
    let slop_v_nonmin_alt: Result<Vec<_>, Error> = nonminimal_alt.instruction_indices().collect();

    unwrap_all!(
        v_zero,
        v_zeropush,
        v_min,
        v_nonmin_alt,
        slop_v_min,
        slop_v_nonmin,
        slop_v_nonmin_alt
    );

    assert_eq!(v_zero, vec![(0, Instruction::PushBytes(PushBytes::empty()))]);
    assert_eq!(v_zeropush, vec![(0, Instruction::PushBytes([0].as_ref()))]);

    assert_eq!(
        v_min,
        vec![(0, Instruction::PushBytes([105].as_ref())), (2, Instruction::Op(opcodes::OP_NOP3))]
    );

    assert_eq!(v_nonmin.unwrap_err(), Error::NonMinimalPush);

    assert_eq!(
        v_nonmin_alt,
        vec![
            (0, Instruction::PushBytes([105, 0].as_ref())),
            (3, Instruction::Op(opcodes::OP_NOP3))
        ]
    );

    assert_eq!(v_min, slop_v_min);
    // indices must differ
    assert_ne!(v_min, slop_v_nonmin);
    // but the instructions must be equal
    for ((_, v_min_instr), (_, slop_v_nomin_instr)) in v_min.iter().zip(&slop_v_nonmin) {
        assert_eq!(v_min_instr, slop_v_nomin_instr);
    }
    assert_eq!(v_nonmin_alt, slop_v_nonmin_alt);
}

#[test]
fn script_ord() {
    let script_1 = Builder::new().push_slice([1, 2, 3, 4]).into_script();
    let script_2 = Builder::new().push_int(10).into_script();
    let script_3 = Builder::new().push_int(15).into_script();
    let script_4 = Builder::new().push_opcode(OP_RETURN).into_script();

    assert!(script_1 < script_2);
    assert!(script_2 < script_3);
    assert!(script_3 < script_4);

    assert!(script_1 <= script_1);
    assert!(script_1 >= script_1);

    assert!(script_4 > script_3);
    assert!(script_3 > script_2);
    assert!(script_2 > script_1);
}

#[test]
#[cfg(feature = "bitcoinconsensus")]
fn test_bitcoinconsensus() {
    use crate::consensus_validation::ScriptExt as _;

    // a random segwit transaction from the blockchain using native segwit
    let spent_bytes = hex!("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d");
    let spent = Script::from_bytes(&spent_bytes);
    let spending = hex!("010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000");
    spent.verify(0, crate::Amount::from_sat(18393430), &spending).unwrap();
}

#[test]
fn defult_dust_value_tests() {
    // Check that our dust_value() calculator correctly calculates the dust limit on common
    // well-known scriptPubKey types.
    let script_p2wpkh = Builder::new().push_int(0).push_slice([42; 20]).into_script();
    assert!(script_p2wpkh.is_p2wpkh());
    assert_eq!(script_p2wpkh.minimal_non_dust(), crate::Amount::from_sat(294));
    assert_eq!(
        script_p2wpkh.minimal_non_dust_custom(FeeRate::from_sat_per_vb_unchecked(6)),
        crate::Amount::from_sat(588)
    );

    let script_p2pkh = Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice([42; 20])
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    assert!(script_p2pkh.is_p2pkh());
    assert_eq!(script_p2pkh.minimal_non_dust(), crate::Amount::from_sat(546));
    assert_eq!(
        script_p2pkh.minimal_non_dust_custom(FeeRate::from_sat_per_vb_unchecked(6)),
        crate::Amount::from_sat(1092)
    );
}

#[test]
fn test_script_get_sigop_count() {
    assert_eq!(
        Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice([42; 20])
            .push_opcode(OP_EQUAL)
            .into_script()
            .count_sigops(),
        0
    );
    assert_eq!(
        Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice([42; 20])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .count_sigops(),
        1
    );
    assert_eq!(
        Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice([42; 20])
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_PUSHNUM_1)
            .into_script()
            .count_sigops(),
        1
    );
    let multi = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    assert_eq!(multi.count_sigops(), 3);
    assert_eq!(multi.count_sigops_legacy(), 20);
    let multi_verify = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_opcode(OP_PUSHNUM_3)
        .push_opcode(OP_CHECKMULTISIGVERIFY)
        .push_opcode(OP_PUSHNUM_1)
        .into_script();
    assert_eq!(multi_verify.count_sigops(), 3);
    assert_eq!(multi_verify.count_sigops_legacy(), 20);
    let multi_nopushnum_pushdata = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    assert_eq!(multi_nopushnum_pushdata.count_sigops(), 20);
    assert_eq!(multi_nopushnum_pushdata.count_sigops_legacy(), 20);
    let multi_nopushnum_op = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([3; 33])
        .push_slice([3; 33])
        .push_opcode(OP_DROP)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    assert_eq!(multi_nopushnum_op.count_sigops(), 20);
    assert_eq!(multi_nopushnum_op.count_sigops_legacy(), 20);
}

#[test]
#[cfg(feature = "serde")]
fn test_script_serde_human_and_not() {
    let script = ScriptBuf::from(vec![0u8, 1u8, 2u8]);

    // Serialize
    let json = serde_json::to_string(&script).unwrap();
    assert_eq!(json, "\"000102\"");
    let bincode = bincode::serialize(&script).unwrap();
    assert_eq!(bincode, [3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]); // bincode adds u64 for length, serde_cbor use varint

    // Deserialize
    assert_eq!(script, serde_json::from_str::<ScriptBuf>(&json).unwrap());
    assert_eq!(script, bincode::deserialize::<ScriptBuf>(&bincode).unwrap());
}

#[test]
fn test_instructions_are_fused() {
    let script = ScriptBuf::new();
    let mut instructions = script.instructions();
    assert!(instructions.next().is_none());
    assert!(instructions.next().is_none());
    assert!(instructions.next().is_none());
    assert!(instructions.next().is_none());
}

#[test]
fn script_extend() {
    fn cmp_scripts(new_script: &Script, orig_script: &[Instruction<'_>]) {
        let mut new_instr = new_script.instructions();
        let mut orig_instr = orig_script.iter().cloned();
        for (new, orig) in new_instr.by_ref().zip(orig_instr.by_ref()) {
            assert_eq!(new.unwrap(), orig);
        }
        assert!(new_instr.next().is_none() && orig_instr.next().is_none())
    }

    let script_5_items = [
        Instruction::Op(OP_DUP),
        Instruction::Op(OP_HASH160),
        Instruction::PushBytes([42; 20].as_ref()),
        Instruction::Op(OP_EQUALVERIFY),
        Instruction::Op(OP_CHECKSIG),
    ];
    let new_script = script_5_items.iter().cloned().collect::<ScriptBuf>();
    cmp_scripts(&new_script, &script_5_items);

    let script_6_items = [
        Instruction::Op(OP_DUP),
        Instruction::Op(OP_HASH160),
        Instruction::PushBytes([42; 20].as_ref()),
        Instruction::Op(OP_EQUALVERIFY),
        Instruction::Op(OP_CHECKSIG),
        Instruction::Op(OP_NOP),
    ];
    let new_script = script_6_items.iter().cloned().collect::<ScriptBuf>();
    cmp_scripts(&new_script, &script_6_items);

    let script_7_items = [
        Instruction::Op(OP_DUP),
        Instruction::Op(OP_HASH160),
        Instruction::PushBytes([42; 20].as_ref()),
        Instruction::Op(OP_EQUALVERIFY),
        Instruction::Op(OP_CHECKSIG),
        Instruction::Op(OP_NOP),
    ];
    let new_script = script_7_items.iter().cloned().collect::<ScriptBuf>();
    cmp_scripts(&new_script, &script_7_items);
}

#[test]
fn read_scriptbool_zero_is_false() {
    let v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
    assert!(!read_scriptbool(&v));

    let v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x80]; // With sign bit set.
    assert!(!read_scriptbool(&v));
}

#[test]
fn read_scriptbool_non_zero_is_true() {
    let v: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00];
    assert!(read_scriptbool(&v));

    let v: Vec<u8> = vec![0x01, 0x00, 0x00, 0x80]; // With sign bit set.
    assert!(read_scriptbool(&v));
}

#[test]
fn instruction_script_num_parse() {
    let push_bytes = [
        (PushBytesBuf::from([]), Some(0)),
        (PushBytesBuf::from([0x00]), Some(0)),
        (PushBytesBuf::from([0x01]), Some(1)),
        // Check all the negative 1s
        (PushBytesBuf::from([0x81]), Some(-1)),
        (PushBytesBuf::from([0x01, 0x80]), Some(-1)),
        (PushBytesBuf::from([0x01, 0x00, 0x80]), Some(-1)),
        (PushBytesBuf::from([0x01, 0x00, 0x00, 0x80]), Some(-1)),
        // Check all the negative 0s
        (PushBytesBuf::from([0x80]), Some(0)),
        (PushBytesBuf::from([0x00, 0x80]), Some(0)),
        (PushBytesBuf::from([0x00, 0x00, 0x80]), Some(0)),
        (PushBytesBuf::from([0x00, 0x00, 0x00, 0x80]), Some(0)),
        // Too long
        (PushBytesBuf::from([0x01, 0x00, 0x00, 0x00, 0x80]), None),
        // Check the position of all the bytes
        (PushBytesBuf::from([0xef, 0xbe, 0xad, 0x5e]), Some(0x5eadbeef)),
        // Add negative
        (PushBytesBuf::from([0xef, 0xbe, 0xad, 0xde]), Some(-0x5eadbeef)),
    ];
    let ops = [
        (Instruction::Op(opcodes::all::OP_PUSHDATA4), None),
        (Instruction::Op(opcodes::all::OP_PUSHNUM_NEG1), Some(-1)),
        (Instruction::Op(opcodes::all::OP_RESERVED), None),
        (Instruction::Op(opcodes::all::OP_PUSHNUM_1), Some(1)),
        (Instruction::Op(opcodes::all::OP_PUSHNUM_16), Some(16)),
        (Instruction::Op(opcodes::all::OP_NOP), None),
    ];
    for (input, expected) in &push_bytes {
        assert_eq!(Instruction::PushBytes(input).script_num(), *expected);
    }
    for (input, expected) in &ops {
        assert_eq!(input.script_num(), *expected);
    }

    // script_num() is predicated on OP_0/OP_FALSE (0x00)
    // being treated as an empty PushBytes
    assert_eq!(
        Script::from_bytes(&[0x00]).instructions().next(),
        Some(Ok(Instruction::PushBytes(PushBytes::empty()))),
    );
}
