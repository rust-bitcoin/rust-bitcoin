// SPDX-License-Identifier: CC0-1.0

use alloc::string::ToString;
use alloc::{format, vec};
use core::ops::Bound;

use encoding::{Decode, Decoder as _};
use hashes::{hash160, sha256};

use super::*;

// All tests should compile and pass no matter which script type you put here.
type Script = ScriptSig;
type ScriptBuf = ScriptSigBuf;

#[test]
fn script_buf_capacity() {
    let script = ScriptBuf::with_capacity(10);
    assert!(script.capacity() >= 10);
}

#[test]
fn script_buf_reserve() {
    let mut script = ScriptBuf::new();
    script.reserve(10);
    assert!(script.capacity() >= 10);
}

#[test]
fn script_buf_reserve_exact() {
    let mut script = ScriptBuf::new();
    script.reserve_exact(10);
    assert!(script.capacity() >= 10);
}

#[test]
fn script_buf_default() {
    let script: ScriptBuf = ScriptBuf::default();
    assert!(script.is_empty());
}

#[test]
fn script_buf_from_vec_u8() {
    let vec = vec![0x51, 0x52, 0x53];
    let script_buf: ScriptBuf = vec.clone().into();
    let result: Vec<u8> = script_buf.into();
    assert_eq!(result, vec);
}

#[test]
fn script_buf_from_bytes() {
    let bytes = vec![1, 2, 3];
    let script = ScriptBuf::from_bytes(bytes.clone());
    assert_eq!(script.as_bytes(), bytes);
}

#[test]
fn script_from_bytes() {
    let script = Script::from_bytes(&[1, 2, 3]);
    assert_eq!(script.as_bytes(), [1, 2, 3]);
}

#[test]
fn script_from_bytes_mut() {
    let bytes = &mut [1, 2, 3];
    let script = Script::from_bytes_mut(bytes);
    script.as_mut_bytes()[0] = 4;
    assert_eq!(script.as_mut_bytes(), [4, 2, 3]);
}

#[test]
fn script_buf_as_script() {
    let bytes = vec![1, 2, 3];
    let script = ScriptBuf::from_bytes(bytes.clone());
    let script_ref = script.as_script();
    assert_eq!(script_ref.as_bytes(), bytes);
}

#[test]
fn script_buf_as_mut_script() {
    let mut script = ScriptBuf::from_bytes(vec![1, 2, 3]);
    let script_mut_ref = script.as_mut_script();
    script_mut_ref.as_mut_bytes()[0] = 4;
    assert_eq!(script.as_mut_bytes(), &[4, 2, 3]);
}

#[test]
fn script_to_vec() {
    let script = Script::from_bytes(&[1, 2, 3]);
    assert_eq!(script.to_vec(), vec![1, 2, 3]);
}

#[test]
fn script_to_owned() {
    let script = Script::from_bytes(&[1, 2, 3]);
    let script_buf = script.to_owned();
    assert_eq!(script_buf.as_bytes(), [1, 2, 3]);
}

#[test]
fn script_buf_into_bytes() {
    let bytes = vec![1, 2, 3];
    let script = ScriptBuf::from_bytes(bytes.clone());
    let result = script.into_bytes();
    assert_eq!(result, bytes);
}

#[test]
fn script_buf_into_boxed_script() {
    let bytes = vec![1, 2, 3];
    let script = ScriptBuf::from_bytes(bytes.clone());
    let boxed_script = script.into_boxed_script();
    assert_eq!(boxed_script.as_bytes(), bytes);
}

#[test]
fn script_buf_as_ref() {
    let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
    let script_ref: &[u8] = script_buf.as_ref();
    assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

    let script_ref: &Script = script_buf.as_ref();
    assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
}

#[test]
fn script_buf_as_mut() {
    let mut script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);

    let script_mut: &mut [u8] = script_buf.as_mut();
    script_mut[0] = 0x50;
    assert_eq!(script_mut, [0x50, 0x52, 0x53]);

    let script_mut: &mut Script = script_buf.as_mut();
    script_mut.as_mut_bytes()[1] = 0x51;
    assert_eq!(script_buf.as_bytes(), &[0x50, 0x51, 0x53]);
}

#[test]
fn script_buf_borrow_mut() {
    let mut script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
    let script_mut: &mut Script = script_buf.borrow_mut();
    script_mut.as_mut_bytes()[0] = 0x50;

    assert_eq!(script_buf.as_bytes(), &[0x50, 0x52, 0x53]);
}

#[test]
#[allow(clippy::useless_asref)]
fn script_as_ref() {
    let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let script_ref: &[u8] = script.as_ref();
    assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

    let script_ref: &Script = script.as_ref();
    assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
}

#[test]
#[allow(clippy::useless_asref)]
fn script_as_mut() {
    let bytes = &mut [0x51, 0x52, 0x53];
    let script = Script::from_bytes_mut(bytes);

    let script_mut: &mut [u8] = script.as_mut();
    script_mut[0] = 0x50;
    assert_eq!(script_mut, [0x50, 0x52, 0x53]);

    let script_mut: &mut Script = script.as_mut();
    script_mut.as_mut_bytes()[1] = 0x51;
    assert_eq!(script.as_bytes(), &[0x50, 0x51, 0x53]);
}

#[test]
fn script_len() {
    let script = Script::from_bytes(&[1, 2, 3]);
    assert_eq!(script.len(), 3);
}

#[test]
fn script_is_empty() {
    let script: &Script = Default::default();
    assert!(script.is_empty());

    let script = Script::from_bytes(&[1, 2, 3]);
    assert!(!script.is_empty());
}

#[test]
#[cfg(feature = "hex")]
fn script_builder() {
    use hex::hex;

    use crate::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};

    // from txid 3bb5e6434c11fb93f64574af5d116736510717f2c595eb45b52c28e31622dfff which was in my mempool when I wrote the test
    let script = Builder::<ScriptPubKeyTag>::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(hex!("16e1ae70ff0fa102905d4af297f6912bda6cce19"))
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    assert_eq!(
        script.to_hex_string_no_length_prefix(),
        "76a91416e1ae70ff0fa102905d4af297f6912bda6cce1988ac"
    );
}

#[test]
#[cfg(feature = "hex")]
#[cfg(feature = "serde")]
fn script_json_serialize() {
    use serde_json;

    let original = ScriptBuf::from_hex_no_length_prefix("827651a0698faaa9a8a7a687").unwrap();
    let json = serde_json::to_value(&original).unwrap();
    assert_eq!(json, serde_json::Value::String("827651a0698faaa9a8a7a687".to_owned()));
    let des = serde_json::from_value::<ScriptBuf>(json).unwrap();
    assert_eq!(original, des);
}

#[test]
#[cfg(feature = "hex")]
fn script_asm() {
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("6363636363686868686800").unwrap().to_string(),
        "OP_IF OP_IF OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_ENDIF OP_0"
    );
    assert_eq!(ScriptBuf::from_hex_no_length_prefix("2102715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699ac").unwrap().to_string(),
               "OP_PUSHBYTES_33 02715e91d37d239dea832f1460e91e368115d8ca6cc23a7da966795abad9e3b699 OP_CHECKSIG");
    // Elements Alpha peg-out transaction with some signatures removed for brevity. Mainly to test PUSHDATA1
    assert_eq!(ScriptBuf::from_hex_no_length_prefix("0047304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401004cf1552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae").unwrap().to_string(),
               "OP_0 OP_PUSHBYTES_71 304402202457e78cc1b7f50d0543863c27de75d07982bde8359b9e3316adec0aec165f2f02200203fd331c4e4a4a02f48cf1c291e2c0d6b2f7078a784b5b3649fca41f8794d401 OP_0 OP_PUSHDATA1 552103244e602b46755f24327142a0517288cebd159eccb6ccf41ea6edf1f601e9af952103bbbacc302d19d29dbfa62d23f37944ae19853cf260c745c2bea739c95328fcb721039227e83246bd51140fe93538b2301c9048be82ef2fb3c7fc5d78426ed6f609ad210229bf310c379b90033e2ecb07f77ecf9b8d59acb623ab7be25a0caed539e2e6472103703e2ed676936f10b3ce9149fa2d4a32060fb86fa9a70a4efe3f21d7ab90611921031e9b7c6022400a6bb0424bbcde14cff6c016b91ee3803926f3440abf5c146d05210334667f975f55a8455d515a2ef1c94fdfa3315f12319a14515d2a13d82831f62f57ae");
    // Various weird scripts found in transaction 6d7ed9914625c73c0288694a6819196a27ef6c08f98e1270d975a8e65a3dc09a
    // which triggered overflow bugs on 32-bit machines in script formatting in the past.
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("01").unwrap().to_string(),
        "OP_PUSHBYTES_1 <push past end>"
    );
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("0201").unwrap().to_string(),
        "OP_PUSHBYTES_2 <push past end>"
    );
    assert_eq!(ScriptBuf::from_hex_no_length_prefix("4c").unwrap().to_string(), "<unexpected end>");
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("4c0201").unwrap().to_string(),
        "OP_PUSHDATA1 <push past end>"
    );
    assert_eq!(ScriptBuf::from_hex_no_length_prefix("4d").unwrap().to_string(), "<unexpected end>");
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("4dffff01").unwrap().to_string(),
        "OP_PUSHDATA2 <push past end>"
    );
    assert_eq!(
        ScriptBuf::from_hex_no_length_prefix("4effffffff01").unwrap().to_string(),
        "OP_PUSHDATA4 <push past end>"
    );
}

#[test]
fn test_index() {
    let script = Script::from_bytes(&[1, 2, 3, 4, 5]);

    assert_eq!(script[1..3].as_bytes(), &[2, 3]);
    assert_eq!(script[2..].as_bytes(), &[3, 4, 5]);
    assert_eq!(script[..3].as_bytes(), &[1, 2, 3]);
    assert_eq!(script[..].as_bytes(), &[1, 2, 3, 4, 5]);
    assert_eq!(script[1..=3].as_bytes(), &[2, 3, 4]);
    assert_eq!(script[..=2].as_bytes(), &[1, 2, 3]);
}

#[test]
fn test_index_bound_tuple() {
    let script = Script::from_bytes(&[1, 2, 3, 4, 5]);

    assert_eq!(script[(Bound::Included(1), Bound::Excluded(4))].as_bytes(), &[2, 3, 4]);
}

#[test]
fn partial_ord() {
    let script_small = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let script_big = Script::from_bytes(&[0x54, 0x55, 0x56]);
    let script_buf_small = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
    let script_buf_big = ScriptBuf::from(vec![0x54, 0x55, 0x56]);

    assert!(script_small == &script_buf_small);
    assert!(script_buf_small == *script_small);
    assert!(script_small != &script_buf_big);
    assert!(script_buf_small != *script_big);

    assert!(script_small < &script_buf_big);
    assert!(script_buf_small < *script_big);
    assert!(script_big > &script_buf_small);
    assert!(script_buf_big > *script_small);
}

#[test]
#[cfg(feature = "hex")]
fn provably_unspendable() {
    // p2pk
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix("410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac").unwrap().is_op_return());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix("4104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").unwrap().is_op_return());
    // p2pkhash
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac"
    )
    .unwrap()
    .is_op_return());
    assert!(ScriptPubKeyBuf::from_hex_no_length_prefix(
        "6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87"
    )
    .unwrap()
    .is_op_return());
}

#[test]
#[cfg(feature = "hex")]
fn op_return() {
    assert!(ScriptPubKeyBuf::from_hex_no_length_prefix(
        "6aa9149eb21980dc9d413d8eac27314938b9da920ee53e87"
    )
    .unwrap()
    .is_op_return());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "76a914ee61d57ab51b9d212335b1dba62794ac20d2bcf988ac"
    )
    .unwrap()
    .is_op_return());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix("").unwrap().is_op_return());
}

#[test]
#[cfg(feature = "hex")]
fn script_p2sh_p2pkh_template() {
    // random outputs I picked out of the mempool
    assert!(ScriptPubKeyBuf::from_hex_no_length_prefix(
        "76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac"
    )
    .unwrap()
    .is_p2pkh());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ac"
    )
    .unwrap()
    .is_p2sh());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "76a91402306a7c23f3e8010de41e9e591348bb83f11daa88ad"
    )
    .unwrap()
    .is_p2pkh());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix("").unwrap().is_p2pkh());
    assert!(ScriptPubKeyBuf::from_hex_no_length_prefix(
        "a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87"
    )
    .unwrap()
    .is_p2sh());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "a914acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87"
    )
    .unwrap()
    .is_p2pkh());
    assert!(!ScriptPubKeyBuf::from_hex_no_length_prefix(
        "a314acc91e6fef5c7f24e5c8b3f11a664aa8f1352ffd87"
    )
    .unwrap()
    .is_p2sh());
}

#[test]
fn script_hash_from_script() {
    let script = RedeemScript::from_bytes(&[0x51; 520]);
    assert!(ScriptHash::from_script(script).is_ok());

    let script = RedeemScript::from_bytes(&[0x51; 521]);
    assert!(ScriptHash::from_script(script).is_err());
}

#[test]
fn script_hash_from_script_unchecked() {
    let script = WitnessScript::from_bytes(&[0x51; 521]);

    let got = ScriptHash::from_script_unchecked(script);
    let want = ScriptHash::from_byte_array(hash160::Hash::hash(script.as_bytes()).to_byte_array());

    assert_eq!(got, want);
}

#[test]
fn wscript_hash_from_script() {
    let script = WitnessScript::from_bytes(&[0x51; 10_000]);
    assert!(WScriptHash::from_script(script).is_ok());

    let script = WitnessScript::from_bytes(&[0x51; 10_001]);
    assert!(WScriptHash::from_script(script).is_err());
}

#[test]
fn wscript_hash_from_script_unchecked() {
    let script = WitnessScript::from_bytes(&[0x51; 10_001]);

    let got = WScriptHash::from_script_unchecked(script);
    let want = WScriptHash::from_byte_array(sha256::Hash::hash(script.as_bytes()).to_byte_array());

    assert_eq!(got, want);
}

#[test]
fn try_from_scriptpubkeybuf_for_scripthash() {
    let script = ScriptPubKeyBuf::from(vec![0x51; 520]);
    assert!(ScriptHash::try_from(script).is_ok());

    let script = ScriptPubKeyBuf::from(vec![0x51; 521]);
    assert!(ScriptHash::try_from(script).is_err());
}

#[test]
fn try_from_scriptpubkeybuf_ref_for_scripthash() {
    let script = ScriptPubKeyBuf::from(vec![0x51; 520]);
    assert!(ScriptHash::try_from(&script).is_ok());

    let script = ScriptPubKeyBuf::from(vec![0x51; 521]);
    assert!(ScriptHash::try_from(&script).is_err());
}

#[test]
fn try_from_script_for_scripthash() {
    let script = RedeemScript::from_bytes(&[0x51; 520]);
    assert!(ScriptHash::try_from(script).is_ok());

    let script = RedeemScript::from_bytes(&[0x51; 521]);
    assert!(ScriptHash::try_from(script).is_err());
}

#[test]
fn try_from_script_buf_for_wscript_hash() {
    let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
    assert!(WScriptHash::try_from(script).is_ok());

    let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
    assert!(WScriptHash::try_from(script).is_err());
}

#[test]
fn try_from_script_buf_ref_for_wscript_hash() {
    let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
    assert!(WScriptHash::try_from(&script).is_ok());

    let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
    assert!(WScriptHash::try_from(&script).is_err());
}

#[test]
fn try_from_script_for_wscript_hash() {
    let script = WitnessScript::from_bytes(&[0x51; 10_000]);
    assert!(WScriptHash::try_from(script).is_ok());

    let script = WitnessScript::from_bytes(&[0x51; 10_001]);
    assert!(WScriptHash::try_from(script).is_err());
}

#[test]
fn cow_script_to_script_buf() {
    let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let cow_borrowed: Cow<Script> = Cow::Borrowed(script);
    let script_buf: ScriptBuf = cow_borrowed.into();
    assert_eq!(script_buf.as_bytes(), &[0x51, 0x52, 0x53]);
}

#[test]
fn cow_script_buf_to_script() {
    let cow_owned: Cow<Script> = Cow::Owned(ScriptBuf::from(vec![0x51, 0x52, 0x53]));
    let script: &Script = cow_owned.borrow();
    assert_eq!(script.as_bytes(), &[0x51, 0x52, 0x53]);
}

#[test]
fn cow_script_buf_to_box_script() {
    let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
    let cow_owned: Cow<Script> = Cow::Owned(script_buf.clone());
    let boxed_script: Box<Script> = cow_owned.into();
    let script_buf2 = boxed_script.into_script_buf();
    assert_eq!(script_buf2, script_buf);
}

#[test]
fn cow_owned_to_script_buf() {
    let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
    let cow_owned: Cow<Script> = Cow::Owned(script_buf.clone());
    let script_buf_2: ScriptBuf = cow_owned.into();
    assert_eq!(script_buf_2, script_buf);
}

#[test]
fn cow_script_to_box_script() {
    let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let cow_borrowed: Cow<Script> = Cow::Borrowed(script);
    let boxed_script: Box<Script> = cow_borrowed.into();
    assert_eq!(boxed_script.as_bytes(), &[0x51, 0x52, 0x53]);

    let cow_owned: Cow<Script> = Cow::from(script.to_owned());
    assert_eq!(cow_owned.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);

    let cow_from_script: Cow<Script> = Cow::from(script);
    assert_eq!(cow_from_script.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);
}

#[test]
fn redeem_script_size_error() {
    #[cfg(feature = "std")]
    use std::error::Error as _;

    let script = RedeemScriptBuf::from(vec![0x51; 521]);
    let result = ScriptHash::try_from(script);

    let err = result.unwrap_err();
    assert_eq!(err.invalid_size(), 521);

    assert!(!err.to_string().is_empty());
    #[cfg(feature = "std")]
    assert!(err.source().is_none());
}

#[test]
fn witness_script_size_error() {
    #[cfg(feature = "std")]
    use std::error::Error as _;

    let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
    let result = WScriptHash::try_from(script);

    let err = result.unwrap_err();
    assert_eq!(err.invalid_size(), 10_001);

    assert!(!err.to_string().is_empty());
    #[cfg(feature = "std")]
    assert!(err.source().is_none());
}

#[test]
#[cfg(target_has_atomic = "ptr")]
fn script_to_arc() {
    let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let arc_script: Arc<Script> = Arc::from(script);

    assert_eq!(arc_script.as_bytes(), script.as_bytes());
    assert_eq!(Arc::strong_count(&arc_script), 1);
}

#[test]
fn script_to_rc() {
    let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
    let rc_script: Rc<Script> = Rc::from(script);

    assert_eq!(rc_script.as_bytes(), script.as_bytes());
    assert_eq!(Rc::strong_count(&rc_script), 1);
}

#[test]
fn pushdata_end_conditions() {
    let push_past_end_script = Script::from_bytes(&[0x4c, 0x02]);
    let formatted_script = format!("{}", push_past_end_script);
    assert!(formatted_script.contains("<push past end>"));

    let unexpected_end_script = Script::from_bytes(&[0x4c]);
    let formatted_script = format!("{}", unexpected_end_script);
    assert!(formatted_script.contains("<unexpected end>"));
}

#[test]
fn legacy_opcode() {
    let script = Script::from_bytes(&[0x03, 0xaa, 0xbb, 0xcc]);
    assert_eq!(format!("{}", script), "OP_PUSHBYTES_3 aabbcc");
}

#[test]
fn script_display() {
    let script = Script::from_bytes(&[0x00, 0xa1, 0xb2]);
    assert_eq!(format!("{}", script), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

    #[cfg(feature = "hex")]
    {
        assert_eq!(format!("{:x}", script), "00a1b2");
        assert_eq!(format!("{:X}", script), "00A1B2");
    }
    assert!(!format!("{:?}", script).is_empty());
}

#[test]
fn script_pubkey_display_and_debug() {
    let script = ScriptPubKey::from_bytes(&[0x00, 0xa1, 0xb2]);

    assert_eq!(format!("{}", script), "OP_0 OP_LESSTHANOREQUAL OP_CSV");
    assert_eq!(format!("{:?}", script), "Script(OP_0 OP_LESSTHANOREQUAL OP_CSV)");
}

#[test]
fn script_display_pushdata() {
    // OP_PUSHDATA1
    let script = Script::from_bytes(&[0x4c, 0x02, 0xab, 0xcd]);
    assert_eq!(format!("{}", script), "OP_PUSHDATA1 abcd");

    // OP_PUSHDATA2
    let script = Script::from_bytes(&[0x4d, 0x02, 0x00, 0x12, 0x34]);
    assert_eq!(format!("{}", script), "OP_PUSHDATA2 1234");

    // OP_PUSHDATA4
    let script = Script::from_bytes(&[0x4e, 0x02, 0x00, 0x00, 0x00, 0x56, 0x78]);
    assert_eq!(format!("{}", script), "OP_PUSHDATA4 5678");
}

#[test]
fn script_buf_display() {
    let script_buf = ScriptBuf::from(vec![0x00, 0xa1, 0xb2]);
    assert_eq!(format!("{}", script_buf), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

    #[cfg(feature = "hex")]
    {
        assert_eq!(format!("{:x}", script_buf), "00a1b2");
        assert_eq!(format!("{:X}", script_buf), "00A1B2");
    }
    assert!(!format!("{:?}", script_buf).is_empty());
}

#[test]
fn script_pubkey_buf_display_and_debug() {
    let script_buf = ScriptPubKeyBuf::from(vec![0x00, 0xa1, 0xb2]);

    assert_eq!(format!("{}", script_buf), "OP_0 OP_LESSTHANOREQUAL OP_CSV");
    assert_eq!(format!("{:?}", script_buf), "Script(OP_0 OP_LESSTHANOREQUAL OP_CSV)");
}

#[test]
fn encode() {
    // Consensus encoding includes the length of the encoded data
    // (compact size encoded length prefix).
    let consensus_encoded: [u8; 6] = [0x05, 1, 2, 3, 4, 5];

    // `from_bytes` does not expect the prefix.
    let script = Script::from_bytes(&consensus_encoded[1..]);

    let got = encoding::encode_to_vec(script);
    assert_eq!(got, consensus_encoded);
}

#[test]
#[cfg(feature = "hex")]
fn script_to_hex() {
    let script = Script::from_bytes(&[0xa1, 0xb2, 0xc3]);
    let hex = format!("{script:x}");
    assert_eq!(hex, "a1b2c3");
}

#[test]
#[cfg(feature = "hex")]
fn script_buf_to_hex() {
    let script = ScriptBuf::from_bytes(vec![0xa1, 0xb2, 0xc3]);
    let hex = format!("{script:x}");
    assert_eq!(hex, "a1b2c3");
}

#[test]
#[cfg(feature = "hex")]
fn hex() {
    // This test is similar to code in `bitcoin/examples/script.rs` but without
    // touching the `bitcoin::consensus::encode` functions.
    use alloc::format;

    let consensus = "04deadbeef";
    let raw = "deadbeef";

    // Sanity check - positive case.
    let a = ScriptBuf::from_hex_prefixed(consensus).unwrap();
    let b = ScriptBuf::from_hex_no_length_prefix(raw).unwrap();
    assert_eq!(a, b);

    // Sanity check - negative case. Nice API, this misuse fails.
    assert!(ScriptBuf::from_hex_prefixed(raw).is_err()); //

    // Sanity check - negative case. But this just puts the length prefix in the script, ouch.
    assert!(ScriptBuf::from_hex_no_length_prefix(consensus).is_ok());

    let script = ScriptBuf::from_hex_prefixed(consensus).unwrap();

    let got = script.to_hex_string_prefixed();
    assert_eq!(got, consensus);

    let got = script.to_hex_string_no_length_prefix();
    assert_eq!(got, raw);

    // `LowerHex` is not consensus encoding, this may be surprising?
    let got = format!("{:x}", script);
    assert_eq!(got, raw);
}

#[test]
fn script_consensus_decode_empty() {
    let bytes = vec![0_u8];
    let mut push = bytes.as_slice();
    let mut decoder = ScriptBuf::decoder();
    decoder.push_bytes(&mut push).unwrap();

    let got = decoder.end().unwrap();
    let want = ScriptBuf::new();

    assert_eq!(got, want);
}

#[test]
fn script_consensus_decode_empty_with_more_data() {
    // An empty script sig with a bunch of unrelated data at the end.
    let bytes = vec![0x00_u8, 0xff, 0xff, 0xff, 0xff];
    let mut push = bytes.as_slice();
    let mut decoder = ScriptBuf::decoder();
    decoder.push_bytes(&mut push).unwrap();

    let got = decoder.end().unwrap();
    let want = ScriptBuf::new();

    assert_eq!(got, want);
}

#[test]
fn decoder_full_read_limit() {
    let mut decoder = ScriptBuf::decoder();
    // ByteVecDecoder length prefix is CompactSize: needs 1 byte.
    assert_eq!(decoder.read_limit(), 1);

    // Script length prefix = 32.
    let mut push = [32_u8].as_slice();
    decoder.push_bytes(&mut push).unwrap();
    // Limit is 32 for the script data.
    assert_eq!(decoder.read_limit(), 32);

    // Provide 1 byte of script data decreasing the read limit by 1.
    let mut push = [0xAA_u8].as_slice();
    decoder.push_bytes(&mut push).unwrap();
    assert_eq!(decoder.read_limit(), 31);
}

#[test]
fn witness_to_signet_script() {
    let bytes = vec![0x51, 0x52, 0x53];
    let witness = WitnessScriptBuf::from(bytes.clone());
    let signet: SignetBlockScriptBuf = witness.into();
    assert_eq!(signet.as_bytes(), &bytes);
}

// Builds a witness-program-shaped script: version byte, push opcode, then `program_len` bytes.
fn witness_program_bytes(version_byte: u8, push_opcode: u8, program_len: usize) -> Vec<u8> {
    let mut v = vec![version_byte, push_opcode];
    v.resize(2 + program_len, 0xab);
    v
}

#[test]
fn witness_version_valid() {
    use crate::witness_version::WitnessVersion;

    let p2wpkh = ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x14, 20));
    assert_eq!(p2wpkh.witness_version(), Some(WitnessVersion::V0));

    let p2wsh = ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x20, 32));
    assert_eq!(p2wsh.witness_version(), Some(WitnessVersion::V0));

    let p2tr = ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x20, 32));
    assert_eq!(p2tr.witness_version(), Some(WitnessVersion::V1));

    let push2 = ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x02, 2));
    assert_eq!(push2.witness_version(), Some(WitnessVersion::V1));

    let max = ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x28, 40));
    assert_eq!(max.witness_version(), Some(WitnessVersion::V1));

    assert!(ScriptPubKeyBuf::from(vec![0x00, 0x01, 0xab]).witness_version().is_none());
    assert!(ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x28, 41))
        .witness_version()
        .is_none());

    assert!(ScriptPubKeyBuf::from(vec![0x00, 0x01, 0xab, 0xab]).witness_version().is_none());

    assert!(ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x14, 19))
        .witness_version()
        .is_none());

    assert!(ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x14, 21))
        .witness_version()
        .is_none());
}

#[test]
fn script_is_p2wsh() {
    let p2wsh = ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x20, 32));
    assert!(p2wsh.is_p2wsh());

    assert!(!ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x21, 33)).is_p2wsh());
    assert!(!ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x20, 32)).is_p2wsh());
    assert!(!ScriptPubKeyBuf::from(vec![0xab; 34]).is_p2wsh());
}

#[test]
fn script_is_p2wpkh() {
    let p2wpkh = ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x14, 20));
    assert!(p2wpkh.is_p2wpkh());

    assert!(!ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x15, 21)).is_p2wpkh());
    assert!(!ScriptPubKeyBuf::from(witness_program_bytes(0x51, 0x14, 20)).is_p2wpkh());
    assert!(!ScriptPubKeyBuf::from(vec![0xab; 22]).is_p2wpkh());
}

#[test]
fn script_is_witness_program() {
    let p2wpkh = ScriptPubKeyBuf::from(witness_program_bytes(0x00, 0x14, 20));
    assert!(p2wpkh.is_witness_program());

    assert!(!ScriptPubKeyBuf::from(vec![0x00, 0x01, 0xab]).is_witness_program());
}

#[test]
fn script_is_p2a() {
    let p2a = ScriptPubKeyBuf::new_p2a();
    assert!(p2a.is_p2a());
    assert_eq!(p2a.as_bytes(), &[0x51, 0x02, 0x4e, 0x73]);

    assert!(!ScriptPubKeyBuf::from(vec![0x00, 0x02, 0x4e, 0x73]).is_p2a());
    assert!(!ScriptPubKeyBuf::from(vec![0x51, 0x02, 0xaa, 0xbb]).is_p2a());
    assert!(!ScriptPubKeyBuf::from(vec![0x51, 0x03, 0x4e, 0x73, 0x00]).is_p2a());
}

#[test]
fn new_op_return() {
    let op_return = ScriptPubKeyBuf::new_op_return([0x01u8, 0x02, 0x03]);
    assert!(op_return.is_op_return());
    assert!(!op_return.is_empty());
    assert_eq!(op_return.as_bytes(), &[0x6a, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn new_p2sh() {
    let script_hash = ScriptHash::from_byte_array([0x12; 20]);
    let p2sh = ScriptPubKeyBuf::new_p2sh(script_hash);
    assert!(p2sh.is_p2sh());
    assert!(!p2sh.is_empty());

    let mut want = vec![0xa9, 0x14];
    want.extend([0x12; 20]);
    want.push(0x87);
    assert_eq!(p2sh.as_bytes(), &want[..]);
}

#[test]
fn new_p2wsh() {
    let wscript_hash = WScriptHash::from_byte_array([0x34; 32]);
    let p2wsh = ScriptPubKeyBuf::new_p2wsh(wscript_hash);
    assert!(p2wsh.is_p2wsh());
    assert!(!p2wsh.is_empty());

    let mut want = vec![0x00, 0x20];
    want.extend([0x34; 32]);
    assert_eq!(p2wsh.as_bytes(), &want[..]);

    let redeem_script = RedeemScriptBuf::new_p2wsh(wscript_hash);
    assert!(redeem_script.is_p2wsh());
    assert_eq!(redeem_script.as_bytes(), &want[..]);
}

#[test]
fn new_p2a() {
    let p2a = ScriptPubKeyBuf::new_p2a();
    assert!(p2a.is_p2a());
    assert!(!p2a.is_empty());
    assert_eq!(p2a.as_bytes(), &[0x51, 0x02, 0x4e, 0x73]);
}

#[test]
fn decoder_error_display() {
    #[cfg(feature = "std")]
    use std::error::Error as _;

    let bytes = vec![0x01_u8];
    let mut push = bytes.as_slice();
    let mut decoder = <ScriptBuf as Decode>::Decoder::default();
    decoder.push_bytes(&mut push).unwrap();

    let err = decoder.end().unwrap_err();
    assert!(!err.to_string().is_empty());
    #[cfg(feature = "std")]
    assert!(err.source().is_some());
}
