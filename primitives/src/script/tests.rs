// SPDX-License-Identifier: CC0-1.0

#[cfg(feature = "alloc")]
use alloc::{format, vec};

use hashes::{hash160, sha256};

use super::*;

// All tests should compile and pass no matter which script type you put here.
type Script = ScriptSig;
type ScriptBuf = ScriptSigBuf;

#[test]
fn script_buf_from_vec_u8() {
    let vec = vec![0x51, 0x52, 0x53];
    let script_buf: ScriptBuf = vec.clone().into();
    let result: Vec<u8> = script_buf.into();
    assert_eq!(result, vec);
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
    let want =
        ScriptHash::from_byte_array(hash160::Hash::hash(script.as_bytes()).to_byte_array());

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
    let want =
        WScriptHash::from_byte_array(sha256::Hash::hash(script.as_bytes()).to_byte_array());

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
    let script = RedeemScriptBuf::from(vec![0x51; 521]);
    let result = ScriptHash::try_from(script);

    let err = result.unwrap_err();
    assert_eq!(err.invalid_size(), 521);

    let err_msg = format!("{}", err);
    assert!(err_msg.contains("521"));
}

#[test]
fn witness_script_size_error() {
    let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
    let result = WScriptHash::try_from(script);

    let err = result.unwrap_err();
    assert_eq!(err.invalid_size(), 10_001);

    let err_msg = format!("{}", err);
    assert!(err_msg.contains("10001"));
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
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn script_to_hex() {
    let script = Script::from_bytes(&[0xa1, 0xb2, 0xc3]);
    let hex = alloc::format!("{script:x}");
    assert_eq!(hex, "a1b2c3");
}

#[test]
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
fn script_buf_to_hex() {
    let script = ScriptBuf::from_bytes(vec![0xa1, 0xb2, 0xc3]);
    let hex = alloc::format!("{script:x}");
    assert_eq!(hex, "a1b2c3");
}
