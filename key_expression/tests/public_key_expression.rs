// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "alloc")]

use bitcoin_key_expression::key_expression::{ParsePublicKeyExpressionError, PublicKeyExpression};

// These fixtures encode the secp256k1 generator from SEC 2 §2.4.1 and its negation.
// https://www.secg.org/sec2-v2.pdf#page=13
const COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ODD_COMPRESSED: &str = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
                           483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const X_ONLY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn roundtrips_preserve_key_form_and_origin() {
    for (raw, compressed) in [(COMPRESSED, true), (ODD_COMPRESSED, true), (UNCOMPRESSED, false)] {
        let expr = raw.parse::<PublicKeyExpression>().unwrap();
        assert!(expr.origin().is_none());
        let PublicKeyExpression::Full { key, .. } = expr else {
            panic!("expected a full key, got {expr:?}");
        };
        assert_eq!(key.compressed(), compressed);
        assert_eq!(&*key.serialize(), hex::decode_to_vec(raw).unwrap().as_slice());
        assert_eq!(expr.to_string(), raw);
        assert_eq!(expr.to_string().parse(), Ok(expr));
    }

    let input = format!("[D34DB33F/84h/0'/1]{}", X_ONLY.to_ascii_uppercase());
    let expr = input.parse::<PublicKeyExpression>().unwrap();
    let origin = expr.origin().unwrap();
    assert_eq!(origin.fingerprint.to_string(), "d34db33f");
    assert_eq!(origin.path.to_u32_vec(), [0x8000_0054, 0x8000_0000, 1]);
    let PublicKeyExpression::XOnly { key, .. } = expr else {
        panic!("expected an x-only key, got {expr:?}");
    };
    assert_eq!(key.to_byte_array(), hex::decode_to_array::<32>(X_ONLY).unwrap());
    assert_eq!(expr.to_string(), format!("[d34db33f/84'/0'/1]{X_ONLY}"));
    assert_eq!(expr.to_string().parse(), Ok(expr));

    let fingerprint_only = format!("[d34db33f]{COMPRESSED}");
    let expr = fingerprint_only.parse::<PublicKeyExpression>().unwrap();
    assert!(expr.origin().unwrap().path.is_empty());
    assert_eq!(expr.to_string(), fingerprint_only);
}

#[test]
fn rejects_malformed_origins_and_keys() {
    use ParsePublicKeyExpressionError::*;

    let out_of_field_x = "ff".repeat(32);
    for (input, expected) in [
        (format!("[d34db33f{COMPRESSED}"), InvalidOrigin),
        (format!("d34db33f]{COMPRESSED}"), InvalidOrigin),
        (format!("[d34db33f][d34db33f]{COMPRESSED}"), InvalidOrigin),
        (format!("{COMPRESSED}[d34db33f]"), InvalidOrigin),
        (format!("[d34db33]{COMPRESSED}"), InvalidFingerprint),
        (format!("[d34db33ff]{COMPRESSED}"), InvalidFingerprint),
        (format!("[g34db33f]{COMPRESSED}"), InvalidFingerprint),
        (format!("[d34dbéf]{COMPRESSED}"), InvalidFingerprint),
        (String::new(), MissingKey),
        ("[d34db33f]".to_owned(), MissingKey),
        (format!("06{}", &UNCOMPRESSED[2..]), InvalidPublicKey),
        (format!("02{out_of_field_x}"), InvalidPublicKey),
        (out_of_field_x, InvalidPublicKey),
        (format!("{COMPRESSED}/0"), InvalidPublicKey),
        (format!("{COMPRESSED}junk"), InvalidPublicKey),
        (format!(" {COMPRESSED}"), InvalidPublicKey),
        (format!("{COMPRESSED}\n"), InvalidPublicKey),
    ] {
        assert_eq!(input.parse::<PublicKeyExpression>(), Err(expected), "{input:?}");
    }

    for path in ["", "0//1", "0/", "0/*", "m/0", "+1", "-1", "2147483648", "2147483648'"] {
        let input = format!("[d34db33f/{path}]{COMPRESSED}");
        assert_eq!(input.parse::<PublicKeyExpression>(), Err(InvalidOriginPath), "{input:?}");
    }
}

#[cfg(feature = "serde")]
#[test]
fn serde_uses_a_string_in_both_formats() {
    let canonical = format!("[d34db33f/1']{COMPRESSED}");
    let expr = canonical.parse::<PublicKeyExpression>().unwrap();

    assert_eq!(serde_json::to_string(&expr).unwrap(), format!("\"{canonical}\""));
    assert_eq!(bincode::serialize(&expr).unwrap(), bincode::serialize(&canonical).unwrap());

    let input = format!("[D34DB33F/1h]{}", COMPRESSED.to_ascii_uppercase());
    let json = serde_json::to_string(&input).unwrap();
    let binary = bincode::serialize(&input).unwrap();
    assert_eq!(serde_json::from_str::<PublicKeyExpression>(&json).unwrap(), expr);
    assert_eq!(bincode::deserialize::<PublicKeyExpression>(&binary).unwrap(), expr);

    let invalid = "not a key";
    let json = serde_json::to_string(invalid).unwrap();
    let binary = bincode::serialize(invalid).unwrap();
    assert!(serde_json::from_str::<PublicKeyExpression>(&json).is_err());
    assert!(bincode::deserialize::<PublicKeyExpression>(&binary).is_err());
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_expressions_roundtrip() {
    use arbitrary::{Arbitrary, Unstructured};

    let mut generated = 0;
    for offset in 0..16 {
        let bytes: [u8; 256] = std::array::from_fn(|index| (index as u8).wrapping_add(offset));
        if let Ok(expr) = PublicKeyExpression::arbitrary(&mut Unstructured::new(&bytes)) {
            assert_eq!(expr.to_string().parse(), Ok(expr));
            generated += 1;
        }
    }
    assert!(generated > 0);
}
