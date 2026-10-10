// SPDX-License-Identifier: CC0-1.0

//! Demonstrates the API for parsing and formatting Bitcoin scripts.
//!
//! Bitcoin script is conceptually a vector of bytes. As such it is consensus encoded with a compact
//! size encoded length prefix. See [`CompactSize`].
//!
//! [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>

use bitcoin::key::PubkeyHash;
use bitcoin::script::ScriptPubKeyBufExt as _;
use bitcoin::{encoding, ScriptPubKeyBuf};

fn main() {
    let pk = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb".parse::<PubkeyHash>().unwrap();

    // TL;DR Use `to_hex_string_prefixed` and `from_hex_prefixed`.
    let script = ScriptPubKeyBuf::new_p2pkh(pk);
    let hex = script.to_hex_string_prefixed();
    let decoded = ScriptPubKeyBuf::from_hex_prefixed(&hex).unwrap();
    assert_eq!(decoded, script);

    // Or if you prefer: `to_hex_string_no_length_prefix` and `from_hex_no_length_prefix`.
    let script = ScriptPubKeyBuf::new_p2pkh(pk);
    let hex = script.to_hex_string_no_length_prefix();
    let decoded = ScriptPubKeyBuf::from_hex_no_length_prefix(&hex).unwrap();
    assert_eq!(decoded, script);

    // Writes the script as human-readable eg, OP_DUP OP_HASH160 OP_PUSHBYTES_20 ...
    println!("human-readable script: {script}");

    // We do not implement parsing scripts from human-readable format.
    // let decoded = s.parse::<ScriptPubKeyBuf>().unwrap();

    // This is not equivalent to consensus encoding i.e., does not include the length prefix.
    let hex_lower_hex_trait = format!("{script:x}");
    println!("hex created using `LowerHex`: {hex_lower_hex_trait}");

    // The `deserialize_hex` function requires the length prefix.
    assert!(encoding::decode_from_hex::<ScriptPubKeyBuf>(&hex_lower_hex_trait).is_err());
    // And so does `from_hex_prefixed`.
    assert!(ScriptPubKeyBuf::from_hex_prefixed(&hex_lower_hex_trait).is_err());
    // But we provide an explicit constructor that does not.
    assert_eq!(
        ScriptPubKeyBuf::from_hex_no_length_prefix(&hex_lower_hex_trait).unwrap(),
        script
    );

    // This is consensus encoding i.e., includes the length prefix.
    let hex_inherent = script.to_hex_string_prefixed(); // Defined in `ScriptExt`.
    println!("hex created using inherent `to_hex_string_prefixed`: {hex_inherent}");

    // The inverse of `to_hex_string_prefixed` is `from_hex_prefixed`.
    let decoded = ScriptPubKeyBuf::from_hex_prefixed(&hex_inherent).unwrap(); // Defined in `ScriptBufExt`.
    assert_eq!(decoded, script);
    // We can also parse the output of `to_hex_string_prefixed` using `deserialize_hex`.
    let decoded = encoding::decode_from_hex::<ScriptPubKeyBuf>(&hex_inherent).unwrap();
    assert_eq!(decoded, script);

    // We also support encode/decode using `consensus::encode` functions.
    let encoded = encoding::encode_to_hex(script.as_script(), hex::Case::Lower);
    println!("hex created using consensus::encode::serialize_hex: {encoded}");

    let decoded: ScriptPubKeyBuf = encoding::decode_from_hex(&encoded).unwrap();
    assert_eq!(decoded, script);

    // And we can mix these two calls because both include the length prefix.
    let encoded = encoding::encode_to_hex(script.as_script(), hex::Case::Lower);
    let decoded = ScriptPubKeyBuf::from_hex_prefixed(&encoded).unwrap();
    assert_eq!(decoded, script);

    // Encode/decode using a byte vector.
    let encoded = encoding::encode_to_vec(script.as_script());
    assert_eq!(&encoded[1..], script.as_bytes()); // Shows that prefix is the first byte.
    let decoded: ScriptPubKeyBuf = encoding::decode_from_slice(&encoded).unwrap();
    assert_eq!(decoded, script);

    // to/from bytes excludes the prefix, these are not encoding/decoding functions so this is sane.
    let bytes = script.to_vec();
    let got = ScriptPubKeyBuf::from_bytes(bytes);
    assert_eq!(got, script);
}
