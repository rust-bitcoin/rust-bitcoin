// SPDX-License-Identifier: CC0-1.0

//! Demonstrates the API for parsing and formatting Bitcoin scripts.
//!
//! Bitcoin script is conceptually a vector of bytes. As such it is consensus encoded with a compact
//! size encoded length prefix. See [CompactSize].
//!
//! [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>

use bitcoin::consensus::encode;
use bitcoin::key::WPubkeyHash;
use bitcoin::script::{self, ScriptBufExt, ScriptExt};
use bitcoin::ScriptBuf;

fn main() {
    let pk = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb".parse::<WPubkeyHash>().unwrap();

    // TL;DR Use `to_hex_string` and `from_hex`.
    let script_code = script::p2wpkh_script_code(pk);
    let hex = script_code.to_hex_string();
    let decoded = ScriptBuf::from_hex(&hex).unwrap();
    assert_eq!(decoded, script_code);

    // Writes the script as human-readable eg, OP_DUP OP_HASH160 OP_PUSHBYTES_20 ...
    println!("human-readable script: {script_code}");

    // We do not implement parsing scripts from human-readable format.
    // let decoded = s.parse::<ScriptBuf>().unwrap();

    // This is equivalent to consensus encoding i.e., includes the length prefix.
    let hex_lower_hex_trait = format!("{script_code:x}");
    println!("hex created using `LowerHex`: {hex_lower_hex_trait}");

    // The `deserialize_hex` function requires the length prefix.
    assert_eq!(encode::deserialize_hex::<ScriptBuf>(&hex_lower_hex_trait).unwrap(), script_code);
    // And so does `from_hex`.
    assert_eq!(ScriptBuf::from_hex(&hex_lower_hex_trait).unwrap(), script_code);

    // And we also provide an explicit constructor that does not use the length prefix.
    let other = ScriptBuf::from_hex_no_length_prefix(&hex_lower_hex_trait).unwrap();
    // Without a prefix the script parses but its not the one we meant.
    assert_ne!(other, script_code);

    // This is consensus encoding i.e., includes the length prefix.
    let hex_inherent = script_code.to_hex_string(); // Defined in `ScriptExt`.
    println!("hex created using inherent `to_hex_string`: {hex_inherent}");

    // The inverse of `to_hex_string` is `from_hex`.
    let decoded = ScriptBuf::from_hex(&hex_inherent).unwrap(); // Defined in `ScriptBufExt`.
    assert_eq!(decoded, script_code);
    // We can also parse the output of `to_hex_string` using `deserialize_hex`.
    let decoded = encode::deserialize_hex::<ScriptBuf>(&hex_inherent).unwrap();
    assert_eq!(decoded, script_code);

    // We also support encode/decode using `consensus::encode` functions.
    let encoded = encode::serialize_hex(&script_code);
    println!("hex created using consensus::encode::serialize_hex: {encoded}");

    let decoded: ScriptBuf = encode::deserialize_hex(&encoded).unwrap();
    assert_eq!(decoded, script_code);
    // And we can mix these to calls because both include the length prefix.
    let decoded = ScriptBuf::from_hex(&encoded).unwrap();
    assert_eq!(decoded, script_code);

    // Encode/decode using a byte vector.
    let encoded = encode::serialize(&script_code);
    assert_eq!(&encoded[1..], script_code.as_bytes()); // Shows that prefix is the first byte.
    let decoded: ScriptBuf = encode::deserialize(&encoded).unwrap();
    assert_eq!(decoded, script_code);

    // to/from bytes excludes the prefix, these are not encoding/decoding functions so this is sane.
    let bytes = script_code.to_bytes();
    let got = ScriptBuf::from_bytes(bytes);
    assert_eq!(got, script_code);
}
