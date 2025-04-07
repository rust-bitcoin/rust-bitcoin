// SPDX-License-Identifier: CC0-1.0

use bitcoin::consensus::{encode, FromHexError};
use bitcoin::key::WPubkeyHash;
use bitcoin::script::{self, ScriptExt, ScriptBufExt};
use bitcoin::ScriptBuf;

fn main() {
    let pk = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb".parse::<WPubkeyHash>().unwrap();

    let script_code = script::p2wpkh_script_code(pk);
    let hex = script_code.to_hex_string();
    let parsed = ScriptBuf::from_hex(&hex).unwrap();
    assert_eq!(parsed, script_code);

    // Writes the script as human-readable eg, OP_DUP OP_HASH160 OP_PUSHBYTES_20 ...
    let _human_readable = format!("{}", script_code);
    // We do not implement parsing scripts from human-readable format.
    // let parsed = s.parse::<ScriptBuf>().unwrap();

    // This does not include the length prefix.
    let hex_lower_hex_trait = format!("{:x}", script_code);
    println!("hex created using `LowerHex`: {}", hex_lower_hex_trait);
    // But `deserialize_hex` requires the length prefix.
    let decoded: Result<ScriptBuf, FromHexError> = encode::deserialize_hex(&hex_lower_hex_trait);
    assert!(decoded.is_err());

    // FIXME: The inherent functions are in `bitcoin` so have access to consensus encoding.
    // This also does not include the length prefix.
    let hex_inherent = script_code.to_hex_string();
    println!("hex created using inherent `to_hex_string`: {}", hex_inherent);
    let parsed = ScriptBuf::from_hex(&hex_inherent).unwrap();
    assert_eq!(parsed, script_code);

    // Cannot parse the output of `to_hex_string` using `deserialize_hex` because no length prefix.
    assert!(encode::deserialize_hex::<ScriptBuf>(&hex_inherent).is_err());

    // Encode/decode using `consensus::encode` functions.
    // This does include the length prefix.
    let encoded = encode::serialize_hex(&script_code);
    println!("hex created using consensus::encode::serialize_hex: {}", encoded);
    let decoded: ScriptBuf = encode::deserialize_hex(&encoded).unwrap();
    assert_eq!(decoded, script_code);

    // And we cannot mix these to calls because `serialize_hex` includes the length prefix
    // but `from_hex` expects no length prefix.
    let encoded = encode::serialize_hex(&script_code);
    let decoded = ScriptBuf::from_hex(&encoded).unwrap();
    assert_ne!(decoded, script_code);

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
