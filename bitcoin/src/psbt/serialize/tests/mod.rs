#![cfg(all(feature = "std", feature = "base64"))]
// Functions in this file are all used but clippy complains still.
#![allow(dead_code)]

mod bip174_parse_invalid;
mod bip174_parse_valid;
mod bip370_parse_invalid;
mod bip370_parse_valid;
mod serialize;

use hex::FromHex;

use crate::psbt::serialize::{Error, Psbt};

#[track_caller]
pub fn hex_psbt(s: &str) -> Result<Psbt, Error> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    let psbt = match r {
        Err(_e) => panic!("unable to parse PSBT v0 from hex string {}", s),
        Ok(v) => Psbt::deserialize(&v)?,
    };
    Ok(psbt)
}

#[track_caller]
pub fn assert_valid_v0(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt(hex) {
        println!("Parse PSBT v0 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    let psbt = base64.parse::<Psbt>().expect("failed to parse base64");
    psbt.assert_valid_v0().unwrap()
}

#[track_caller]
pub fn assert_valid_v2(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt(hex) {
        println!("Parse PSBT v2 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    let psbt = base64.parse::<Psbt>().expect("failed to parse base64");
    psbt.assert_valid_v2().unwrap()
}

#[track_caller]
pub fn is_invalid_v0(hex: &str, base64: &str) -> bool {
    // Invalid can mean either it doesn't parse or its not valid v0 (ie its v2).
    if let Ok(psbt) = hex_psbt(hex) {
        if psbt.assert_valid_v0().is_ok() {
            return false;
        }
    }
    if let Ok(psbt) = base64.parse::<Psbt>() {
        if psbt.assert_valid_v0().is_ok() {
            return false;
        }
    }
    true
}

#[track_caller]
pub fn is_invalid_v2(hex: &str, base64: &str) -> bool {
    // Invalid can mean either it doesn't parse or its not valid v2 (ie its v0).
    if let Ok(psbt) = hex_psbt(hex) {
        if psbt.assert_valid_v2().is_ok() {
            return false;
        }
    }
    if let Ok(psbt) = base64.parse::<Psbt>() {
        if psbt.assert_valid_v2().is_ok() {
            return false;
        }
    }
    true
}
