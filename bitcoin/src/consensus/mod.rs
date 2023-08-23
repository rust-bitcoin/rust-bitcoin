// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod decode;
pub mod encode;
mod impls;
pub mod params;
#[cfg(feature = "serde")]
pub mod serde;
mod types;
#[cfg(feature = "bitcoinconsensus")]
pub mod validation;

use crate::io::Cursor;
use crate::prelude::*;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{Decodable, Encodable, ReadExt, WriteExt},
    params::Params,
    types::{CheckedData, VarInt},
};
#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};

/// Encodes an object into a vector.
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).expect("in-memory writers don't error");
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encodes an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data).to_lower_hex_string()
}

/// Deserializes an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, decode::Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(decode::Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// Deserializes an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), decode::Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode_from_finite_reader(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}
