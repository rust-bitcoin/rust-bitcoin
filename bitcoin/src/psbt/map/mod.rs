// SPDX-License-Identifier: CC0-1.0

//! Implementation of the "maps" concept defined in BIP-174.
//!
//! > The Partially Signed Bitcoin Transaction (PSBT) format consists of key-value maps.
//! > ...
//! > `<global-map> := <keypair>* 0x00`
//! > `<input-map> := <keypair>* 0x00`
//! > `<output-map> := <keypair>* 0x00`
//! > ...

/// The `global-map`.
mod global;
/// The `input-map`.
mod input;
/// The `output-map`.
mod output;

use crate::prelude::Vec;
use crate::psbt::raw;
use crate::psbt::serialize::Serialize;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    input::{Input, PsbtSighashType},
    output::Output,
};

/// A trait that describes a PSBT key-value map.
pub(super) trait Map {
    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Vec<raw::Pair>;

    /// Serialize Psbt binary map data according to BIP-174 specification.
    ///
    /// <map> := <keypair>* 0x00
    ///
    /// Why is the separator here 0x00 instead of 0xff? The separator here is used to distinguish between each chunk of data.
    /// A separator of 0x00 would mean that the unserializer can read it as a key length of 0, which would never occur with
    /// actual keys. It can thus be used as a separator and allow for easier unserializer implementation.
    fn serialize_map(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for pair in Map::get_pairs(self) {
            buf.extend(&pair.serialize());
        }
        buf.push(0x00_u8);
        buf
    }
}
