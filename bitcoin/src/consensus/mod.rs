// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

mod encode;
mod params;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(feature = "bitcoinconsensus")]
pub mod validation;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, serialize_hex, Decodable, Encodable, Error, ReadExt, WriteExt, VarInt, CheckedData, MAX_VEC_SIZE},
    params::Params,
};

pub(crate) use self::encode::consensus_encode_with_size;
#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};
