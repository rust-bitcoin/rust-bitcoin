// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;
#[cfg(feature = "serde")]
pub mod serde;
#[cfg(feature = "bitcoinconsensus")]
pub mod validation;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, serialize_hex, Decodable, Encodable, ReadExt, WriteExt, CheckedData, MAX_VEC_SIZE, Error},
    params::Params,
};

#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
pub use self::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};
