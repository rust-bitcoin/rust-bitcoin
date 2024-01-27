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

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    encode::{deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt},
    params::Params,
};

#[cfg(feature = "bitcoinconsensus")]
#[doc(inline)]
#[deprecated(since = "TBD" , note = "available at the crate root and also from the bitcoin::validation module")]
pub use crate::validation::{
    verify_script, verify_script_with_flags, verify_transaction, verify_transaction_with_flags,
};
