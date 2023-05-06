// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus.
//!
//! This module defines structures, functions, and traits that are needed to
//! conform to Bitcoin consensus.
//!

pub mod encode;
pub mod params;

pub use self::encode::{
    deserialize, deserialize_partial, serialize, Decodable, Encodable, ReadExt, WriteExt,
};
pub use self::params::Params;

#[cfg(feature = "serde")]
pub mod serde;

#[cfg(feature = "bitcoinconsensus")]
mod transaction_verifier;

#[cfg(feature = "bitcoinconsensus")]
pub use transaction_verifier::{TransactionVerifier, VerificationError, InputCountMismatch, MissingUtxo};
pub use transaction_verifier::Error as TransactionError;
