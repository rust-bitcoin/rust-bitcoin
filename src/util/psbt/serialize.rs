//! # PSBT Serialization
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes in PSBT key-value pairs.

use blockdata::transaction::Transaction;
use consensus::encode;

/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error>;
}

impl_psbt_de_serialize!(Transaction);
