use consensus::encode;
use util::psbt;
use util::psbt::raw;

/// A trait that describes a PSBT key-value map.
pub trait Map {
    /// Attempt to insert a key-value pair.
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error>;

    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, encode::Error>;

    /// Attempt to merge with another key-value map of the same type.
    fn merge(&mut self, other: Self) -> Result<(), psbt::Error>;
}

// place at end to pick up macros
mod global;
mod output;

pub use self::global::Global;
pub use self::output::Output;
