// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use prelude::*;

use io;

use consensus::encode;
use util::psbt;
use util::psbt::raw;

/// A trait that describes a PSBT key-value map.
pub trait Map {
    /// Attempt to insert a key-value pair.
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error>;

    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error>;

    /// Attempt to merge with another key-value map of the same type.
    fn merge(&mut self, other: Self) -> Result<(), psbt::Error>;

    /// Encodes map data with bitcoin consensus encoding
    fn consensus_encode_map<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, io::Error> {
        let mut len = 0;
        for pair in Map::get_pairs(self)? {
            len += encode::Encodable::consensus_encode(
                &pair,
                &mut s,
            )?;
        }

        Ok(len + encode::Encodable::consensus_encode(&0x00_u8, s)?)
    }
}

// place at end to pick up macros
mod global;
mod input;
mod output;

pub use self::input::Input;
pub use self::output::Output;
pub use self::output::TapTree;
