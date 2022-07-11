// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;

use crate::io;

use crate::consensus::encode;
use crate::util::psbt::raw;

mod global;
mod input;
mod output;

pub use self::input::{Input, PsbtSighashType};
pub use self::output::{Output, TapTree, IncompleteTapTree};

/// A trait that describes a PSBT key-value map.
pub(super) trait Map {
    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, io::Error>;

    /// Encodes map data with bitcoin consensus encoding.
    fn consensus_encode_map<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for pair in Map::get_pairs(self)? {
            len += encode::Encodable::consensus_encode(&pair, w)?;
        }

        Ok(len + encode::Encodable::consensus_encode(&0x00_u8, w)?)
    }
}
