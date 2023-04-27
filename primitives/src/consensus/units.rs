// SPDX-License-Identifier: CC0-1.0

//! Implement `Encodable` and `Decodable` for types from the `units` crate.

use units::Amount;

use crate::consensus::{encode, Decodable, Encodable};
use crate::io::{BufRead, Write};

impl Decodable for Amount {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Amount::from_sat(Decodable::consensus_decode(r)?))
    }
}

impl Encodable for Amount {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_sat().consensus_encode(w)
    }
}
