// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Utility functions
//!
//! Functions needed by all parts of the Bitcoin library

pub mod address;
pub mod base58;
pub mod contracthash;
pub mod decimal;
pub mod hash;
pub mod iter;
pub mod misc;
pub mod patricia_tree;
pub mod uint;

use byteorder;
use std::io;

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;
}

/// A general error code
#[derive(Debug)]
pub enum Error {
    /// An I/O error
    Io(io::Error),
    /// Order from the `byteorder` crate
    ByteOrder(byteorder::Error),
    /// Network magic was not what we expected
    BadNetworkMagic(u32, u32),
    /// Network message was unrecognized
    BadNetworkMessage(String),
    /// An object was attempted to be added twice
    DuplicateHash,
    /// Some operation was attempted on a block (or blockheader) that doesn't exist
    BlockNotFound,
    /// Parsing error
    ParseFailed,
    /// An object was added but it does not link into existing history
    PrevHashNotFound,
    /// The `target` field of a block header did not match the expected difficulty
    SpvBadTarget,
    /// The header hash is not below the target
    SpvBadProofOfWork,
    /// Error propagated from subsystem
    Detail(String, Box<Error>)
}
display_from_debug!(Error);

/// Prepend the detail of an IoResult's error with some text to get poor man's backtracing
pub fn propagate_err<T>(s: String, res: Result<T, Error>) -> Result<T, Error> {
    res.map_err(|err| Error::Detail(s, Box::new(err)))
}


