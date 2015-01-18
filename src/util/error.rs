// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Error codes
//!
//! Various utility functions

use std::io::IoError;

/// A success/failure return value
pub type BitcoinResult<T> = Result<T, BitcoinError>;

/// A general error code
#[deriving(PartialEq, Eq, Show, Clone)]
pub enum BitcoinError {
  /// An I/O error
  InputOutput(IoError),
  /// An object was attempted to be added twice
  DuplicateHash,
  /// Some operation was attempted on a block (or blockheader) that doesn't exist
  BlockNotFound,
  /// An object was added but it does not link into existing history
  PrevHashNotFound,
  /// The `target` field of a block header did not match the expected difficulty
  SpvBadTarget,
  /// The header hash is not below the target
  SpvBadProofOfWork
}


