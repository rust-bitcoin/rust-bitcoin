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

//! # Utility functions
//!
//! Functions needed by all parts of the Bitcoin library

pub mod base58;
pub mod error;
pub mod hash;
pub mod iter;
pub mod misc;
pub mod patricia_tree;
pub mod thinvec;
pub mod uint;

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

