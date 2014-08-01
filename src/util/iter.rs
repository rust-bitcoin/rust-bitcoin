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

//! # Iterator adaptors
//!
//! Iterator adaptors needed by Bitcoin but not provided by the Rust
//! standard library.

/// An iterator that returns pairs of elements
pub struct Pair<A, I> {
  iter: I,
  last_elem: Option<A>
}

impl<A, I: Iterator<A>> Iterator<(A, A)> for Pair<A, I> {
  #[inline]
  fn next(&mut self) -> Option<(A, A)> {
    let elem1 = self.iter.next();
    if elem1.is_none() {
      None
    } else {
      let elem2 = self.iter.next();
      if elem2.is_none() {
        self.last_elem = elem1;
        None
      } else {
        Some((elem1.unwrap(), elem2.unwrap()))
      }
    }
  }

  #[inline]
  fn size_hint(&self) -> (uint, Option<uint>) {
    match self.iter.size_hint() {
      (n, None) => (n/2, None),
      (n, Some(m)) => (n/2, Some(m/2))
    }
  }
}

impl<A, I: Iterator<A>> Pair<A, I> {
  /// Returns the last element of the iterator if there were an odd
  /// number of elements remaining before it was Pair-ified.
  #[inline]
  pub fn remainder(self) -> Option<A> {
    self.last_elem
  }
}

/// Returns an iterator that returns elements of the original iterator 2 at a time
pub trait Pairable<A> {
  /// Returns an iterator that returns elements of the original iterator 2 at a time
  fn pair(self) -> Pair<A, Self>;
}

impl<A, I: Iterator<A>> Pairable<A> for I {
  /// Creates an iterator that yields pairs ef elements from the underlying
  /// iterator, yielding `None` when there are fewer than two elements to
  /// return.
  #[inline]
  fn pair(self) -> Pair<A, I> {
    Pair{iter: self, last_elem: None}
  }
}

