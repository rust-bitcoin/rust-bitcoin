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

/// An iterator that just returns None
pub struct NullIterator<T>;
impl<T> Iterator<T> for NullIterator<T> {
  #[inline]
  fn next(&mut self) -> Option<T> { None }
  #[inline]
  fn size_hint(&self) -> (uint, Option<uint>) { (0, Some(0)) }
}

impl<T> NullIterator<T> {
  /// Creates a new NullIterator
  pub fn new() -> NullIterator<T> { NullIterator }
}

/// An Iterator which will give n elements of the contained iterator
/// before returning None. If the contained iterator returns None too
/// early,
pub struct FixedTake<I> {
  iter: I,
  n_elems: uint,
  is_err: bool
}

impl<T, I: Iterator<T>> Iterator<T> for FixedTake<I> {
  fn next(&mut self) -> Option<T> {
    if self.n_elems == 0 {
      None
    } else {
      self.n_elems -= 1;
      match self.iter.next() {
        Some(e) => Some(e),
        None => {
          self.is_err = true;
          None
        }
      }
    }
  }
}

impl<I> FixedTake<I> {
  /// Constructs a FixedTake iterator from an underlying iterator
  pub fn new(iter: I, n_elems: uint) -> FixedTake<I> {
    FixedTake { iter: iter, n_elems: n_elems, is_err: false }
  }

  /// Indicates whether the underlying iterator has ended early
  pub fn is_err(&self) -> bool {
    self.is_err
  }

  /// Number of remaining elements
  pub fn remaining(&self) -> uint {
    self.n_elems
  }
}

/// An iterator that returns at most `n_elems` elements, entering an error
/// state if the underlying iterator yields fewer than `n_elems` elements.
pub trait FixedTakeable<I> {
  /// Returns an iterator similar to Take but which detects if the original 
  /// iterator runs out early
  fn fixed_take(self, n_elems: uint) -> FixedTake<I>;
}

impl<T, I: Iterator<T>> FixedTakeable<I> for I {
  fn fixed_take(self, n_elems: uint) -> FixedTake<I> {
    FixedTake::new(self, n_elems)
  }
}

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

