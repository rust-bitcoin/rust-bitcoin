// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Thin vectors
//!
//! A vector type designed to take as little memory as possible by limiting
//! its size to 4bn elements and not distinguishing between size and capacity.
//! It is very easy to read uninitialized memory: make sure you assign all
//! values after calling `reserve` or `with_capacity`.
//!

use alloc::heap::{allocate, reallocate, deallocate};
use std::raw;
use std::slice::{Iter, MutIter};
use std::{fmt, mem, ptr};
use std::u32;

/// A vector type designed to take very little memory
pub struct ThinVec<T> {
  ptr: *mut T,
  cap: u32  // capacity and length are the same
}

impl<T> ThinVec<T> {
  /// Constructor
  #[inline]
  pub fn new() -> ThinVec<T> { ThinVec { ptr: RawPtr::null(), cap: 0 } }

  /// Constructor with predetermined capacity
  #[inline]
  pub unsafe fn with_capacity(capacity: u32) -> ThinVec<T> {
    if mem::size_of::<T>() == 0 {
      ThinVec { ptr: RawPtr::null(), cap: capacity }
    } else if capacity == 0 {
      ThinVec::new()
    } else {
      let size = (capacity as usize).checked_mul(&mem::size_of::<T>())
                   .expect("ThinVec::reserve: capacity overflow");
      let ptr = allocate(size, mem::min_align_of::<T>());
      ThinVec { ptr: ptr as *mut T, cap: capacity }
    }
  }

  /// Constructor from an ordinary vector
  #[inline]
  pub fn from_vec(mut v: Vec<T>) -> ThinVec<T> {
    v.shrink_to_fit();
    assert!(v.len() <= u32::MAX as usize);
    let ret = ThinVec { ptr: v.as_mut_ptr(), cap: v.len() as u32 };
    unsafe { mem::forget(v); }
    ret
  }

  /// Iterator over elements of the vector
  #[inline]
  pub fn iter<'a>(&'a self) -> Iter<'a, T> {
    self.as_slice().iter()
  }

  /// Mutable iterator over elements of the vector
  #[inline]
  pub fn iter_mut<'a>(&'a mut self) -> MutIter<'a, T> {
    self.as_mut_slice().iter_mut()
  }

  /// Get vector as mutable slice
  #[inline]
  pub fn as_mut_slice<'a>(&'a mut self) -> &'a mut [T] {
    unsafe { mem::transmute(raw::Slice { data: self.ptr as *const T, len: self.cap as usize }) }
  }

  /// Accessor
  #[inline]
  pub unsafe fn get<'a>(&'a self, index: usize) -> &'a T {
    &self.as_slice()[index]
  }

  /// Mutable accessor NOT for first use
  #[inline]
  pub unsafe fn get_mut<'a>(&'a mut self, index: usize) -> &'a mut T {
    &mut self.as_mut_slice()[index]
  }

  /// Mutable accessor for first use
  #[inline]
  pub unsafe fn init<'a>(&'a mut self, index: usize, value: T) {
    ptr::write(&mut *self.ptr.offset(index as isize), value);
  }

  /// Returns a slice starting from `index`
  #[inline]
  pub fn slice_from<'a>(&'a self, index: usize) -> &'a [T] {
    self.as_slice().slice_from(index)
  }

  /// Returns a slice ending just before `index`
  #[inline]
  pub fn slice_to<'a>(&'a self, index: usize) -> &'a [T] {
    self.as_slice().slice_to(index)
  }

  /// Returns a slice starting from `s` ending just before `e`
  #[inline]
  pub fn slice<'a>(&'a self, s: usize, e: usize) -> &'a [T] {
    self.as_slice().slice(s, e)
  }

  /// Push: always reallocates, try not to use this
  #[inline]
  pub fn push(&mut self, value: T) {
    self.cap = self.cap.checked_add(&1).expect("ThinVec::push: length overflow");
    if mem::size_of::<T>() == 0 {
      unsafe { mem::forget(value); }
    } else {
      let old_size = (self.cap - 1) as usize * mem::size_of::<T>();
      let new_size = self.cap as usize * mem::size_of::<T>();
      if new_size < old_size { panic!("ThinVec::push: cap overflow") }
      unsafe {
        self.ptr =
          if old_size == 0 {
            allocate(new_size, mem::min_align_of::<T>()) as *mut T
          } else {
            reallocate(self.ptr as *mut u8, new_size,
                       mem::min_align_of::<T>(), self.cap as usize) as *mut T
          };
        ptr::write(&mut *self.ptr.offset((self.cap - 1) as isize), value);
      }
    }
  }

  /// Set the length of the vector to the minimum of the current capacity and new capacity
  pub unsafe fn reserve(&mut self, new_cap: u32) {
    if new_cap > self.cap {
      let new_size = (new_cap as usize).checked_mul(&mem::size_of::<T>())
                       .expect("ThinVec::reserve: capacity overflow");
      self.ptr =
        if self.cap == 0 {
          allocate(new_size, mem::min_align_of::<T>()) as *mut T
        } else {
          reallocate(self.ptr as *mut u8, new_size,
                     mem::min_align_of::<T>(), self.cap as usize) as *mut T
        };
      self.cap = new_cap;
    }
  }

  /// Increase the length of the vector
  pub unsafe fn reserve_additional(&mut self, extra: u32) {
    let new_cap = self.cap.checked_add(&extra).expect("ThinVec::reserve_additional: length overflow");
    self.reserve(new_cap);
  }
}

impl<T:Clone> ThinVec<T> {
  /// Push an entire slice onto the ThinVec
  #[inline]
  pub fn push_all(&mut self, other: &[T]) {
    let old_cap = self.cap as usize;
    unsafe { self.reserve_additional(other.len() as u32); }
    // Copied from vec.rs, which claims this will be optimized to a memcpy
    // if T is Copy
    for i in range(0, other.len()) {
      unsafe {
        ptr::write(self.as_mut_slice().unsafe_mut(old_cap + i),
                   other.unsafe_get(i).clone());
      }
    }
  }
}

impl<T:Clone> CloneableVector<T> for ThinVec<T> {
  fn to_vec(&self) -> Vec<T> {
    self.as_slice().to_vec()
  }

  fn into_vec(self) -> Vec<T> {
    unsafe { Vec::from_raw_parts(self.cap as usize, self.cap as usize, self.ptr) }
  }
}

impl<T> Slice<T> for ThinVec<T> {
  #[inline]
  fn as_slice<'a>(&'a self) -> &'a [T] {
    unsafe { mem::transmute(raw::Slice { data: self.ptr as *const T, len: self.cap as usize }) }
  }
}

impl<T:Clone> Clone for ThinVec<T> {
  fn clone(&self) -> ThinVec<T> {
    unsafe {
      let mut ret = ThinVec::with_capacity(self.len() as u32);
      // Copied from vec.rs, which claims this will be optimized to a memcpy
      // if T is Copy
      for i in range(0, self.len()) {
        ptr::write(ret.as_mut_slice().unsafe_mut(i),
                   self.as_slice().unsafe_get(i).clone());
      }
      ret
    }
  }

   // TODO: clone_from
}

impl<T> FromIterator<T> for ThinVec<T> {
  #[inline]
  fn from_iter<I: Iterator<T>>(iter: I) -> ThinVec<T> {
    let (lower, _) = iter.size_hint();
    assert!(lower <= u32::MAX as usize);
    unsafe {
      let mut vector = ThinVec::with_capacity(lower as u32);
      for (n, elem) in iter.enumerate() {
        if n < lower {
          vector.init(n, elem);
        } else {
          vector.push(elem);
        }
      }
      vector
    }
  }
}

impl<T> Extendable<T> for ThinVec<T> {
  #[inline]
  fn extend<I: Iterator<T>>(&mut self, iter: I) {
    let old_cap = self.cap;
    let (lower, _) = iter.size_hint();
    unsafe { self.reserve_additional(lower as u32); }
    for (n, elem) in iter.enumerate() {
      if n < lower {
        unsafe { self.init(old_cap as usize + n, elem) };
      } else {
        self.push(elem);
      }
    }
  }
}

impl<T> Collection for ThinVec<T> {
  #[inline]
  fn len(&self) -> usize { self.cap as usize }
}

impl<T:fmt::Show> fmt::Show for ThinVec<T> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    self.as_slice().fmt(f)
  }
}

impl<T: PartialEq> PartialEq for ThinVec<T> {
  #[inline]
  fn eq(&self, other: &ThinVec<T>) -> bool {
    self.as_slice() == other.as_slice()
  }
}

impl<T: Eq> Eq for ThinVec<T> {}

#[unsafe_destructor]
impl<T> Drop for ThinVec<T> {
  fn drop(&mut self) {
    if self.cap != 0 {
      unsafe {
        for x in self.as_mut_slice().iter() {
            ptr::read(x);
        }
        if mem::size_of::<T>() != 0 {
          deallocate(self.ptr as *mut u8,
                     self.cap as usize * mem::size_of::<T>(),
                     mem::min_align_of::<T>());
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::ThinVec;

  #[test]
  fn simple_destructor_thinvec_test() {
    let cap = 2;
    unsafe {
      let mut thinvec = ThinVec::with_capacity(cap);

      for i in range(0, cap) {
        thinvec.init(i, Some(Box::new(i)));
      }

      for i in range(0, cap) {
        assert_eq!(thinvec.get_mut(i).take(), Some(Box::new(i)));
        assert_eq!(thinvec.get_mut(i).take(), None); 
      }
    }
  }
}

