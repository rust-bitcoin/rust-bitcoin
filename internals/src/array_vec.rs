// SPDX-License-Identifier: CC0-1.0

//! A simplified `Copy` version of `arrayvec::ArrayVec`.

use core::fmt;

pub use safety_boundary::ArrayVec;

/// Limits the scope of `unsafe` auditing.
// New trait impls and fns that don't need to access internals should go below the module, not
// inside it!
mod safety_boundary {
    use core::mem::MaybeUninit;

    /// A growable contiguous collection backed by array.
    #[derive(Copy)]
    pub struct ArrayVec<T: Copy, const CAP: usize> {
        len: usize,
        data: [MaybeUninit<T>; CAP],
    }

    impl<T: Copy, const CAP: usize> ArrayVec<T, CAP> {
        /// Constructs an empty `ArrayVec`.
        pub const fn new() -> Self { Self { len: 0, data: [MaybeUninit::uninit(); CAP] } }

        /// Constructs a new `ArrayVec` initialized with the contents of `slice`.
        ///
        /// # Panics
        ///
        /// If the slice is longer than `CAP`.
        pub const fn from_slice(slice: &[T]) -> Self {
            assert!(slice.len() <= CAP);
            let mut data = [MaybeUninit::uninit(); CAP];
            let mut i = 0;
            // can't use mutable references and operators in const
            while i < slice.len() {
                data[i] = MaybeUninit::new(slice[i]);
                i += 1;
            }

            Self { len: slice.len(), data }
        }

        /// Returns a reference to the underlying data.
        pub const fn as_slice(&self) -> &[T] {
            // transmute needed; see https://github.com/rust-lang/rust/issues/63569
            // SAFETY: self.len is chosen such that everything is initialized up to len,
            //  and MaybeUninit<T> has the same representation as T.
            let ptr = self.data.as_ptr().cast::<T>();
            unsafe { core::slice::from_raw_parts(ptr, self.len) }
        }

        /// Returns a mutable reference to the underlying data.
        pub fn as_mut_slice(&mut self) -> &mut [T] {
            // SAFETY: self.len is chosen such that everything is initialized up to len,
            //  and MaybeUninit<T> has the same representation as T.
            let ptr = self.data.as_mut_ptr().cast::<T>();
            unsafe { core::slice::from_raw_parts_mut(ptr, self.len) }
        }

        /// Adds an element into `self`.
        ///
        /// # Panics
        ///
        /// If the length would increase past CAP.
        pub fn push(&mut self, element: T) {
            assert!(self.len < CAP);
            self.data[self.len] = MaybeUninit::new(element);
            self.len += 1;
        }

        /// Copies and appends all elements from `slice` into `self`.
        ///
        /// # Panics
        ///
        /// If the length would increase past CAP.
        pub fn extend_from_slice(&mut self, slice: &[T]) {
            let new_len = self.len.checked_add(slice.len()).expect("integer/buffer overflow");
            assert!(new_len <= CAP, "buffer overflow");
            // SAFETY: MaybeUninit<T> has the same layout as T
            let slice = unsafe {
                let ptr = slice.as_ptr();
                core::slice::from_raw_parts(ptr.cast::<MaybeUninit<T>>(), slice.len())
            };
            self.data[self.len..new_len].copy_from_slice(slice);
            self.len = new_len;
        }
    }
}

impl<T: Copy, const CAP: usize> Default for ArrayVec<T, CAP> {
    fn default() -> Self { Self::new() }
}

/// Clones the value *faster* than using `Copy`.
///
/// Because we avoid copying the uninitialized part of the array this copies the value faster than
/// memcpy.
#[allow(clippy::non_canonical_clone_impl)]
impl<T: Copy, const CAP: usize> Clone for ArrayVec<T, CAP> {
    fn clone(&self) -> Self { Self::from_slice(self) }
}

impl<T: Copy, const CAP: usize> core::ops::Deref for ArrayVec<T, CAP> {
    type Target = [T];

    fn deref(&self) -> &Self::Target { self.as_slice() }
}

impl<T: Copy, const CAP: usize> core::ops::DerefMut for ArrayVec<T, CAP> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_slice() }
}

impl<T: Copy + Eq, const CAP: usize> Eq for ArrayVec<T, CAP> {}

impl<T: Copy + PartialEq, const CAP1: usize, const CAP2: usize> PartialEq<ArrayVec<T, CAP2>>
    for ArrayVec<T, CAP1>
{
    fn eq(&self, other: &ArrayVec<T, CAP2>) -> bool { **self == **other }
}

impl<T: Copy + PartialEq, const CAP: usize> PartialEq<[T]> for ArrayVec<T, CAP> {
    fn eq(&self, other: &[T]) -> bool { **self == *other }
}

impl<T: Copy + PartialEq, const CAP: usize> PartialEq<ArrayVec<T, CAP>> for [T] {
    fn eq(&self, other: &ArrayVec<T, CAP>) -> bool { *self == **other }
}

impl<T: Copy + PartialEq, const CAP: usize, const LEN: usize> PartialEq<[T; LEN]>
    for ArrayVec<T, CAP>
{
    fn eq(&self, other: &[T; LEN]) -> bool { **self == *other }
}

impl<T: Copy + PartialEq, const CAP: usize, const LEN: usize> PartialEq<ArrayVec<T, CAP>>
    for [T; LEN]
{
    fn eq(&self, other: &ArrayVec<T, CAP>) -> bool { *self == **other }
}

impl<T: Copy + Ord, const CAP: usize> Ord for ArrayVec<T, CAP> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering { (**self).cmp(&**other) }
}

impl<T: Copy + PartialOrd, const CAP1: usize, const CAP2: usize> PartialOrd<ArrayVec<T, CAP2>>
    for ArrayVec<T, CAP1>
{
    fn partial_cmp(&self, other: &ArrayVec<T, CAP2>) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<T: Copy + fmt::Debug, const CAP: usize> fmt::Debug for ArrayVec<T, CAP> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(&**self, f) }
}

impl<T: Copy + core::hash::Hash, const CAP: usize> core::hash::Hash for ArrayVec<T, CAP> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state) }
}

#[cfg(test)]
mod tests {
    use super::ArrayVec;

    #[test]
    fn arrayvec_ops() {
        let mut av = ArrayVec::<_, 1>::new();
        assert!(av.is_empty());
        av.push(42);
        assert_eq!(av.len(), 1);
        assert_eq!(av, [42]);
    }

    #[test]
    #[should_panic]
    fn overflow_push() {
        let mut av = ArrayVec::<_, 0>::new();
        av.push(42);
    }

    #[test]
    #[should_panic]
    fn overflow_extend() {
        let mut av = ArrayVec::<_, 0>::new();
        av.extend_from_slice(&[42]);
    }

    #[test]
    fn extend_from_slice() {
        let mut av = ArrayVec::<u8, 8>::new();
        av.extend_from_slice(b"abc");
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::unwind(16)] // One greater than 15 (max number of elements).
    #[kani::proof]
    fn no_out_of_bounds_less_than_cap() {
        const CAP: usize = 32;
        let n = kani::any::<u32>();
        let elements = (n & 0x0F) as usize; // Just use 4 bits.

        let val = kani::any::<u32>();

        let mut v = ArrayVec::<u32, CAP>::new();
        for _ in 0..elements {
            v.push(val);
        }

        for i in 0..elements {
            assert_eq!(v[i], val);
        }
    }

    #[kani::unwind(16)] // One greater than 15.
    #[kani::proof]
    fn no_out_of_bounds_upto_cap() {
        const CAP: usize = 15;
        let elements = CAP;

        let val = kani::any::<u32>();

        let mut v = ArrayVec::<u32, CAP>::new();
        for _ in 0..elements {
            v.push(val);
        }

        for i in 0..elements {
            assert_eq!(v[i], val);
        }
    }
}
