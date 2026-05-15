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
        #[must_use]
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

        /// Removes the last element, returning it.
        ///
        /// # Returns
        ///
        /// None if the `ArrayVec` is empty.
        pub fn pop(&mut self) -> Option<T> {
            if self.len > 0 {
                self.len -= 1;
                // SAFETY: All elements in 0..len are initialized
                let res = self.data[self.len];
                self.data[self.len] = MaybeUninit::uninit();
                Some(unsafe { res.assume_init() })
            } else {
                None
            }
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
#[allow(clippy::expl_impl_clone_on_copy)]
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
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state); }
}

#[cfg(feature = "serde")]
impl<T: Copy + crate::serde::Serialize, const CAP: usize> crate::serde::Serialize
    for ArrayVec<T, CAP>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: crate::serde::Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

#[cfg(feature = "serde")]
impl<'de, T, const CAP: usize> crate::serde::Deserialize<'de> for ArrayVec<T, CAP>
where
    T: Copy + crate::serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::marker::PhantomData;

        use crate::serde::de;

        struct Visitor<T, const CAP: usize>(PhantomData<T>);

        impl<'de, T, const CAP: usize> de::Visitor<'de> for Visitor<T, CAP>
        where
            T: Copy + crate::serde::Deserialize<'de>,
        {
            type Value = ArrayVec<T, CAP>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a sequence of at most {} elements", CAP)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                use de::Error;

                if let Some(hint) = seq.size_hint() {
                    if hint > CAP {
                        return Err(Error::invalid_length(hint, &self));
                    }
                }

                let mut out = ArrayVec::<T, CAP>::new();
                while let Some(elem) = seq.next_element::<T>()? {
                    // The `push()` call below panics if array is full but we want to error.
                    if out.len() >= CAP {
                        return Err(Error::invalid_length(out.len() + 1, &self));
                    }
                    out.push(elem);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(Visitor::<T, CAP>(PhantomData))
    }
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
    #[should_panic(expected = "assertion failed")]
    fn overflow_push() {
        let mut av = ArrayVec::<_, 0>::new();
        av.push(42);
    }

    #[test]
    #[should_panic(expected = "buffer overflow")]
    fn overflow_extend() {
        let mut av = ArrayVec::<_, 0>::new();
        av.extend_from_slice(&[42]);
    }

    #[test]
    fn extend_from_slice() {
        let mut av = ArrayVec::<u8, 8>::new();
        av.extend_from_slice(b"abc");
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_round_trip_u8() {
        let mut want = ArrayVec::<u8, 8>::new();
        want.extend_from_slice(b"abc");

        let json = crate::serde_json::to_string(&want).expect("serde_json failed to encode");
        let got: ArrayVec<u8, 8> =
            crate::serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let bin = crate::bincode::serialize(&want).expect("bincode failed to encode");
        let got: ArrayVec<u8, 8> =
            crate::bincode::deserialize(&bin).expect("bincode failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_round_trip_u32() {
        let mut want = ArrayVec::<u32, 4>::new();
        (1..=3).for_each(|i| want.push(i));

        let json = crate::serde_json::to_string(&want).expect("serde_json failed to encode");
        let got: ArrayVec<u32, 4> =
            crate::serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let bin = crate::bincode::serialize(&want).expect("bincode failed to encode");
        let got: ArrayVec<u32, 4> =
            crate::bincode::deserialize(&bin).expect("bincode failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_round_trip_empty() {
        let want = ArrayVec::<u8, 0>::new();

        let json = crate::serde_json::to_string(&want).expect("serde_json failed to encode");
        assert_eq!(json, "[]");
        let got: ArrayVec<u8, 0> =
            crate::serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_deserialize_overflow_json_returns_error() {
        // CAP=2 but JSON contains 3 elements -> must error, not panic.
        // Excercises the read-until-overflow path (no usable size_hint).
        let json = "[1,2,3]";
        let res: Result<ArrayVec<u8, 2>, _> = crate::serde_json::from_str(json);
        assert!(res.is_err(), "expected an error for over-capacity input");
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_deserialize_overflow_bincode_returns_error() {
        // Exercises the size_hint > CAP fast-reject path; bincode prefixes the
        // sequence with a length, which becomes the sze_hint on deserialize.
        let slice: &[u8] = &[1, 2, 3];
        let bin = crate::bincode::serialize(slice).expect("bincode failed to encode");
        let res: Result<ArrayVec<u8, 2>, _> = crate::bincode::deserialize(&bin);
        assert!(res.is_err(), "expected an error for over-capacity input");
    }

    #[cfg(feature = "test-serde")]
    #[test]
    fn serde_matches_vec_wire_format() {
        // Verifies the on-the-wire encoding is identical to `Vec<T>`/`&[T]` so
        // that an `ArrayVec<T, CAP>` is interchangeable with `Vec<T>` in serde.
        let slice: &[u8] = &[1, 2, 3];
        let want = ArrayVec::<u8, 8>::from_slice(slice);

        // JSON
        let av_json = crate::serde_json::to_string(&want).expect("serde_json failed to encode");
        let slice_json = crate::serde_json::to_string(slice).expect("serde_json failed to encode");
        assert_eq!(av_json, slice_json);

        // Bincode.
        let av_bin = crate::bincode::serialize(&want).expect("bincode failed to encode");
        let slice_bin = crate::bincode::serialize(slice).expect("bincode failed to encode");
        assert_eq!(av_bin, slice_bin);

        // Deserialize the slice-encoded bytes into ArrayVec.
        let got: ArrayVec<u8, 8> =
            crate::serde_json::from_str(&slice_json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let got: ArrayVec<u8, 8> =
            crate::bincode::deserialize(&slice_bin).expect("bincode failed to decode");
        assert_eq!(got, want);
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
