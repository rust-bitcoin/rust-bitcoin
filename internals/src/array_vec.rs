// SPDX-License-Identifier: CC0-1.0

//! A simplified `Copy` version of `arrayvec::ArrayVec`.

use core::fmt;
use core::mem::MaybeUninit;

pub use error::CapacityExceededError;
pub use safety_boundary::ArrayVec;
#[cfg(creusot)]
use creusot_std::prelude::*;

/// Limits the scope of `unsafe` auditing.
// New trait impls and fns that don't need to access internals should go below the module, not
// inside it!
mod safety_boundary {
    #[cfg(creusot)]
    use creusot_std::prelude::*;

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
        #[cfg_attr(creusot, check(ghost))]
        #[cfg_attr(creusot, requires(slice@.len() <= CAP@))]
        #[cfg_attr(creusot, ensures(result@ == slice@))]
        pub const fn from_slice(slice: &[T]) -> Self {
            assert!(slice.len() <= CAP);
            let mut data = [MaybeUninit::uninit(); CAP];
            let mut i = 0;
            // can't use mutable references and operators in const
            #[cfg_attr(creusot, invariant(forall<j> j >= 0 && j < i@ ==> data@[j]@ == Some(slice@[j])))]
            #[cfg_attr(creusot, variant(slice@.len() - i@))]
            while i < slice.len() {
                data[i] = MaybeUninit::new(slice[i]);
                i += 1;
            }

            Self { len: slice.len(), data }
        }

        /// Returns a reference to the underlying data.
        #[cfg_attr(creusot, check(ghost))]
        #[cfg_attr(creusot, ensures(self@ == result@))]
        #[cfg_attr(creusot, ensures(result@.len() == self.len_view()))]
        #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < self.len_view() ==> self.buf_view()[i]@ == Some((*result)@[i])))]
        pub const fn as_slice(&self) -> &[T] {
            // SAFETY: self.len is chosen such that everything is initialized up to len
            unsafe {
                if self.len > CAP { core::hint::unreachable_unchecked() }
                super::slice_assume_init_ref(self.data.split_at(self.len).0)
            }
        }

        /// Returns a mutable reference to the underlying data.
        #[cfg_attr(creusot, check(ghost))]
        #[cfg_attr(creusot, ensures(result@.len() == self.len_view()))]
        #[cfg_attr(creusot, ensures((*self)@.len() == (^self)@.len()))]
        #[cfg_attr(creusot, ensures((*result)@.len() == (^result)@.len()))]
        #[cfg_attr(creusot, ensures(self@ == result@))]
        #[cfg_attr(creusot, ensures((^self)@ == (^result)@))]
        #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < self.len_view() ==> (*self).buf_view()[i]@ == Some((*result)@[i]) && (^self).buf_view()[i]@ == Some((^result)@[i])))]
        #[cfg_attr(creusot, ensures(forall<i> i >= self@.len() && i < CAP@ ==> (^self).buf_view()[i] == (*self).buf_view()[i]))]
        pub fn as_mut_slice(&mut self) -> &mut [T] {
            // SAFETY: self.len is chosen such that everything is initialized up to len
            unsafe {
                if self.len > CAP { core::hint::unreachable_unchecked() }
                super::slice_assume_init_mut(self.data.split_at_mut(self.len).0)
            }
        }

        /// Returns remaining spare capacity of the vector as a slice of `MaybeUninit<T>`.
        #[cfg_attr(creusot, ensures((^self)@ == (*self)@))]
        #[cfg_attr(creusot, ensures((*result)@.len() == CAP@ - self@.len()))]
        #[cfg_attr(creusot, ensures((^result)@.len() == CAP@ - self@.len()))]
        #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < CAP@ - self@.len() ==> (*result)[i] == (*self).buf_view()[self@.len() + i]))]
        #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < CAP@ - self@.len() ==> (^result)[i] == (^self).buf_view()[self@.len() + i]))]
        pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
            // SOUNDNESS: self.len <= CAP is the invariant on the type
            unsafe { self.data.get_unchecked_mut(self.len..) }
        }

        /// Forces the length to `new_len`.
        ///
        /// # Safety
        ///
        /// * `new_len` must be less than or equal to `CAP`.
        /// * All elements up to `new_len` must be initialized.
        #[cfg_attr(creusot, requires(new_len <= CAP))]
        #[cfg_attr(creusot, requires(forall<i> i >= 0 && i < new_len@ ==> match (*self).buf_view()[i]@ { Some(x) => inv(x), None => false }))]
        #[cfg_attr(creusot, ensures((^self)@.len() == new_len@))]
        #[cfg_attr(creusot, ensures((^self).buf_view() == (*self).buf_view()))]
        #[cfg_attr(creusot, ensures((^self).len_view() == new_len@))]
        pub unsafe fn set_len(&mut self, new_len: usize) {
            debug_assert!(new_len <= CAP);
            self.len = new_len;
        }

        #[cfg(creusot)]
        #[logic(inline)]
        #[ensures(inv(self) ==> result.len() == CAP@)]
        pub fn buf_view(self) -> Seq<MaybeUninit<T>> {
            self.data.view()
        }

        #[cfg(creusot)]
        #[logic]
        #[ensures(inv(self) ==> result <= CAP@)]
        pub fn len_view(self) -> Int {
            self.len.view()
        }
    }

    #[cfg(creusot)]
    impl<T: Copy, const CAP: usize> Invariant for ArrayVec<T, CAP> {
        #[logic(prophetic, inline)]
        fn invariant(self) -> bool {
            pearlite! {
                self.len <= CAP && forall<i: Int> 0 <= i && i < self.len@ ==> match self.data@[i]@ { Some(x) => inv(x), None => false }
            }
        }
    }

    #[cfg(creusot)]
    impl<T: Copy, const CAP: usize> View for ArrayVec<T, CAP> {
        type ViewTy = Seq<T>;

        #[logic(inline)]
        #[ensures(inv(self) ==> result.len() <= CAP@)]
        #[ensures(inv(self) ==> forall<i> i >= 0 && i < result.len() ==> self.buf_view()[i]@ == Some(result[i]))]
        #[ensures(inv(self) ==> result.len() == self.len_view())]
        fn view(self) -> Self::ViewTy {
            pearlite! {
                self.buf_view()
                    .subsequence(0, self.len@)
                    .map(|x: MaybeUninit<T>| {
                        match x@ {
                            Some(x) => x,
                            None => creusot_std::logic::any(),
                        }
                    })
            }
        }
    }

    #[cfg(creusot)]
    impl<T: Copy + DeepModel, const CAP: usize> DeepModel for ArrayVec<T, CAP> {
        type DeepModelTy = Seq<T::DeepModelTy>;

        #[logic(open, inline)]
        #[ensures(self@.len() == result.len())]
        #[ensures(forall<i> 0 <= i && i < self@.len() ==> result[i] == self@[i].deep_model())]
        fn deep_model(self) -> Self::DeepModelTy {
            pearlite! {
                self@.map(|x: T| x.deep_model())
            }
        }
    }
}

// Polyfill because creusot doesn't support pointer casting and we need const, pre-1.93 MSRV, and
// check(ghost)
#[cfg_attr(creusot, check(ghost))]
#[cfg_attr(creusot, requires(forall<i> i >= 0 && i < slice@.len() ==> match slice[i]@ { Some(_) => true, None => false }))]
#[cfg_attr(creusot, ensures(slice@.len() == result@.len()))]
#[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < slice@.len() ==> slice@[i]@ == Some(result@[i])))]
const unsafe fn slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    #[cfg(creusot)]
    {
        // SAFETY: the caller must guarantee correctness
        unsafe { slice.assume_init_ref() }
    }
    #[cfg(not(creusot))]
    {
        // SAFETY: the caller must guarantee correctness and the code is literally the copy of
        // `assume_init_ref` from std.
        unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
    }
}

// Same reason as above except here we don't have `const` as it's currently not needed even though
// we could theoretically have it conditional on sufficiently recent Rust version.
#[cfg_attr(creusot, check(ghost))]
#[cfg_attr(creusot, requires(forall<i> 0 <= i && i < slice@.len() ==> (*slice)[i]@ != None))]
#[cfg_attr(creusot, ensures((*slice)@.len() == (*result)@.len()))]
#[cfg_attr(creusot, ensures((^slice)@.len() == (^result)@.len()))]
#[cfg_attr(creusot, ensures((*result)@.len() == (^result)@.len()))]
#[cfg_attr(creusot, ensures(forall<i> 0 <= i && i < slice@.len() ==> (*slice)[i]@ == Some((*result)[i])))]
#[cfg_attr(creusot, ensures(forall<i> 0 <= i && i < slice@.len() ==> (^slice)[i]@ == Some((^result)[i])))]
unsafe fn slice_assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    #[cfg(creusot)]
    {
        // SAFETY: the caller must guarantee correctness
        unsafe { slice.assume_init_mut() }
    }
    #[cfg(not(creusot))]
    {
        // SAFETY: the caller must guarantee correctness and the code is literally the copy of
        // `assume_init_mut` from std.
        unsafe { &mut *(slice as *mut [MaybeUninit<T>] as *mut [T]) }
    }
}

// Same reason as above
#[cfg_attr(creusot, check(ghost))]
#[cfg_attr(creusot, requires(dest@.len() == src@.len()))]
#[cfg_attr(creusot, ensures((^dest)@.len() == (*dest)@.len()))]
#[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < dest@.len() ==> (^dest)@[i]@ == Some(src[i])))]
fn write_copy_of_slice<T: Copy>(dest: &mut [MaybeUninit<T>], src: &[T]) {
    #[cfg(creusot)]
    {
        dest.write_copy_of_slice(src);
    }
    #[cfg(not(creusot))]
    // We want to use std's code verbatim
    #[allow(clippy::transmute_ptr_to_ptr)]
    {
        // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout
        let uninit_src: &[MaybeUninit<T>] = unsafe { core::mem::transmute(src) };
        dest.copy_from_slice(uninit_src);
    }
}

impl<T: Copy, const CAP: usize> ArrayVec<T, CAP> {
    /// Adds an element into `self`.
    ///
    /// # Panics
    ///
    /// If the length would increase past CAP.
    #[track_caller]
    #[cfg_attr(creusot, requires(self@.len() < CAP@))]
    #[cfg_attr(creusot, ensures((^self)@ == self@.push_back(element)))]
    pub fn push(&mut self, element: T) {
        self.try_push(element).expect("push past the capacity of the array");
    }

    /// Adds an element into `self`.
    ///
    /// # Errors
    ///
    /// Returns error if the `ArrayVec` is full.
    #[cfg_attr(creusot, ensures(self@.len() < CAP@ ==> (^self)@ == self@.push_back(element) && result == Ok(())))]
    #[cfg_attr(creusot, ensures(self@.len() == CAP@ ==> (^self)@ == (*self)@ && match result { Ok(()) => false, Err(_) => true }))]
    pub fn try_push(&mut self, element: T) -> Result<(), CapacityExceededError> {
        let first = self.spare_capacity_mut().first_mut().ok_or(CapacityExceededError { capacity: CAP })?;
        *first = MaybeUninit::new(element);
        let old_len = self.len();
        // SOUNDNESS:
        // * first being non-None implies the element exists therefore one-past the length <=
        //   CAP
        // * all elements up to old_len were already filled and we just added one
        unsafe {
            self.set_len(old_len + 1);
        }
        Ok(())
    }

    /// Removes the last element, returning it.
    ///
    /// # Returns
    ///
    /// None if the `ArrayVec` is empty.
    #[cfg_attr(creusot, ensures(self@.len() == 0 ==> result == None))]
    #[cfg_attr(creusot, ensures(self@.len() == 0 ==> (^self) == (*self)))]
    #[cfg_attr(creusot, ensures(self@.len() > 0 ==> result == Some(self@[self@.len() - 1])))]
    #[cfg_attr(creusot, ensures(self@.len() > 0 ==> (^self)@ == (*self)@.subsequence(0, (*self)@.len() - 1)))]
    pub fn pop(&mut self) -> Option<T> {
        let slice = self.as_slice();
        let res = *slice.last()?;
        let old_len = slice.len();
        // SOUNDNESS:
        // * decreasing the already-valid len keeps the len <= CAP invariant
        // * decreasing the already-valid len does not mark any new elements as initialized
        unsafe { self.set_len(old_len - 1) }
        Some(res)
    }

    /// Copies and appends all elements from `slice` into `self`.
    ///
    /// # Panics
    ///
    /// If the length would increase past CAP.
    #[cfg_attr(creusot, requires(slice@.len() <= CAP@ - self@.len()))]
    #[cfg_attr(creusot, ensures((^self)@ == (*self)@.concat(slice@)))]
    pub fn extend_from_slice(&mut self, slice: &[T]) {
        let dst = self.spare_capacity_mut()
            .get_mut(..slice.len())
            .expect("buffer overflow");
        write_copy_of_slice(dst, slice);
        let old_len = self.len();
        unsafe { self.set_len(old_len + slice.len()) }
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
    #[cfg_attr(creusot, ensures(result@ == self@))]
    fn clone(&self) -> Self { Self::from_slice(self) }
}

impl<T: Copy, const CAP: usize> core::ops::Deref for ArrayVec<T, CAP> {
    type Target = [T];

    #[cfg_attr(creusot, check(ghost))]
    #[cfg_attr(creusot, ensures(self@ == result@))]
    #[cfg_attr(creusot, ensures(result@.len() == self.len_view()))]
    #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < self.len_view() ==> self.buf_view()[i]@ == Some((*result)@[i])))]
    fn deref(&self) -> &Self::Target { self.as_slice() }
}

impl<T: Copy, const CAP: usize> core::ops::DerefMut for ArrayVec<T, CAP> {
    #[cfg_attr(creusot, check(ghost))]
    #[cfg_attr(creusot, ensures(result@.len() == self.len_view()))]
    #[cfg_attr(creusot, ensures((*self)@.len() == (^self)@.len()))]
    #[cfg_attr(creusot, ensures((*result)@.len() == (^result)@.len()))]
    #[cfg_attr(creusot, ensures(self@ == result@))]
    #[cfg_attr(creusot, ensures((^self)@ == (^result)@))]
    #[cfg_attr(creusot, ensures(forall<i> i >= 0 && i < self.len_view() ==> (*self).buf_view()[i]@ == Some((*result)@[i]) && (^self).buf_view()[i]@ == Some((^result)@[i])))]
    #[cfg_attr(creusot, ensures(forall<i> i >= self@.len() && i < CAP@ ==> (^self).buf_view()[i] == (*self).buf_view()[i]))]
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_slice() }
}

macro_rules! with_deep_model {
    ($(impl<$param:ident: $bound:ident $(+ $bounds:ident)*, const $cap:ident: usize $(, const $cap2:ident: usize)?> $tr:ident$(<$trait_ty:ty>)? for $ty:ty { $($imp:tt)* })*) => {
        $(
        #[cfg(creusot)]
        impl<$param: $bound $(+ $bounds)* + DeepModel, const $cap: usize $(, const $cap2: usize)?> $tr $(<$trait_ty>)? for $ty {
            $($imp)*
        }

        #[cfg(not(creusot))]
        impl<$param: $bound $(+ $bounds)*, const $cap: usize $(, const $cap2: usize)?> $tr$(<$trait_ty>)? for $ty {
            $($imp)*
        }
        )*
    }
}

with_deep_model! {
impl<T: Copy + PartialEq, const CAP: usize> Eq for ArrayVec<T, CAP> {}

impl<T: Copy + PartialEq, const CAP1: usize, const CAP2: usize> PartialEq<ArrayVec<T, CAP2>>
    for ArrayVec<T, CAP1>
{
    #[cfg_attr(creusot, ensures(result == (self.deep_model() == other.deep_model())))]
    fn eq(&self, other: &ArrayVec<T, CAP2>) -> bool {
        /*
        let left = &**self;
        let right = &**other;

        proof_assert!(left@ == self@);
        proof_assert!(right@ == other@);
        left == right
        */
        **self == **other
    }
}

impl<T: Copy + PartialEq, const CAP: usize> PartialEq<[T]> for ArrayVec<T, CAP> {
    #[cfg_attr(creusot, ensures(result == (self.deep_model() == other.deep_model())))]
    fn eq(&self, other: &[T]) -> bool { **self == *other }
}

impl<T: Copy + PartialEq, const CAP: usize> PartialEq<ArrayVec<T, CAP>> for [T] {
    #[cfg_attr(creusot, ensures(result == (self.deep_model() == other.deep_model())))]
    fn eq(&self, other: &ArrayVec<T, CAP>) -> bool { *self == **other }
}

impl<T: Copy + PartialEq, const CAP: usize, const LEN: usize> PartialEq<[T; LEN]>
    for ArrayVec<T, CAP>
{
    #[cfg_attr(creusot, ensures(result == (self.deep_model() == other.deep_model())))]
    fn eq(&self, other: &[T; LEN]) -> bool { other == self }
}

impl<T: Copy + PartialEq, const CAP: usize, const LEN: usize> PartialEq<ArrayVec<T, CAP>>
    for [T; LEN]
{
    #[cfg_attr(creusot, ensures(result == (self.deep_model() == other.deep_model())))]
    fn eq(&self, other: &ArrayVec<T, CAP>) -> bool { *self == **other }
}

impl<T: Copy + Ord, const CAP: usize> Ord for ArrayVec<T, CAP> {
    #[cfg_attr(creusot, ensures(result == (*self).deep_model().cmp_log((*rhs).deep_model())))]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering { (**self).cmp(&**other) }
}

impl<T: Copy + PartialOrd, const CAP1: usize, const CAP2: usize> PartialOrd<ArrayVec<T, CAP2>>
    for ArrayVec<T, CAP1>
{
    #[cfg_attr(creusot, ensures(result == (*self).deep_model().partial_cmp_log((*rhs).deep_model())))]
    fn partial_cmp(&self, other: &ArrayVec<T, CAP2>) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}
}

impl<T: Copy + fmt::Debug, const CAP: usize> fmt::Debug for ArrayVec<T, CAP> {
    #[cfg_attr(creusot, requires(false))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(&**self, f) }
}

impl<T: Copy + core::hash::Hash, const CAP: usize> core::hash::Hash for ArrayVec<T, CAP> {
    #[cfg_attr(creusot, requires(false))]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state); }
}

/// Error types for `ArrayVec`.
pub mod error {
    use core::fmt;
    #[cfg(creusot)]
    use creusot_std::prelude::*;
    #[cfg(creusot)]
    use creusot_std::prelude::{Clone, PartialEq};

    /// Errors encountered when inserting or removing elements from an `ArrayVec`.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct CapacityExceededError {
        /// The capacity that was exceeded.
        pub(super) capacity: usize,
    }

    impl fmt::Display for CapacityExceededError {
        #[cfg_attr(creusot, requires(false))]
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Capacity exceeded: {}", self.capacity)
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CapacityExceededError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            let Self { capacity: _ } = self;
            None
        }
    }

    #[cfg(creusot)]
    impl DeepModel for CapacityExceededError {
        type DeepModelTy = Self;

        #[logic]
        fn deep_model(self) -> Self::DeepModelTy {
            self
        }
    }
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
                    out.try_push(elem).map_err(|_| Error::invalid_length(out.len() + 1, &self))?;
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
    #[should_panic(expected = "push past the capacity of the array")]
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

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_u8() {
        let mut want = ArrayVec::<u8, 8>::new();
        want.extend_from_slice(b"abc");

        let json = serde_json::to_string(&want).expect("serde_json failed to encode");
        let got: ArrayVec<u8, 8> =
            serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let bin = bincode::serialize(&want).expect("bincode failed to encode");
        let got: ArrayVec<u8, 8> = bincode::deserialize(&bin).expect("bincode failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_u32() {
        let mut want = ArrayVec::<u32, 4>::new();
        (1..=3).for_each(|i| want.push(i));

        let json = serde_json::to_string(&want).expect("serde_json failed to encode");
        let got: ArrayVec<u32, 4> =
            serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let bin = bincode::serialize(&want).expect("bincode failed to encode");
        let got: ArrayVec<u32, 4> = bincode::deserialize(&bin).expect("bincode failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_empty() {
        let want = ArrayVec::<u8, 0>::new();

        let json = serde_json::to_string(&want).expect("serde_json failed to encode");
        assert_eq!(json, "[]");
        let got: ArrayVec<u8, 0> =
            serde_json::from_str(&json).expect("serde_json failed to decode");
        assert_eq!(got, want);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialize_overflow_json_returns_error() {
        // CAP=2 but JSON contains 3 elements -> must error, not panic.
        // Excercises the read-until-overflow path (no usable size_hint).
        let json = "[1,2,3]";
        let res: Result<ArrayVec<u8, 2>, _> = serde_json::from_str(json);
        assert!(res.is_err(), "expected an error for over-capacity input");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_deserialize_overflow_bincode_returns_error() {
        // Exercises the size_hint > CAP fast-reject path; bincode prefixes the
        // sequence with a length, which becomes the sze_hint on deserialize.
        let slice: &[u8] = &[1, 2, 3];
        let bin = bincode::serialize(slice).expect("bincode failed to encode");
        let res: Result<ArrayVec<u8, 2>, _> = bincode::deserialize(&bin);
        assert!(res.is_err(), "expected an error for over-capacity input");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_matches_vec_wire_format() {
        // Verifies the on-the-wire encoding is identical to `Vec<T>`/`&[T]` so
        // that an `ArrayVec<T, CAP>` is interchangeable with `Vec<T>` in serde.
        let slice: &[u8] = &[1, 2, 3];
        let want = ArrayVec::<u8, 8>::from_slice(slice);

        // JSON
        let av_json = serde_json::to_string(&want).expect("serde_json failed to encode");
        let slice_json = serde_json::to_string(slice).expect("serde_json failed to encode");
        assert_eq!(av_json, slice_json);

        // Bincode.
        let av_bin = bincode::serialize(&want).expect("bincode failed to encode");
        let slice_bin = bincode::serialize(slice).expect("bincode failed to encode");
        assert_eq!(av_bin, slice_bin);

        // Deserialize the slice-encoded bytes into ArrayVec.
        let got: ArrayVec<u8, 8> =
            serde_json::from_str(&slice_json).expect("serde_json failed to decode");
        assert_eq!(got, want);

        let got: ArrayVec<u8, 8> =
            bincode::deserialize(&slice_bin).expect("bincode failed to decode");
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
