//! Contains extensions related to arrays.

#[cfg(creusot)]
use creusot_std::prelude::*;

/// Extension trait for arrays.
pub trait ArrayExt {
    /// The item type the array is storing.
    type Item;

    /// How long the array is. Only needed by creusot.
    #[cfg(creusot)]
    const ARR_LEN: usize;

    /// Just like the slicing operation, this returns an array `LEN` items long at position
    /// `OFFSET`.
    ///
    /// The correctness of this operation is compile-time checked.
    ///
    /// Note that unlike slicing where the second number is the end index, here the second number
    /// is array length!
    #[cfg_attr(creusot, requires(OFFSET@ + LEN@ <= Self::ARR_LEN@))]
    fn sub_array<const OFFSET: usize, const LEN: usize>(&self) -> &[Self::Item; LEN];

    /// Returns an item at given statically-known index.
    ///
    /// This is just like normal indexing except the check happens at compile time.
    #[cfg_attr(creusot, requires(INDEX@ < Self::ARR_LEN@))]
    fn get_static<const INDEX: usize>(&self) -> &Self::Item { &self.sub_array::<INDEX, 1>()[0] }

    /// Returns the first item in an array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name intentionally shadows the `std`'s `first` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    #[cfg_attr(creusot, requires(Self::ARR_LEN@ > 0))]
    fn first(&self) -> &Self::Item { self.get_static::<0>() }

    /// Splits the array into two, non-overlapping smaller arrays covering the entire range.
    ///
    /// This is almost equivalent to just calling [`sub_array`](Self::sub_array) twice, except it also
    /// checks that the arrays don't overlap and that they cover the full range. This is very useful
    /// for demonstrating correctness, especially when chained. Using this technique even revealed
    /// a bug in the past. ([#4195](https://github.com/rust-bitcoin/rust-bitcoin/issues/4195))
    #[cfg_attr(creusot, requires(LEFT@ + RIGHT@ == Self::ARR_LEN@))]
    fn split_array<const LEFT: usize, const RIGHT: usize>(
        &self,
    ) -> (&[Self::Item; LEFT], &[Self::Item; RIGHT]);

    /// Splits the array into the first element and the remaining, one element shorter, array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name intentionally shadows the `std`'s `split_first` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    #[cfg_attr(creusot, requires(RIGHT@ + 1 == Self::ARR_LEN@))]
    fn split_first<const RIGHT: usize>(&self) -> (&Self::Item, &[Self::Item; RIGHT]) {
        let (first, remaining) = self.split_array::<1, RIGHT>();
        (&first[0], remaining)
    }

    /// Splits the array into the last element and the remaining, one element shorter, array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name intentionally shadows the `std`'s `split_last` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    ///
    /// The returned tuple is also reversed just as `std` for consistency and simpler diffs when
    /// migrating.
    #[cfg_attr(creusot, requires(LEFT@ + 1 == Self::ARR_LEN@))]
    fn split_last<const LEFT: usize>(&self) -> (&Self::Item, &[Self::Item; LEFT]) {
        let (remaining, last) = self.split_array::<LEFT, 1>();
        (&last[0], remaining)
    }
}

impl<const N: usize, T> ArrayExt for [T; N] {
    type Item = T;

    #[cfg(creusot)]
    const ARR_LEN: usize = N;

    #[cfg_attr(creusot, requires(OFFSET@ + LEN@ <= N@))]
    #[cfg_attr(creusot, ensures(result@ == self@.subsequence(OFFSET@, OFFSET@ + LEN@)))]
    fn sub_array<const OFFSET: usize, const LEN: usize>(&self) -> &[Self::Item; LEN] {
        #[allow(clippy::let_unit_value)]
        let () = Hack::<N, OFFSET, LEN>::IS_VALID_RANGE;

        self.as_slice()[OFFSET..(OFFSET + LEN)]
            .try_into()
            .expect("this is also compiler-checked above")
    }

    #[cfg_attr(creusot, requires(LEFT@ + RIGHT@ == N@))]
    #[cfg_attr(creusot, ensures(result.0@ == self@.subsequence(0, LEFT@)))]
    #[cfg_attr(creusot, ensures(result.1@ == self@.subsequence(LEFT@, N@)))]
    fn split_array<const LEFT: usize, const RIGHT: usize>(
        &self,
    ) -> (&[Self::Item; LEFT], &[Self::Item; RIGHT]) {
        #[allow(clippy::let_unit_value)]
        let () = Hack2::<N, LEFT, RIGHT>::IS_FULL_RANGE;

        (self.sub_array::<0, LEFT>(), self.sub_array::<LEFT, RIGHT>())
    }
}

struct Hack<const N: usize, const OFFSET: usize, const LEN: usize>;

impl<const N: usize, const OFFSET: usize, const LEN: usize> Hack<N, OFFSET, LEN> {
    const IS_VALID_RANGE: () = assert!(OFFSET + LEN <= N);
}

struct Hack2<const N: usize, const LEFT: usize, const RIGHT: usize>;

impl<const N: usize, const LEFT: usize, const RIGHT: usize> Hack2<N, LEFT, RIGHT> {
    const IS_FULL_RANGE: () = assert!(LEFT + RIGHT == N);
}
