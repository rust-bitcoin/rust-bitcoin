//! Contains extensions related to arrays.

/// Extension trait for arrays.
pub trait ArrayExt {
    /// The item type the array is storing.
    type Item;

    /// Just like the slicing operation, this returns an array `LEN` items long at position
    /// `OFFSET`.
    ///
    /// The correctness of this operation is compile-time checked.
    ///
    /// Note that unlike slicing where the second number is the end index, here the second number
    /// is array length!
    fn sub_array<const OFFSET: usize, const LEN: usize>(&self) -> &[Self::Item; LEN];

    /// Returns an item at given statically-known index.
    ///
    /// This is just like normal indexing except the check happens at compile time.
    fn get_static<const INDEX: usize>(&self) -> &Self::Item { &self.sub_array::<INDEX, 1>()[0] }

    /// Returns the first item in an array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name is intentionally shadowing the `std`'s `first` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    fn first(&self) -> &Self::Item { self.get_static::<0>() }

    /// Splits the array into two, non-overlaping smaller arrays covering the entire range.
    ///
    /// This is almost equivalent to just calling [`sub_array`](Self::sub_array) twice, except it also
    /// checks that the arrays don't overlap and that they cover the full range. This is very useful
    /// for demonstrating correctness, especially when chained. Using this technique even revealed
    /// a bug in the past. ([#4195](https://github.com/rust-bitcoin/rust-bitcoin/issues/4195))
    fn split_array<const LEFT: usize, const RIGHT: usize>(
        &self,
    ) -> (&[Self::Item; LEFT], &[Self::Item; RIGHT]);

    /// Splits the array into the first element and the remaining, one element shorter, array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name is intentionally shadowing the `std`'s `split_first` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    fn split_first<const RIGHT: usize>(&self) -> (&Self::Item, &[Self::Item; RIGHT]) {
        let (first, remaining) = self.split_array::<1, RIGHT>();
        (&first[0], remaining)
    }

    /// Splits the array into the last element and the remaining, one element shorter, array.
    ///
    /// Fails to compile if the array is empty.
    ///
    /// Note that this method's name is intentionally shadowing the `std`'s `split_last` method which
    /// returns `Option`. The rationale is that given the known length of the array, we always know
    /// that this will not return `None` so trying to keep the `std` method around is pointless.
    /// Importing the trait will also cause compile failures - that's also intentional to expose
    /// the places where useless checks are made.
    ///
    /// The returned tuple is also reversed just as `std` for consistency and simpler diffs when
    /// migrating.
    fn split_last<const LEFT: usize>(&self) -> (&Self::Item, &[Self::Item; LEFT]) {
        let (remaining, last) = self.split_array::<LEFT, 1>();
        (&last[0], remaining)
    }
}

impl<const N: usize, T> ArrayExt for [T; N] {
    type Item = T;

    fn sub_array<const OFFSET: usize, const LEN: usize>(&self) -> &[Self::Item; LEN] {
        #[allow(clippy::let_unit_value)]
        let _ = Hack::<N, OFFSET, LEN>::IS_VALID_RANGE;

        self[OFFSET..(OFFSET + LEN)].try_into().expect("this is also compiler-checked above")
    }

    fn split_array<const LEFT: usize, const RIGHT: usize>(
        &self,
    ) -> (&[Self::Item; LEFT], &[Self::Item; RIGHT]) {
        #[allow(clippy::let_unit_value)]
        let _ = Hack2::<N, LEFT, RIGHT>::IS_FULL_RANGE;

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
