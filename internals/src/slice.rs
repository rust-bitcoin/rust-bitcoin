//! Contains extensions related to slices.

/// Extension trait for slice.
pub trait SliceExt {
    /// The item type the slice is storing.
    type Item;

    /// Splits up the slice into a slice of arrays and a remainder.
    ///
    /// Note that `N` must not be zero:
    ///
    /// ```compile_fail
    /// let slice = [1, 2, 3];
    /// let fail = slice.as_chunks::<0>();
    /// ```
    fn bitcoin_as_chunks<const N: usize>(&self) -> (&[[Self::Item; N]], &[Self::Item]);

    /// Splits up the slice into a slice of arrays and a remainder.
    ///
    /// Note that `N` must not be zero:
    ///
    /// ```compile_fail
    /// let mut slice = [1, 2, 3];
    /// let fail = slice.as_chunks_mut::<0>();
    /// ```
    fn bitcoin_as_chunks_mut<const N: usize>(
        &mut self,
    ) -> (&mut [[Self::Item; N]], &mut [Self::Item]);
}

impl<T> SliceExt for [T] {
    type Item = T;

    fn bitcoin_as_chunks<const N: usize>(&self) -> (&[[Self::Item; N]], &[Self::Item]) {
        #[allow(clippy::let_unit_value)]
        let _ = Hack::<N>::IS_NONZERO;

        let chunks_count = self.len() / N;
        let total_left_len = chunks_count * N;
        let (left, right) = self.split_at(total_left_len);
        // SAFETY: we've obtained the pointer from a slice that's still live
        // we're merely casting, so no aliasing issues here
        // arrays of T have same alignment as T
        // the resulting slice points within the obtained slice as was computed above
        let left = unsafe {
            core::slice::from_raw_parts(left.as_ptr().cast::<[Self::Item; N]>(), chunks_count)
        };
        (left, right)
    }

    fn bitcoin_as_chunks_mut<const N: usize>(
        &mut self,
    ) -> (&mut [[Self::Item; N]], &mut [Self::Item]) {
        #[allow(clippy::let_unit_value)]
        let _ = Hack::<N>::IS_NONZERO;

        let chunks_count = self.len() / N;
        let total_left_len = chunks_count * N;
        let (left, right) = self.split_at_mut(total_left_len);
        // SAFETY: we've obtained the pointer from a slice that's still live
        // we're merely casting, so no aliasing issues here
        // arrays of T have same alignment as T
        // the resulting slice points within the obtained slice as was computed above
        let left = unsafe {
            core::slice::from_raw_parts_mut(
                left.as_mut_ptr().cast::<[Self::Item; N]>(),
                chunks_count,
            )
        };
        (left, right)
    }
}

struct Hack<const N: usize>;

impl<const N: usize> Hack<N> {
    const IS_NONZERO: () = {
        assert!(N != 0);
    };
}

#[cfg(test)]
mod tests {
    use super::SliceExt;

    // some comparisons require type annotations
    const EMPTY: &[i32] = &[];

    #[test]
    fn one_to_one() {
        let slice = [1];
        let (left, right) = slice.bitcoin_as_chunks::<1>();
        assert_eq!(left, &[[1]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn one_to_two() {
        const EMPTY_LEFT: &[[i32; 2]] = &[];

        let slice = [1i32];
        let (left, right) = slice.bitcoin_as_chunks::<2>();
        assert_eq!(left, EMPTY_LEFT);
        assert_eq!(right, &[1]);
    }

    #[test]
    fn two_to_one() {
        let slice = [1, 2];
        let (left, right) = slice.bitcoin_as_chunks::<1>();
        assert_eq!(left, &[[1], [2]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn two_to_two() {
        let slice = [1, 2];
        let (left, right) = slice.bitcoin_as_chunks::<2>();
        assert_eq!(left, &[[1, 2]]);
        assert_eq!(right, EMPTY);
    }

    #[test]
    fn three_to_two() {
        let slice = [1, 2, 3];
        let (left, right) = slice.bitcoin_as_chunks::<2>();
        assert_eq!(left, &[[1, 2]]);
        assert_eq!(right, &[3]);
    }
}
