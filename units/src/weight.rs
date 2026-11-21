// SPDX-License-Identifier: CC0-1.0

//! Provides type [`Weight`] that represents weight units in Bitcoin's weight metric.
//!
//! Forwarded from `bitcoin-units` 0.5.0 (see the crate-level docs on the semver trick), plus a
//! compat shim restoring the `Weight` constructors that 0.5.0 removed.

#[doc(inline)]
pub use units_v0_5::weight::*;

/// Restores `Weight` constructors that `bitcoin-units` removed in 0.5.0.
///
/// Note: unlike the original 0.4.0 methods, these are not `const fn` (trait methods cannot be
/// `const` in stable Rust).
pub trait WeightExt: Sized + crate::sealed::Sealed {
    /// Constructs a new [`Weight`] from virtual bytes panicking if an overflow occurred.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    #[deprecated(since = "1.0.0-rc.0", note = "use `from_vb_unchecked` instead")]
    fn from_vb_unwrap(vb: u64) -> Self;

    /// Constructs a new [`Weight`] from witness size.
    #[deprecated(since = "1.0.0-rc.1", note = "use `from_wu` instead")]
    fn from_witness_data_size(witness_size: u64) -> Self;

    /// Constructs a new [`Weight`] from non-witness size.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    #[deprecated(since = "1.0.0-rc.1", note = "use `from_vb` or `from_vb_unchecked` instead")]
    fn from_non_witness_data_size(non_witness_size: u64) -> Self;
}

impl WeightExt for units_v0_5::Weight {
    fn from_vb_unwrap(vb: u64) -> Self {
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(weight) => Self::from_wu(weight),
            None => panic!("checked_mul overflowed"),
        }
    }

    fn from_witness_data_size(witness_size: u64) -> Self { Self::from_wu(witness_size) }

    fn from_non_witness_data_size(non_witness_size: u64) -> Self {
        Self::from_wu(non_witness_size * Self::WITNESS_SCALE_FACTOR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn from_vb_unwrap() {
        let witness_data_size = 1;
        let got = units_v0_5::Weight::from_vb_unwrap(witness_data_size);
        let want = units_v0_5::Weight::from_vb(witness_data_size).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    #[allow(deprecated)]
    #[should_panic = "checked_mul overflowed"]
    fn from_vb_unwrap_panic() { units_v0_5::Weight::from_vb_unwrap(u64::MAX); }

    #[test]
    #[allow(deprecated)]
    fn from_witness_data_size() {
        let witness_data_size = 1;
        let got = units_v0_5::Weight::from_witness_data_size(witness_data_size);
        let want = units_v0_5::Weight::from_wu(witness_data_size);
        assert_eq!(got, want);
    }

    #[test]
    #[allow(deprecated)]
    fn from_non_witness_data_size() {
        let non_witness_data_size = 1;
        let got = units_v0_5::Weight::from_non_witness_data_size(non_witness_data_size);
        let want = units_v0_5::Weight::from_wu(non_witness_data_size * 4);
        assert_eq!(got, want);
    }
}
