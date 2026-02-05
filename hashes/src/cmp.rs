// SPDX-License-Identifier: CC0-1.0

//! Useful comparison functions.

/// Compares two slices for equality in fixed time. Panics if the slices are of non-equal length.
///
/// This works by XOR'ing each byte of the two inputs together and keeping an OR counter of the
/// results.
///
/// Instead of doing fancy bit twiddling to try to outsmart the compiler and prevent early exits,
/// which is not guaranteed to remain stable as compilers get ever smarter, we take the hit of
/// writing each intermediate value to memory with a volatile write and then re-reading it with a
/// volatile read. This should remain stable across compiler upgrades, but is much slower.
///
/// As of rust 1.31.0 disassembly looks completely within reason for this, see
/// <https://godbolt.org/z/mMbGQv>.
///
/// # Panics
///
/// Panics if the slices have different lengths.
pub fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    #[cfg(hashes_fuzz)]
    {
        // Fuzzers want to break memcmp calls into separate comparisons for coverage monitoring,
        // so we avoid our fancy fixed-time comparison below for fuzzers.
        a == b
    }
    #[cfg(not(hashes_fuzz))]
    {
        assert!(a.len() == b.len());
        let count = a.len();
        let lhs = &a[..count];
        let rhs = &b[..count];

        let mut r: u8 = 0;
        for i in 0..count {
            let mut rs = unsafe { core::ptr::read_volatile(&r) };
            rs |= lhs[i] ^ rhs[i];
            unsafe {
                core::ptr::write_volatile(&mut r, rs);
            }
        }
        {
            let mut t = unsafe { core::ptr::read_volatile(&r) };
            t |= t >> 4;
            unsafe {
                core::ptr::write_volatile(&mut r, t);
            }
        }
        {
            let mut t = unsafe { core::ptr::read_volatile(&r) };
            t |= t >> 2;
            unsafe {
                core::ptr::write_volatile(&mut r, t);
            }
        }
        {
            let mut t = unsafe { core::ptr::read_volatile(&r) };
            t |= t >> 1;
            unsafe {
                core::ptr::write_volatile(&mut r, t);
            }
        }
        unsafe { (::core::ptr::read_volatile(&r) & 1) == 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unreadable_literal)]
    fn eq_test() {
        assert!(fixed_time_eq(&[0b00000000], &[0b00000000]));
        assert!(fixed_time_eq(&[0b00000001], &[0b00000001]));
        assert!(fixed_time_eq(&[0b00000010], &[0b00000010]));
        assert!(fixed_time_eq(&[0b00000100], &[0b00000100]));
        assert!(fixed_time_eq(&[0b00001000], &[0b00001000]));
        assert!(fixed_time_eq(&[0b00010000], &[0b00010000]));
        assert!(fixed_time_eq(&[0b00100000], &[0b00100000]));
        assert!(fixed_time_eq(&[0b01000000], &[0b01000000]));
        assert!(fixed_time_eq(&[0b10000000], &[0b10000000]));
        assert!(fixed_time_eq(&[0b11111111], &[0b11111111]));

        assert!(!fixed_time_eq(&[0b00000001], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00000001], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b00000010], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00000010], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b00000100], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00000100], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b00001000], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00001000], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b00010000], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00010000], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b00100000], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b00100000], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b01000000], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b01000000], &[0b11111111]));
        assert!(!fixed_time_eq(&[0b10000000], &[0b00000000]));
        assert!(!fixed_time_eq(&[0b10000000], &[0b11111111]));

        assert!(fixed_time_eq(&[0b00000000, 0b00000000], &[0b00000000, 0b00000000]));
        assert!(!fixed_time_eq(&[0b00000001, 0b00000000], &[0b00000000, 0b00000000]));
        assert!(!fixed_time_eq(&[0b00000000, 0b00000001], &[0b00000000, 0b00000000]));
        assert!(!fixed_time_eq(&[0b00000000, 0b00000000], &[0b00000001, 0b00000000]));
        assert!(!fixed_time_eq(&[0b00000000, 0b00000000], &[0b00000001, 0b00000001]));
    }
}
