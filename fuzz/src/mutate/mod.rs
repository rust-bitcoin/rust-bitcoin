//! Custom libFuzzer mutators.
//!
//! A few targets sit behind a checksum, or behind a checksummed string encoding. Random byte
//! mutation cannot satisfy those: changing any byte invalidates the envelope, so the fuzzer
//! spends its whole budget being rejected and never reaches the parser inside. These mutators
//! keep the envelope well formed, so libFuzzer's mutations land on the payload instead.
//!
//! Each mutator takes libFuzzer's built-in mutator as a [`Mutate`] parameter rather than
//! calling `libfuzzer_sys::fuzzer_mutate` itself. That function is an `extern "C"` call into
//! the libFuzzer runtime, which is only linked into a fuzz target binary; taking it as a
//! parameter keeps this library linkable, and its mutators unit testable, on their own.
//!
//! Note that libFuzzer stops using its built-in mutators as soon as a custom one is defined,
//! so every path through a mutator has to call [`Mutate`] to keep them.

pub mod address;
pub mod p2p_frame;

/// The signature of `libfuzzer_sys::fuzzer_mutate`.
///
/// Mutates `data[..size]` in place, growing or shrinking it to at most `max_size`, and returns
/// the new length.
pub type Mutate = fn(&mut [u8], usize, usize) -> usize;

/// A SplitMix64 generator.
///
/// libFuzzer requires that a mutation be a deterministic function of the seed it passes in, so
/// mutators must not reach for any ambient source of randomness.
pub struct Rng(u64);

impl Rng {
    /// Constructs a generator from libFuzzer's per-call seed.
    pub fn new(seed: u32) -> Self { Self(u64::from(seed)) }

    /// Returns the next value in the sequence.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..n`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero.
    pub fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "below(0) has no valid result");
        (self.next_u64() % n as u64) as usize
    }

    /// Returns `true` with probability `1 / n`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is zero.
    pub fn one_in(&mut self, n: usize) -> bool { self.below(n) == 0 }

    /// Returns one of `choices`.
    ///
    /// # Panics
    ///
    /// Panics if `choices` is empty.
    pub fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T { &choices[self.below(choices.len())] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_in_the_seed() {
        let sequence = |seed| {
            let mut rng = Rng::new(seed);
            [rng.next_u64(), rng.next_u64(), rng.next_u64()]
        };

        assert_eq!(sequence(7), sequence(7));
        assert_ne!(sequence(7), sequence(8));
    }

    #[test]
    fn rng_below_stays_in_range() {
        let mut rng = Rng::new(0);
        for _ in 0..1_000 {
            assert!(rng.below(38) < 38);
        }
    }

    #[test]
    fn rng_below_one_is_always_zero() {
        let mut rng = Rng::new(1);
        assert_eq!(rng.below(1), 0);
    }
}
