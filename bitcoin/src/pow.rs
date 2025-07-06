// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.

use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};
use core::{cmp, fmt};

use io::{BufRead, Write};
use units::parse::{self, ParseIntError, PrefixedHexError, UnprefixedHexError};

use crate::block::{BlockHash, Header};
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::internal_macros::define_extension_trait;
use crate::network::Params;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use units::CompactTarget;

define_extension_trait! {
    /// Extension functionality for the [`Work`] type.
    pub trait WorkExt impl for Work {
        /// Converts this [`Work`] to [`Target`].
        fn to_target(self) -> Target { Target(self.0.inverse()) }

        /// Returns log2 of this work.
        ///
        /// The result inherently suffers from a loss of precision and is, therefore, meant to be
        /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
        /// `log2_work` output in its logs.
        #[cfg(feature = "std")]
        fn log2(self) -> f64 { self.0.to_f64().log2() }
    }
}

define_extension_trait! {
    /// Extension functionality for the [`Target`] type.
    pub trait TargetExt impl for Target {
        /// Computes the compact value from a [`Target`] representation.
        ///
        /// The compact form is by definition lossy, this means that
        /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
        fn to_compact_lossy(self) -> CompactTarget {
            let mut size = (self.0.bits() + 7) / 8;
            let mut compact = if size <= 3 {
                (self.0.low_u64() << (8 * (3 - size))) as u32
            } else {
                let bn = self.0 >> (8 * (size - 3));
                bn.low_u32()
            };

            if (compact & 0x0080_0000) != 0 {
                compact >>= 8;
                size += 1;
            }

            CompactTarget::from_consensus(compact | (size << 24))
        }

        /// Returns true if block hash is less than or equal to this [`Target`].
        ///
        /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
        /// to the target.
        fn is_met_by(&self, hash: BlockHash) -> bool {
            let hash = U256::from_le_bytes(hash.to_byte_array());
            hash <= self.0
        }

        /// Converts this [`Target`] to [`Work`].
        ///
        /// "Work" is defined as the work done to mine a block with this target value (recorded in the
        /// block header in compact form as nBits). This is not the same as the difficulty to mine a
        /// block with this target (see `Self::difficulty`).
        fn to_work(self) -> Work { Work(self.0.inverse()) }

        /// Computes the popular "difficulty" measure for mining.
        ///
        /// Difficulty represents how difficult the current target makes it to find a block, relative to
        /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
        ///
        /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
        /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
        /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
        /// valid block
        ///
        /// # Note
        ///
        /// Difficulty is calculated using the following algorithm `max / current` where [max] is
        /// defined for the Bitcoin network and `current` is the current [target] for this block. As
        /// such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
        /// integer but `difficulty()` returns only 128 bits this means for targets below approximately
        /// `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty()` will saturate at `u128::MAX`.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        ///
        /// [max]: Target::max
        /// [target]: crate::block::HeaderExt::target
        fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
            // Panic here may be easier to debug than during the actual division.
            assert_ne!(self.0, U256::ZERO, "divide by zero");

            let max = params.as_ref().max_attainable_target;
            let d = max.0 / self.0;
            d.saturating_to_u128()
        }

        /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
        ///
        /// See [`difficulty`] for details.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        ///
        /// [`difficulty`]: Target::difficulty
        fn difficulty_float(&self, params: impl AsRef<Params>) -> f64 {
            // We want to explicitly panic to be uniform with `difficulty()`
            // (float division by zero does not panic).
            // Note, target 0 is basically impossible to obtain by any "normal" means.
            assert_ne!(self.0, U256::ZERO, "divide by zero");
            let max = params.as_ref().max_attainable_target;
            max.0.to_f64() / self.0.to_f64()
        }

        /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        #[deprecated(since = "0.32.0", note = "use `min_transition_threshold` instead")]
        fn min_difficulty_transition_threshold(&self) -> Self { self.min_transition_threshold() }

        /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        #[deprecated(since = "0.32.0", note = "use `max_transition_threshold` instead")]
        fn max_difficulty_transition_threshold(&self) -> Self {
            self.max_transition_threshold_unchecked()
        }

        /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        ///
        /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
        /// adjustment period.
        ///
        /// # Returns
        ///
        /// In line with Bitcoin Core this function may return a target value of zero.
        fn min_transition_threshold(&self) -> Self { Self(self.0 >> 2) }

        /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        ///
        /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
        /// adjustment period.
        ///
        /// We also check that the calculated target is not greater than the maximum allowed target,
        /// this value is network specific - hence the `params` parameter.
        fn max_transition_threshold(&self, params: impl AsRef<Params>) -> Self {
            let max_attainable = params.as_ref().max_attainable_target;
            cmp::min(self.max_transition_threshold_unchecked(), max_attainable)
        }

        /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        ///
        /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
        /// adjustment period.
        ///
        /// # Returns
        ///
        /// This function may return a value greater than the maximum allowed target for this network.
        ///
        /// The return value should be checked against [`Params::max_attainable_target`] or use one of
        /// the `Target::MAX_ATTAINABLE_FOO` constants.
        fn max_transition_threshold_unchecked(&self) -> Self { Self(self.0 << 2) }
    }
}

define_extension_trait! {
    /// Extension functionality for the [`CompactTarget`] type.
    pub trait CompactTargetExt impl for CompactTarget {
        /// Computes the [`CompactTarget`] from a difficulty adjustment.
        ///
        /// ref: <https://github.com/bitcoin/bitcoin/blob/0503cbea9aab47ec0a87d34611e5453158727169/src/pow.cpp>
        ///
        /// Given the previous Target, represented as a [`CompactTarget`], the difficulty is adjusted
        /// by taking the timespan between them, and multiplying the current [`CompactTarget`] by a factor
        /// of the net timespan and expected timespan. The [`CompactTarget`] may not adjust by more than
        /// a factor of 4, or adjust beyond the maximum threshold for the network.
        ///
        /// # Note
        ///
        /// Under the consensus rules, the difference in the number of blocks between the headers does
        /// not equate to the `difficulty_adjustment_interval` of [`Params`]. This is due to an off-by-one
        /// error, and, the expected number of blocks in between headers is `difficulty_adjustment_interval - 1`
        /// when calculating the difficulty adjustment.
        ///
        /// Take the example of the first difficulty adjustment. Block 2016 introduces a new [`CompactTarget`],
        /// which takes the net timespan between Block 2015 and Block 0, and recomputes the difficulty.
        ///
        /// To calculate the timespan, users should first convert their u32 timestamps to i64s before subtracting them
        ///
        /// # Returns
        ///
        /// The expected [`CompactTarget`] recalculation.
        fn from_next_work_required(
            last: CompactTarget,
            timespan: i64,
            params: impl AsRef<Params>,
        ) -> CompactTarget {
            let params = params.as_ref();
            if params.no_pow_retargeting {
                return last;
            }
            // Comments relate to the `pow.cpp` file from Core.
            // ref: <https://github.com/bitcoin/bitcoin/blob/0503cbea9aab47ec0a87d34611e5453158727169/src/pow.cpp>
            let min_timespan = params.pow_target_timespan >> 2; // Lines 56/57
            let max_timespan = params.pow_target_timespan << 2; // Lines 58/59
            let actual_timespan = timespan.clamp(min_timespan.into(), max_timespan.into());
            let prev_target: Target = last.into();
            let maximum_retarget = prev_target.max_transition_threshold(params); // bnPowLimit
            let retarget = prev_target.0; // bnNew
            let retarget = retarget.mul(u128::try_from(actual_timespan).expect("clamped value won't be negative").into());
            let retarget = retarget.div(params.pow_target_timespan.into());
            let retarget = Target(retarget);
            if retarget.ge(&maximum_retarget) {
                return maximum_retarget.to_compact_lossy();
            }
            retarget.to_compact_lossy()
        }

        /// Computes the [`CompactTarget`] from a difficulty adjustment,
        /// assuming these are the relevant block headers.
        ///
        /// Given two headers, representing the start and end of a difficulty adjustment epoch,
        /// compute the [`CompactTarget`] based on the net time between them and the current
        /// [`CompactTarget`].
        ///
        /// # Note
        ///
        /// See [`CompactTarget::from_next_work_required`]
        ///
        /// For example, to successfully compute the first difficulty adjustment on the Bitcoin network,
        /// one would pass the header for Block 2015 as `current` and the header for Block 0 as
        /// `last_epoch_boundary`.
        ///
        /// # Returns
        ///
        /// The expected [`CompactTarget`] recalculation.
        fn from_header_difficulty_adjustment(
            last_epoch_boundary: Header,
            current: Header,
            params: impl AsRef<Params>,
        ) -> CompactTarget {
            let timespan = i64::from(current.time.to_u32()) - i64::from(last_epoch_boundary.time.to_u32());
            let bits = current.bits;
            CompactTarget::from_next_work_required(bits, timespan, params)
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Work {}
    impl Sealed for super::Target {}
    impl Sealed for super::CompactTarget {}
}

impl Encodable for CompactTarget {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_consensus().consensus_encode(w)
    }
}

impl Decodable for CompactTarget {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(CompactTarget::from_consensus)
    }
}

#[cfg(kani)]
impl kani::Arbitrary for U256 {
    fn any() -> Self {
        let high: u128 = kani::any();
        let low: u128 = kani::any();
        Self(high, low)
    }
}

/// In test code, U256s are a pain to work with, so we just convert Rust primitives in many places
#[cfg(test)]
pub mod test_utils {
    use crate::pow::{Target, Work, U256};

    /// Converts a `u128` to a [`Work`]
    pub fn u128_to_work(u: u128) -> Work { Work(U256::from(u)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::test_utils::{u128_to_work, u32_to_target, u64_to_target};
    use crate::BlockTime;


    #[test]
    fn roundtrip_target_work() {
        let target = u32_to_target(0xdeadbeef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target)
    }

    #[test]
    fn roundtrip_compact_target() {
        let consensus = 0x1d00_ffff;
        let compact = CompactTarget::from_consensus(consensus);
        let t = Target::from_compact(CompactTarget::from_consensus(consensus));
        assert_eq!(t, Target::from(compact)); // From/Into sanity check.

        let back = t.to_compact_lossy();
        assert_eq!(back, compact); // From/Into sanity check.

        assert_eq!(back.to_consensus(), consensus);
    }

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503543726); // Genesis compact target on Signet
        let start_time: i64 = 1598918400; // Genesis block unix time
        let end_time: i64 = 1599332177; // Block 2015 unix time
        let timespan = end_time - start_time; // Faster than expected
        let adjustment = CompactTarget::from_next_work_required(starting_bits, timespan, &params);
        let adjustment_bits = CompactTarget::from_consensus(503394215); // Block 2016 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503394215); // Block 2016 compact target
        let start_time: i64 = 1599332844; // Block 2016 unix time
        let end_time: i64 = 1600591200; // Block 4031 unix time
        let timespan = end_time - start_time; // Slower than expected
        let adjustment = CompactTarget::from_next_work_required(starting_bits, timespan, &params);
        let adjustment_bits = CompactTarget::from_consensus(503397348); // Block 4032 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment_using_headers() {
        use crate::block::Version;
        use crate::constants::genesis_block;
        use crate::TxMerkleNode;
        let params = Params::new(crate::Network::Signet);
        let epoch_start = *genesis_block(&params).header();

        // Block 2015, the only information used are `bits` and `time`
        let current = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1599332177),
            bits: epoch_start.bits,
            nonce: epoch_start.nonce,
        };
        let adjustment =
            CompactTarget::from_header_difficulty_adjustment(epoch_start, current, params);
        let adjustment_bits = CompactTarget::from_consensus(503394215); // Block 2016 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment_using_headers() {
        use crate::block::Version;
        use crate::TxMerkleNode;
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503394215); // Block 2016 compact target

        // Block 2016, the only information used is `time`
        let epoch_start = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1599332844),
            bits: starting_bits,
            nonce: 0,
        };

        // Block 4031, the only information used are `bits` and `time`
        let current = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1600591200),
            bits: starting_bits,
            nonce: 0,
        };
        let adjustment =
            CompactTarget::from_header_difficulty_adjustment(epoch_start, current, params);
        let adjustment_bits = CompactTarget::from_consensus(503397348); // Block 4032 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503403001);
        let timespan = params.pow_target_timespan / 5;
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment_with_negative_timespan() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503403001);
        let timespan: i64 = -i64::from(params.pow_target_timespan);
        let got = CompactTarget::from_next_work_required(starting_bits, timespan, params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_minimum_downward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(403403001); // High difficulty for Signet
        let timespan = 5 * params.pow_target_timespan; // Really slow.
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), &params);
        let want =
            Target::from_compact(starting_bits).max_transition_threshold(params).to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_adjustment_is_max_target() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503543726); // Genesis compact target on Signet
        let timespan = 5 * params.pow_target_timespan; // Really slow.
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), &params);
        let want = params.max_attainable_target.to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn target_is_met_by_for_target_equals_hash() {
        let hash = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
            .parse::<BlockHash>()
            .expect("failed to parse block hash");
        let target = Target(U256::from_le_bytes(hash.to_byte_array()));
        assert!(target.is_met_by(hash));
    }

    #[test]
    fn target_difficulty_float() {
        let params = Params::new(crate::Network::Bitcoin);

        assert_eq!(Target::MAX.difficulty_float(&params), 1.0_f64);
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1c00ffff_u32))
                .difficulty_float(&params),
            256.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1b00ffff_u32))
                .difficulty_float(&params),
            65536.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1a00f3a2_u32))
                .difficulty_float(&params),
            17628585.065897066_f64
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn work_log2() {
        // Compare work log2 to historical Bitcoin Core values found in Core logs.
        let tests: &[(u128, f64)] = &[
            // (chainwork, core log2)                // height
            (0x200020002, 33.000022),                // 1
            (0xa97d67041c5e51596ee7, 79.405055),     // 308004
            (0x1dc45d79394baa8ab18b20, 84.895644),   // 418141
            (0x8c85acb73287e335d525b98, 91.134654),  // 596624
            (0x2ef447e01d1642c40a184ada, 93.553183), // 738965
        ];

        for &(chainwork, core_log2) in tests {
            // Core log2 in the logs is rounded to 6 decimal places.
            let log2 = (u128_to_work(chainwork).log2() * 1e6).round() / 1e6;
            assert_eq!(log2, core_log2)
        }

        assert_eq!(Work(U256::ONE).log2(), 0.0);
        assert_eq!(Work(U256::MAX).log2(), 256.0);
    }

    #[test]
    fn u256_max_min_inverse_roundtrip() {
        let max = U256::MAX;

        for min in [U256::ZERO, U256::ONE].iter() {
            // lower target means more work required.
            assert_eq!(Target(max).to_work(), Work(U256::ONE));
            assert_eq!(Target(*min).to_work(), Work(max));

            assert_eq!(Work(max).to_target(), Target(U256::ONE));
            assert_eq!(Work(*min).to_target(), Target(max));
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::unwind(5)] // mul_u64 loops over 4 64 bit ints so use one more than 4
    #[kani::proof]
    fn check_mul_u64() {
        let x: U256 = kani::any();
        let y: u64 = kani::any();

        let _ = x.mul_u64(y);
    }
}
