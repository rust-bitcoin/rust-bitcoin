// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.

use alloc::string::String;
use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};
use core::{cmp, fmt};

use io::{BufRead, Write};

use crate::block::{BlockHash, BlockHeight, BlockHeightInterval, Header};
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::internal_macros;
use crate::network::Params;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::pow::{error, CompactTarget, CompactTargetEncoder, CompactTargetDecoder, Target, Work};
#[doc(no_inline)]
pub use primitives::pow::{ParseTargetError, ParseWorkError};

#[doc(no_inline)]
pub use self::error::CompactTargetDecoderError;

/// Extension functionality for the [`Work`] type.
// This can't be defined with the extension trait macro because it ignores the feature gate.
pub trait WorkExt {
    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
    /// `log2_work` output in its logs.
    #[cfg(feature = "std")]
    fn log2(self) -> f64;

    /// Gets the hex representation of the [`Work`] value as a [`String`].
    #[deprecated(since = "0.33.0", note = "use `format!(\"{var:x}\")` instead")]
    fn to_hex(&self) -> String;
}
impl WorkExt for Work {
    #[cfg(feature = "std")]
    fn log2(self) -> f64 { self.to_inner().to_f64().log2() }

    fn to_hex(&self) -> String { format!("{self:x}") }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Target`] type.
    pub trait TargetExt impl for Target {
        /// Returns true if block hash is less than or equal to this [`Target`].
        ///
        /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
        /// to the target.
        fn is_met_by(&self, hash: BlockHash) -> bool {
            let hash = U256::from_le_bytes(hash.to_byte_array());
            hash <= self.to_inner()
        }

        /// Computes the popular "difficulty" measure for mining.
        ///
        /// Difficulty represents how difficult the current target makes it to find a block, relative to
        /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
        ///
        /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
        /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
        /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
        /// valid block.
        ///
        /// Values for the `max_target` paramter can be taken from const values on [`Target`]
        /// (e.g. [`Target::MAX_ATTAINABLE_MAINNET`]).
        ///
        /// # Note
        ///
        /// Difficulty is calculated using the following algorithm `max / current` where [max] is
        /// defined for the Bitcoin network and `current` is the current target for this block (i.e. `self`).
        /// As such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
        /// integer but `difficulty_with_max()` returns only 128 bits this means for targets below
        /// approximately `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty_with_max()` will saturate at `u128::MAX`.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        ///
        /// [max]: Target::max
        fn difficulty_with_max(&self, max_target: &Self) -> u128 {
            // Panic here may be easier to debug than during the actual division.
            let self_inner = self.to_inner();
            assert_ne!(self_inner, U256::ZERO, "divide by zero");

            let max_inner = max_target.to_inner();
            let d = max_inner / self_inner;
            d.saturating_to_u128()
        }

        /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
        ///
        /// See [`difficulty_with_max`] for details.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        ///
        /// [`difficulty_with_max`]: Target::difficulty_with_max
        fn difficulty_float_with_max(&self, max_target: &Self) -> f64 {
            // We want to explicitly panic to be uniform with `difficulty()`
            // (float division by zero does not panic).
            // Note, target 0 is basically impossible to obtain by any "normal" means.
            let self_inner = self.to_inner();
            assert_ne!(self_inner, U256::ZERO, "divide by zero");

            let max_inner = max_target.to_inner();
            max_inner.to_f64() / self_inner.to_f64()
        }

        /// Computes the popular "difficulty" measure for mining.
        ///
        /// This function calculates the difficulty measure using the max attainable target
        /// set on the provided [`Params`].
        /// See [`Target::difficulty_with_max`] for details.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
            let max = params.as_ref().max_attainable_target;
            self.difficulty_with_max(&max)
        }

        /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
        ///
        /// This function calculates the difficulty measure using the max attainable target
        /// set on the provided [`Params`].
        /// See [`Target::difficulty_with_max`] for details.
        ///
        /// # Panics
        ///
        /// Panics if `self` is zero (divide by zero).
        ///
        /// [`difficulty`]: Target::difficulty
        fn difficulty_float(&self, params: impl AsRef<Params>) -> f64 {
            let max = params.as_ref().max_attainable_target;
            self.difficulty_float_with_max(&max)
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
        fn min_transition_threshold(&self) -> Self {
            Self::from_inner(self.to_inner() >> 2)
        }

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
        fn max_transition_threshold_unchecked(&self) -> Self {
            Self::from_inner(self.to_inner() << 2)
        }

        /// Gets the hex representation of the [`Target`] value as a [`String`].
        #[deprecated(since = "0.33.0", note = "use `format!(\"{var:x}\")` instead")]
        fn to_hex(&self) -> String { format!("{self:x}") }
    }
}

/// Gets the target for the block after `current_header`.
///
/// Implements the [`GetNextWorkRequired`] function from Bitcoin core.
///
/// Note, `new_block_timestamp` is only used when `params.allow_min_difficulty_blocks = true` i.e.,
/// on testnet and regtest.
///
/// > Special difficulty rule for testnet: If the new block's timestamp is more
/// > than 2*10 minutes then allow mining of a min-difficulty block.
///
/// # Panics
///
/// If we are on testnet/regtest and `new_block_timestamp` is `None`.
///
/// [`GetNextWorkRequired`]: <https://github.com/bitcoin/bitcoin/blob/830583eb9d07e054c54a177907a98153ab3e29ae/src/pow.cpp#L13>
pub fn next_target_after<F, E>(
    current_header: Header,
    current_height: BlockHeight,
    params: &Params,
    new_block_timestamp: Option<u32>,
    mut get_block_header_by_height: F,
) -> Result<CompactTarget, E>
where
    F: FnMut(BlockHeight) -> Result<Header, E>,
{
    let adjustment_interval = params.difficulty_adjustment_interval();

    // if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    if !is_retarget_height(current_height.saturating_add(1.into()), adjustment_interval) {
        if params.allow_min_difficulty_blocks {
            // Only true for testnet and regtest.
            let new_block_timestamp = new_block_timestamp
                .expect("new_block_timestamp must contain a value when on testnet/regtest");

            // Special difficulty rule for testnet: If the new block's timestamp is more
            // than 2*10 minutes then allow mining of a min-difficulty block.
            let pow_limit = params.max_attainable_target.to_compact_lossy();

            // if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
            if new_block_timestamp > current_header.time.to_u32() + params.pow_target_spacing * 2 {
                Ok(pow_limit)
            } else {
                let mut header = current_header;
                let mut height = current_height;
                // while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                while header.prev_blockhash != BlockHash::GENESIS_PREVIOUS_BLOCK_HASH
                    && !is_retarget_height(height, adjustment_interval)
                    && header.bits == pow_limit
                {
                    // pindex = pindex->pprev;
                    height = height.saturating_sub(1.into());
                    header = get_block_header_by_height(height)?;
                }
                Ok(header.bits)
            }
        } else {
            Ok(current_header.bits)
        }
    } else {
        // Go back by what we want to be 14 days worth of blocks
        let back_step = BlockHeightInterval::from_u32(adjustment_interval - 1);
        let height_first = current_height.saturating_sub(back_step);
        let block_first = get_block_header_by_height(height_first)?;

        Ok(CompactTarget::from_header_difficulty_adjustment(block_first, current_header, params))
    }
}

/// Returns true if `height` ends the difficulty period.
fn is_retarget_height(height: BlockHeight, adjustment_interval: u32) -> bool {
    height.to_u32() % adjustment_interval == 0
}

internal_macros::define_extension_trait! {
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
        ) -> Self {
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
            let retarget = prev_target.to_inner(); // bnNew
            let (retarget, _) = retarget.mul_u64(u64::try_from(actual_timespan).expect("clamped value won't be negative"));
            let retarget = retarget.div(params.pow_target_timespan.into());
            let retarget = Target::from_inner(retarget);
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
        ) -> Self {
            let timespan = i64::from(current.time.to_u32()) - i64::from(last_epoch_boundary.time.to_u32());

            // Special difficulty rule for testnet4.
            // Take target from start of epoch instead of end of epoch.
            // See https://github.com/bitcoin/bitcoin/blob/4d7d5f6b79d4c11c47e7a828d81296918fd11d4d/src/pow.cpp#L67
            let bits = if params.as_ref().enforce_bip94 {
                last_epoch_boundary.bits
            } else {
                current.bits
            };

            CompactTarget::from_next_work_required(bits, timespan, params)
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CompactTarget {}
    impl Sealed for super::Target {}
    impl Sealed for super::Work {}
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
        u32::consensus_decode(r).map(Self::from_consensus)
    }
}

/// A trait for types that can convert to and from a [`U256`]
///
/// This just provides short-hand functions for the conversions going via byte arrays.
trait U256Wrapper {
    /// Convert [`Self`] into a [`U256`].
    fn to_inner(self) -> U256;

    /// Create a [`Self`] instance from an inner [`U256`].
    fn from_inner(inner: U256) -> Self;
}

impl U256Wrapper for Target {
    fn to_inner(self) -> U256 { U256::from_le_bytes(self.to_le_bytes()) }
    fn from_inner(inner: U256) -> Self { Self::from_le_bytes(inner.to_le_bytes()) }
}

impl U256Wrapper for Work {
    fn to_inner(self) -> U256 { U256::from_le_bytes(self.to_le_bytes()) }
    fn from_inner(inner: U256) -> Self { Self::from_le_bytes(inner.to_le_bytes()) }
}

include!(concat!(env!("OUT_DIR"), "/u256.rs"));

macro_rules! impl_hex {
    ($hex:path, $case:expr) => {
        impl $hex for U256 {
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                hex::fmt_hex_exact!(f, 32, &self.to_be_bytes(), $case)
            }
        }
    };
}
impl_hex!(fmt::LowerHex, hex::Case::Lower);
impl_hex!(fmt::UpperHex, hex::Case::Upper);

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
    use crate::pow::{Target, U256Wrapper as _, Work, U256};

    /// Converts a `u64` to a [`Work`]
    pub fn u64_to_work(u: u64) -> Work { Work::from_inner(U256::from(u)) }

    /// Converts a `u128` to a [`Work`]
    pub fn u128_to_work(u: u128) -> Work { Work::from_inner(U256::from(u)) }

    /// Converts a `u32` to a [`Target`]
    pub fn u32_to_target(u: u32) -> Target { Target::from_inner(U256::from(u)) }

    /// Converts a `u64` to a [`Target`]
    pub fn u64_to_target(u: u64) -> Target { Target::from_inner(U256::from(u)) }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    #[cfg(feature = "std")]
    use crate::pow::test_utils::u128_to_work;
    use crate::pow::test_utils::u32_to_target;
    use crate::BlockTime;

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
    fn compact_target_from_adjustment_bip94() {
        // Two different compact targets to use for epoch_start and current headers.
        let bits_start = CompactTarget::from_consensus(0x1c00ffff); // Higher difficulty
        let bits_end = CompactTarget::from_consensus(0x1d00ffff); // Minimum difficulty

        // Same timestamps for both networks to keep timespan consistent.
        let start_time = BlockTime::from_u32(1_000_000);
        let end_time = BlockTime::from_u32(1_000_000 + 14 * 24 * 60 * 60); // +14 days. No adjustment.

        let epoch_start = Header {
            version: crate::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
            time: start_time,
            bits: bits_start,
            nonce: 0,
        };

        let current = Header {
            version: crate::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([0; 32]),
            time: end_time,
            bits: bits_end,
            nonce: 0,
        };

        // Test mainnet (enforce_bip94 = false): should use current.bits
        let mainnet_result = CompactTarget::from_header_difficulty_adjustment(
            epoch_start,
            current,
            &Params::MAINNET,
        );
        assert_eq!(mainnet_result, bits_end);

        // Test testnet4 (enforce_bip94 = true): should use epoch_start.bits
        let testnet_result = CompactTarget::from_header_difficulty_adjustment(
            epoch_start,
            current,
            &Params::TESTNET4,
        );
        assert_eq!(testnet_result, bits_start);
    }

    #[test]
    fn target_is_met_by_for_target_equals_hash() {
        let hash = "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
            .parse::<BlockHash>()
            .expect("failed to parse block hash");
        let target = Target::from_inner(U256::from_le_bytes(hash.to_byte_array()));
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
    fn roundtrip_target_work() {
        let target = u32_to_target(0xdeadbeef_u32);
        let work = target.to_work();
        let back = work.to_target();
        assert_eq!(back, target)
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

        assert_eq!(Work::from_inner(U256::ONE).log2(), 0.0);
        assert_eq!(Work::from_inner(U256::MAX).log2(), 256.0);
    }

    fn current_header() -> Header {
        Header {
            version: crate::block::Version::from_consensus(0x2431_a000),
            prev_blockhash: BlockHash::from_str(
                "0000000000000000000387dab5f3cf88824c983770f70f8a8eb7a9a240a257a5",
            )
            .unwrap(),
            merkle_root: crate::TxMerkleNode::from_str(
                "07bf4eafca7979d59b0ec2dc03131c08c1b9ea2ddb8b8945846fcb0ce92cdbe3",
            )
            .unwrap(),
            time: 0x651b_c919.into(), // 2023-10-03 18:56:09 GMT +11 -> 1696359369 -> 651BC919
            bits: CompactTarget::from_consensus(0x1704_ed7f),
            nonce: 0xc637_a163,
        }
    }

    // Test target calculated going from block 808416 to block 810432 on mainnet.
    #[test]
    fn next_target_mainnet() {
        // Only time and bits are used.
        let header_810431 = current_header();

        // This closure should return the header for 808416 since 810431 - 2015 is 808416
        fn fetch_header_808416(height: BlockHeight) -> Result<Header, core::convert::Infallible> {
            assert_eq!(height, BlockHeight::from_u32(808_416)); // sanity check

            // Header for 808416
            Ok(Header {
                version: crate::block::Version::TWO,
                prev_blockhash: BlockHash::from_str(
                    "000000000000000000027ecc78c2da1cc5c0b0496706baa7e4d7c80812c10bf3",
                )
                .unwrap(),
                merkle_root: crate::TxMerkleNode::from_str(
                    "b920d5b5ebef4e9d106072944e0729cea8bf6defc583a7d87063041a316a757b",
                )
                .unwrap(),
                time: 0x6509_64b5.into(), // 2023-09-19 09:07:01 GMT -> 1695114421 -> 650964B5
                bits: CompactTarget::from_consensus(0x1704_ed7f),
                nonce: 0x82d6_8990,
            })
        }

        let params = Params::new(crate::Network::Bitcoin);
        let height = BlockHeight::from_u32(810_431);

        let want = CompactTarget::from_consensus(0x1704_e90f); // Bits from block 810432.
        let got = next_target_after(header_810431, height, &params, None, fetch_header_808416)
            .expect("failed to calculate next target");

        assert_eq!(got, want);
    }

    #[test]
    fn next_target_mainnet_same_target() {
        let header_810430 = current_header();

        // This closure should be unused if the target remains the same
        fn fetch_header(_height: BlockHeight) -> Result<Header, core::num::ParseIntError> {
            unreachable!("get_block_header_by_height should not be called");
        }

        let params = Params::new(crate::Network::Bitcoin);
        let height = BlockHeight::from_u32(810_430);

        // On mainnet, non-retargeting height should return the same block target
        let want = header_810430.bits; // Bits from block 810430.
        let got = next_target_after(header_810430, height, &params, None, fetch_header)
            .expect("failed to calculate next target");

        assert_eq!(got, want);
    }

    // Test that on testnet, if the new block's timestamp is more than 20 minutes after
    // the current header's time, we return the pow_limit (minimum difficulty).
    #[test]
    fn next_target_testnet_min_difficulty_when_slow() {
        let header = current_header();

        fn fetch_header(_height: BlockHeight) -> Result<Header, core::convert::Infallible> {
            unreachable!("fetcher should not be called for min difficulty case");
        }

        let params = Params::TESTNET3;
        let height = BlockHeight::from_u32(100); // non-retarget height

        // New block timestamp is more than 2 * 10 minutes = 20 minutes after current header
        let new_block_timestamp = Some(header.time.to_u32() + 20 * 60 + 1);

        // Should return pow_limit (minimum difficulty)
        let want = params.max_attainable_target.to_compact_lossy();
        let got = next_target_after(header, height, &params, new_block_timestamp, fetch_header)
            .expect("failed to calculate next target");
        assert_eq!(got, want);
    }

    #[test]
    fn next_target_testnet_walk_back_for_real_target() {
        let current_time: u32 = 1_700_000_000;

        let params = Params::TESTNET3;
        let pow_limit = params.max_attainable_target.to_compact_lossy();
        let want = CompactTarget::from_consensus(0x1d00_ffff);

        // Current header is at a retarget boundary (height divisible by 2016) with pow_limit bits
        let adjustment_interval = params.difficulty_adjustment_interval();
        let current_height = BlockHeight::from_u32(adjustment_interval * 5);

        let current_header = Header {
            version: crate::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array([1u8; 32]),
            merkle_root: crate::TxMerkleNode::from_byte_array([2u8; 32]),
            time: current_time.into(),
            bits: pow_limit, // Current header has pow_limit
            nonce: 0,
        };

        // New block timestamp is within 20 minutes
        let new_block_timestamp = Some(current_time + 10 * 60);

        // The fetcher: heights at retarget boundaries with pow_limit should be walked back,
        // until we find one that doesn't have pow_limit or isn't at a retarget boundary.
        let fetch_header = move |height: BlockHeight| -> Result<Header, core::convert::Infallible> {
            assert_eq!(height.to_u32(), 10_079);

            Ok(Header {
                version: crate::block::Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::from_byte_array([1u8; 32]),
                merkle_root: crate::TxMerkleNode::from_byte_array([2u8; 32]),
                time: (current_time - 600).into(),
                bits: want,
                nonce: 0,
            })
        };

        let got = next_target_after(
            current_header,
            current_height,
            &params,
            new_block_timestamp,
            fetch_header,
        )
        .expect("failed to calculate next target");

        // Should return the real_target from the walked-back header
        assert_eq!(got, want);
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
