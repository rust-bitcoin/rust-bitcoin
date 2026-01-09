// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.

use core::cmp;

use io::{BufRead, Write};

use crate::block::{BlockHash, Header};
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::internal_macros;
use crate::network::Params;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use primitives::CompactTarget;

pub use units::pow::{Target, Work};

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Work`] type.
    pub trait WorkExt impl for Work {
        /// Gets the hex representation of the [`Work`] value as a [`String`].
        #[deprecated(since = "0.33.0", note = "use `format!(\"{var:x}\")` instead")]
        fn to_hex(&self) -> alloc::string::String { format!("{self:x}") }
    }
}

internal_macros::define_extension_trait! {
    /// Extension functionality for the [`Target`] type.
    pub trait TargetExt impl for Target {
        /// Returns true if block hash is less than or equal to this [`Target`].
        ///
        /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
        /// to the target.
        fn is_met_by(&self, hash: BlockHash) -> bool {
            let hash = Target::from_le_bytes(hash.to_byte_array());
            hash <= *self
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
        #[must_use]
        fn min_difficulty_transition_threshold(&self) -> Self { self.min_transition_threshold() }

        /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        #[deprecated(since = "0.32.0", note = "use `max_transition_threshold` instead")]
        #[must_use]
        fn max_difficulty_transition_threshold(&self) -> Self {
            self.max_transition_threshold_unchecked()
        }

        /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
        /// adjustment occurs.
        ///
        /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
        /// adjustment period.
        ///
        /// We also check that the calculated target is not greater than the maximum allowed target,
        /// this value is network specific - hence the `params` parameter.
        #[must_use]
        fn max_transition_threshold(&self, params: impl AsRef<Params>) -> Self {
            let max_attainable = params.as_ref().max_attainable_target;
            cmp::min(self.max_transition_threshold_unchecked(), max_attainable)
        }

        /// Gets the hex representation of the [`Target`] value as a [`String`].
        #[deprecated(since = "0.33.0", note = "use `format!(\"{var:x}\")` instead")]
        fn to_hex(&self) -> alloc::string::String { format!("{self:x}") }
    }
}

// Helper function to multiply a Target by a u64, returning a Target
fn mul_target_u64(tgt: Target, rhs: u64) -> Target {
    let mut carry: u128 = 0;
    let mut out_bytes: [u8; 32] = [0u8; 32];

    let le_bytes = tgt.to_le_bytes();

    for i in 0..4 {
        let word = u64::from_le_bytes(
            le_bytes[i * 8..(i + 1) * 8].try_into().expect("slice is 8 bytes")
        );

        // This will not overflow, for proof see https://github.com/rust-bitcoin/rust-bitcoin/pull/1496#issuecomment-1365938572
        let n = carry + u128::from(rhs) * u128::from(word);

        let low = n as u64; // Intentional truncation, save the low bits
        carry = n >> 64; // and carry the high bits.

        out_bytes[i * 8..(i + 1) * 8]
            .copy_from_slice(&low.to_le_bytes());
    }

    Target::from_le_bytes(out_bytes)
}

// Helper function to divide a Target by a u64, returning a Target
fn div_target_u64(tgt: Target, rhs: u64) -> Target {
    let bytes = tgt.to_be_bytes();

    assert!(rhs != 0, "division by zero");

    let mut result = [0u8; 32];
    let mut rem: u128 = 0;

    for i in 0..32 {
        // Bring down the next byte (base-256 long division)
        rem = (rem << 8) | bytes[i] as u128;

        let q = rem / rhs as u128;
        rem %= rhs as u128;

        result[i] = q as u8;
    }

    Target::from_be_bytes(result)
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
            let retarget = prev_target; // bnNew
            let retarget = mul_target_u64(retarget, u64::try_from(actual_timespan).expect("clamped value won't be negative"));
            let retarget = div_target_u64(retarget, params.pow_target_timespan.into());
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
            let bits = current.bits;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockTime;

    #[test]
    fn compact_target_from_upwards_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_543_726); // Genesis compact target on Signet
        let start_time: i64 = 1_598_918_400; // Genesis block unix time
        let end_time: i64 = 1_599_332_177; // Block 2015 unix time
        let timespan = end_time - start_time; // Faster than expected
        let adjustment = CompactTarget::from_next_work_required(starting_bits, timespan, &params);
        let adjustment_bits = CompactTarget::from_consensus(503_394_215); // Block 2016 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_394_215); // Block 2016 compact target
        let start_time: i64 = 1_599_332_844; // Block 2016 unix time
        let end_time: i64 = 1_600_591_200; // Block 4031 unix time
        let timespan = end_time - start_time; // Slower than expected
        let adjustment = CompactTarget::from_next_work_required(starting_bits, timespan, &params);
        let adjustment_bits = CompactTarget::from_consensus(503_397_348); // Block 4032 compact target
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
            time: BlockTime::from_u32(1_599_332_177),
            bits: epoch_start.bits,
            nonce: epoch_start.nonce,
        };
        let adjustment =
            CompactTarget::from_header_difficulty_adjustment(epoch_start, current, params);
        let adjustment_bits = CompactTarget::from_consensus(503_394_215); // Block 2016 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_downwards_difficulty_adjustment_using_headers() {
        use crate::block::Version;
        use crate::TxMerkleNode;
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_394_215); // Block 2016 compact target

        // Block 2016, the only information used is `time`
        let epoch_start = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1_599_332_844),
            bits: starting_bits,
            nonce: 0,
        };

        // Block 4031, the only information used are `bits` and `time`
        let current = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: BlockTime::from_u32(1_600_591_200),
            bits: starting_bits,
            nonce: 0,
        };
        let adjustment =
            CompactTarget::from_header_difficulty_adjustment(epoch_start, current, params);
        let adjustment_bits = CompactTarget::from_consensus(503_397_348); // Block 4032 compact target
        assert_eq!(adjustment, adjustment_bits);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_403_001);
        let timespan = params.pow_target_timespan / 5;
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_maximum_upward_difficulty_adjustment_with_negative_timespan() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_403_001);
        let timespan: i64 = -i64::from(params.pow_target_timespan);
        let got = CompactTarget::from_next_work_required(starting_bits, timespan, params);
        let want =
            Target::from_compact(starting_bits).min_transition_threshold().to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_minimum_downward_difficulty_adjustment() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(403_403_001); // High difficulty for Signet
        let timespan = 5 * params.pow_target_timespan; // Really slow.
        let got = CompactTarget::from_next_work_required(starting_bits, timespan.into(), &params);
        let want =
            Target::from_compact(starting_bits).max_transition_threshold(params).to_compact_lossy();
        assert_eq!(got, want);
    }

    #[test]
    fn compact_target_from_adjustment_is_max_target() {
        let params = Params::new(crate::Network::Signet);
        let starting_bits = CompactTarget::from_consensus(503_543_726); // Genesis compact target on Signet
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
        let target = Target::from_le_bytes(hash.to_byte_array());
        assert!(target.is_met_by(hash));
    }

    #[test]
    fn target_difficulty_float() {
        let params = Params::new(crate::Network::Bitcoin);

        assert_eq!(Target::MAX.difficulty_float(&params), 1.0_f64);
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1c00_ffff_u32))
                .difficulty_float(&params),
            256.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1b00_ffff_u32))
                .difficulty_float(&params),
            65536.0_f64
        );
        assert_eq!(
            Target::from_compact(CompactTarget::from_consensus(0x1a00_f3a2_u32))
                .difficulty_float(&params),
            17_628_585.065_897_066_f64
        );
    }
}
