// SPDX-License-Identifier: CC0-1.0

//! A UNIX timestamp used as the Bitcoin block time.
//!
//! Also known as Epoch Time - January 1, 1970.
//!
//! This differs from other UNIX timestamps in that we only use non-negative values. The Epoch
//! pre-dates Bitcoin so timestamps before this are not useful for block timestamps.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use crate::locktime::relative::MtpInterval;

mod encapsulate {
    #[cfg(feature = "serde")]
    use serde::{Deserialize, Serialize};

    /// A Bitcoin block timestamp.
    ///
    /// > Each block contains a Unix time timestamp. In addition to serving as a source of variation for
    /// > the block hash, they also make it more difficult for an adversary to manipulate the block chain.
    /// >
    /// > A timestamp is accepted as valid if it is greater than the median timestamp of previous 11
    /// > blocks, and less than the network-adjusted time + 2 hours. "Network-adjusted time" is the
    /// > median of the timestamps returned by all nodes connected to you. As a result block timestamps
    /// > are not exactly accurate, and they do not need to be. Block times are accurate only to within
    /// > an hour or two.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Block_timestamp>
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct BlockTime(u32);

    impl BlockTime {
        /// Constructs a new [`BlockTime`] from an unsigned 32 bit integer value.
        #[inline]
        pub const fn from_u32(t: u32) -> Self { BlockTime(t) }

        /// Returns the inner `u32` value.
        #[inline]
        pub const fn to_u32(self) -> u32 { self.0 }
    }
}
#[doc(inline)]
pub use encapsulate::BlockTime;

// TODO: BlockTime: Should we implement Display? - decimal or hex?
// TODO: BlockTime: Should we implement `FromStr`?

impl From<u32> for BlockTime {
    #[inline]
    fn from(t: u32) -> Self { Self::from_u32(t) }
}

impl From<BlockTime> for u32 {
    #[inline]
    fn from(t: BlockTime) -> Self { t.to_u32() }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTime {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let t: u32 = u.arbitrary()?;
        Ok(BlockTime::from(t))
    }
}

// TODO: Add `encapsulate` module.
/// The median time past (MTP).
///
/// The median timestamp of 11 blocks as specified by [BIP-113].
///
/// [BIP-113]: <https://en.bitcoin.it/wiki/BIP_0113>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
// TODO: Derive serde trait impls?
pub struct MedianTimePast(BlockTime);

impl MedianTimePast {
    /// Constructs an MTP from the blocktimes of 11 consecutive blocks.
    ///
    /// The order of the timestamps does not matter i.e., can be from newest to oldest or
    /// vice-versa.
    pub fn new(mut timestamps: [BlockTime; 11]) -> Self {
        timestamps.sort_unstable();
        MedianTimePast(timestamps[5])
    }

    /// Returns the UNIX timestamp.
    pub fn time(self) -> BlockTime { self.0 }

    /// Constructs an MTP from a block time.
    ///
    /// The MTP for a block is **not** the block's timestamp. You probably want to use `Self::new`.
    /// This function is provided for low level code when you _really_ understand the lock-time
    /// BIPs (and even then probably only for testing).
    pub fn from_block_time(t: BlockTime) -> Self { Self(t) }
}

// TODO: Add `encapsulate` module.
/// The block produced time.
///
/// The block produced time is equal to the median-time-past of its previous block. This is used to
/// get the mining date of an unspent output (see [BIP-68]).
///
/// [BIP-68]: <https://en.bitcoin.it/wiki/BIP_0068>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
// TODO: Derive serde trait impls?
pub struct BlockProducedTime(MedianTimePast);

impl BlockProducedTime {
    /// Constructs a [`BlockProducedTime`] from the 11 previous blocks.
    ///
    /// This is for calculating the mining date of an unspent output as defined in [BIP-68].
    ///
    /// > The mining date of the output is equal to the median-time-past of the previous block which mined it.
    ///
    /// **ATTENTION**
    ///
    /// `previous_blocks` **does not include** the blocktime of the block which created the unspent
    /// output. These are the block times of the 11 blocks prior to that block.
    pub fn new(previous_blocks: [BlockTime; 11]) -> Self {
        Self(MedianTimePast::new(previous_blocks))
    }

    /// Returns the UNIX timestamp.
    pub fn time(self) -> BlockTime { self.0.time() }

    /// Returns the [`MtpInterval`] between to block-produced-time and current chain tip.
    ///
    /// # Returns
    ///
    /// Returns `None` if calculated value will not fit in 16 bits because [`MtpInterval`] is
    /// limited as such by the Bitcoin protocol.
    pub fn interval(self, chain_tip: MedianTimePast) -> Result<MtpInterval, ()> {
        let this = self.time().to_u32();
        let that = chain_tip.time().to_u32();

        if that > this {
            return Err(()); // TODO: Implement error handling.
        }

        let interval = this - that;
        MtpInterval::from_seconds_floor(interval).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_time_round_trip() {
        let t = BlockTime::from(1_742_979_600); // 26 Mar 2025 9:00 UTC
        assert_eq!(u32::from(t), 1_742_979_600);
    }
}
