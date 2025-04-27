// SPDX-License-Identifier: CC0-1.0

//! A UNIX timestamp used as the Bitcoin block time.
//!
//! Also known as Epoch Time - January 1, 1970.
//!
//! This differs from other UNIX timestamps in that we only use non-negative values. The Epoch
//! pre-dates Bitcoin so timestamps before this are not useful for block timestamps.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

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

impl From<u32> for BlockTime {
    #[inline]
    fn from(t: u32) -> Self { Self::from_u32(t) }
}

impl From<BlockTime> for u32 {
    #[inline]
    fn from(t: BlockTime) -> Self { t.to_u32() }
}

impl core::ops::Sub for BlockTime {
    type Output = i64;

    fn sub(self, other: Self) -> Self::Output {
        i64::from(self.to_u32()) - i64::from(other.to_u32())
    }
}
#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for BlockTime {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let t: u32 = u.arbitrary()?;
        Ok(BlockTime::from(t))
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

    #[test]
    fn block_time_sub() {
        let t1 = BlockTime::from(1_700_000_000);
        let t2 = BlockTime::from(1_700_000_100);
        assert_eq!(t1-t2, -100);
        assert_eq!(t2-t1, 100);
    }
}
