// SPDX-License-Identifier: CC0-1.0

//! A UNIX timestamp used as the Bitcoin block time.
//!
//! Also known as Epoch Time - January 1, 1970.
//!
//! This differs from other UNIX timestamps in that we only use non-negative values. The Epoch
//! pre-dates Bitcoin so timestamps before this are not useful for block timestamps.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod encapsulate {
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

#[cfg(feature = "serde")]
impl Serialize for BlockTime {
    #[inline]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        u32::serialize(&self.to_u32(), s)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for BlockTime {
    #[inline]
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_u32(u32::deserialize(d)?))
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
}
