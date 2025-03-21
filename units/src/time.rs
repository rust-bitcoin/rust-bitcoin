// SPDX-License-Identifier: CC0-1.0

//! A UNIX timestamp used as the Bitcoin block time.
//!
//! Also known as Epoch Time - January 1, 1970.
//!
//! This differs from other UNIX timestamps in that we only use non-negative values. The Epoch
//! pre-dates Bitcoin so timestamps before this are not useful for block timestamps.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
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
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl From<u32> for BlockTime {
    #[inline]
    fn from(t: u32) -> Self { Self::from_u32(t) }
}

impl From<BlockTime> for u32 {
    #[inline]
    fn from(t: BlockTime) -> Self { t.to_u32() }
}

impl fmt::Display for BlockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::Debug for BlockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockTime({:08x})", self.to_u32())
    }
}

impl fmt::LowerHex for BlockTime {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:#08x}", self.to_u32())
        } else {
            write!(f, "{:08x}", self.to_u32())
        }
    }
}
#[cfg(feature = "alloc")]
internals::impl_to_hex_from_lower_hex!(BlockTime, |_: &BlockTime| 8);

impl fmt::UpperHex for BlockTime {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:#08X}", self.to_u32())
        } else {
            write!(f, "{:08X}", self.to_u32())
        }
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
#[cfg(feature = "alloc")]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn formatting() {
        let nonce = BlockTime::from_u32(0xdead_beef);
        assert_eq!(format!("{}", nonce), "deadbeef");
        assert_eq!(format!("{:x}", nonce), "deadbeef");
        assert_eq!(format!("{:X}", nonce), "DEADBEEF");
        assert_eq!(format!("{:#x}", nonce), "0xdeadbeef");
        assert_eq!(format!("{:#X}", nonce), "0xDEADBEEF");
        assert_eq!(format!("{:?}", nonce), "BlockTime(deadbeef)");
    }
}
