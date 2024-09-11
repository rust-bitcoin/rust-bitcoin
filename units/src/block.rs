// SPDX-License-Identifier: CC0-1.0

//! Block height and interval types.
//!
//! These types are thin wrappers around `u32`, no invariants implemented or implied.
//!
//! These are general types for abstracting over block heights, they are not designed to use with
//! lock times. If you are creating lock times you should be using the
//! [`locktime::absolute::Height`] and [`locktime::relative::Height`] types.
//!
//! The difference between these types and the locktime types is that these types are thin wrappers
//! whereas the locktime types contain more complex locktime specific abstractions.

use core::{fmt, ops};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::locktime;
use crate::locktime::{absolute, relative};

/// The block height, zero denotes the genesis block.
///
/// This type is not meant for constructing height based timelocks, this is a general purpose block
/// height abstraction. For locktimes please see [`locktime::absolute::Height`].
///
/// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// Public to try and make it really clear that there are no invariants.
pub struct BlockHeight(pub u32);

impl BlockHeight {
    /// Block height 0, the genesis block.
    pub const ZERO: Self = BlockHeight(0);

    /// The minimum block height (0), the genesis block.
    pub const MIN: Self = Self::ZERO;

    /// The maximum block height.
    pub const MAX: Self = BlockHeight(u32::MAX);

    /// Creates a block height from a `u32`.
    // Because From<u32> is not const.
    pub const fn from_u32(inner: u32) -> Self { Self(inner) }

    /// Returns block height as a `u32`.
    // Because type inference doesn't always work using `Into`.
    pub const fn to_u32(&self) -> u32 { self.0 }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

crate::impl_parse_str_from_int_infallible!(BlockHeight, u32, from);

impl From<u32> for BlockHeight {
    fn from(inner: u32) -> Self { Self::from_u32(inner) }
}

impl From<BlockHeight> for u32 {
    fn from(height: BlockHeight) -> Self { height.to_u32() }
}

impl From<absolute::Height> for BlockHeight {
    /// Converts a [`locktime::absolute::Height`] to a [`BlockHeight`].
    ///
    /// An absolute locktime block height has a maximum value of [`absolute::LOCK_TIME_THRESHOLD`]
    /// (500,000,000) where as a [`BlockHeight`] is a thin wrapper around a `u32`, the two types are
    /// not interchangeable.
    fn from(h: absolute::Height) -> Self { Self::from_u32(h.to_consensus_u32()) }
}

impl TryFrom<BlockHeight> for absolute::Height {
    type Error = absolute::ConversionError;

    /// Converts a [`BlockHeight`] to a [`locktime::absolute::Height`].
    ///
    /// An absolute locktime block height has a maximum value of [`absolute::LOCK_TIME_THRESHOLD`]
    /// (500,000,000) where as a [`BlockHeight`] is a thin wrapper around a `u32`, the two types are
    /// not interchangeable.
    fn try_from(h: BlockHeight) -> Result<Self, Self::Error> {
        absolute::Height::from_consensus(h.to_u32())
    }
}

/// The block interval.
///
/// Block interval is an integer type denoting the number of blocks that has passed since some point
/// i.e., this type is meant for usage as a relative block measure.
///
/// This type is not meant for constructing relative height based timelocks, this is a general
/// purpose block interval abstraction. For locktimes please see [`locktime::relative::Height`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// Public to try and make it really clear that there are no invariants.
pub struct BlockInterval(pub u32);

impl BlockInterval {
    /// Block interval 0 i.e., the current block.
    pub const ZERO: Self = BlockInterval(0);

    /// The minimum block interval (0).
    pub const MIN: Self = Self::ZERO;

    /// The maximum block interval.
    pub const MAX: Self = BlockInterval(u32::MAX);

    /// Creates a block interval from a `u32`.
    // Because From<u32> is not const.
    pub const fn from_u32(inner: u32) -> Self { Self(inner) }

    /// Returns block interval as a `u32`.
    // Because type inference doesn't always work using `Into`.
    pub const fn to_u32(&self) -> u32 { self.0 }
}

impl fmt::Display for BlockInterval {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

crate::impl_parse_str_from_int_infallible!(BlockInterval, u32, from);

impl From<u32> for BlockInterval {
    fn from(inner: u32) -> Self { Self::from_u32(inner) }
}

impl From<BlockInterval> for u32 {
    fn from(height: BlockInterval) -> Self { height.to_u32() }
}

impl From<relative::Height> for BlockInterval {
    /// Converts a [`locktime::relative::Height`] to a [`BlockInterval`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn from(h: relative::Height) -> Self { Self::from_u32(h.value().into()) }
}

impl TryFrom<BlockInterval> for relative::Height {
    type Error = TooBigForRelativeBlockHeightError;

    /// Converts a [`BlockInterval`] to a [`locktime::relative::Height`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn try_from(h: BlockInterval) -> Result<Self, Self::Error> {
        let h = h.to_u32();
        if h > u16::MAX as u32 {
            return Err(TooBigForRelativeBlockHeightError(h));
        }
        Ok(relative::Height::from(h as u16)) // Cast ok, value checked above
    }
}

/// Error returned when the block interval is too big to be used as a relative lock time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooBigForRelativeBlockHeightError(u32);

impl fmt::Display for TooBigForRelativeBlockHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "block interval is too big to be used as a relative lock time: {} (max: {})",
            self.0,
            relative::Height::MAX
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooBigForRelativeBlockHeightError {}

// height - height = interval
impl ops::Sub<BlockHeight> for BlockHeight {
    type Output = BlockInterval;

    fn sub(self, rhs: BlockHeight) -> Self::Output {
        let interval = self.to_u32() - rhs.to_u32();
        BlockInterval::from_u32(interval)
    }
}

// height + interval = height
impl ops::Add<BlockInterval> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: BlockInterval) -> Self::Output {
        let height = self.to_u32() + rhs.to_u32();
        BlockHeight::from_u32(height)
    }
}

// height - interval = height
impl ops::Sub<BlockInterval> for BlockHeight {
    type Output = BlockHeight;

    fn sub(self, rhs: BlockInterval) -> Self::Output {
        let height = self.to_u32() - rhs.to_u32();
        BlockHeight::from_u32(height)
    }
}

// interval + interval = interval
impl ops::Add<BlockInterval> for BlockInterval {
    type Output = BlockInterval;

    fn add(self, rhs: BlockInterval) -> Self::Output {
        let height = self.to_u32() + rhs.to_u32();
        BlockInterval::from_u32(height)
    }
}

impl ops::AddAssign<BlockInterval> for BlockInterval {
    fn add_assign(&mut self, rhs: BlockInterval) { self.0 = self.to_u32() + rhs.to_u32(); }
}

// interval - interval = interval
impl ops::Sub<BlockInterval> for BlockInterval {
    type Output = BlockInterval;

    fn sub(self, rhs: BlockInterval) -> Self::Output {
        let height = self.to_u32() - rhs.to_u32();
        BlockInterval::from_u32(height)
    }
}

impl ops::SubAssign<BlockInterval> for BlockInterval {
    fn sub_assign(&mut self, rhs: BlockInterval) { self.0 = self.to_u32() - rhs.to_u32(); }
}

/// This module holds implementations of stuff useful for writing test code.
#[cfg(feature = "test-infrastructure")]
mod testing_infrastructure {
    use super::*;
    use crate::testing_infrastructure::TestDummy;

    impl TestDummy for BlockHeight {
        fn test_dummy() -> BlockHeight { BlockHeight(800_000) }
    }

    impl TestDummy for BlockInterval {
        fn test_dummy() -> BlockInterval { BlockInterval(100) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests are supposed to comprise an exhaustive list of available operations.
    #[test]
    fn all_available_ops() {
        // height - height = interval
        assert!(BlockHeight(100) - BlockHeight(99) == BlockInterval(1));

        // height + interval = height
        assert!(BlockHeight(100) + BlockInterval(1) == BlockHeight(101));

        // height - interval == height
        assert!(BlockHeight(100) - BlockInterval(1) == BlockHeight(99));

        // interval + interval = interval
        assert!(BlockInterval(1) + BlockInterval(2) == BlockInterval(3));

        // interval - interval = interval
        assert!(BlockInterval(3) - BlockInterval(2) == BlockInterval(1));

        // interval += interval
        let mut int = BlockInterval(1);
        int += BlockInterval(2);
        assert_eq!(int, BlockInterval(3));

        // interval -= interval
        let mut int = BlockInterval(3);
        int -= BlockInterval(2);
        assert_eq!(int, BlockInterval(1));
    }
}
