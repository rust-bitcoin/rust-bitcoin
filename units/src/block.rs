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

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::locktime;
use crate::locktime::{absolute, relative};

macro_rules! impl_u32_wrapper {
    {
        $(#[$($type_attrs:tt)*])*
        $type_vis:vis struct $newtype:ident($inner_vis:vis u32);
    } => {
        $(#[$($type_attrs)*])*
        $type_vis struct $newtype($inner_vis u32);

        impl $newtype {
            /// Block height 0, the genesis block.
            pub const ZERO: Self = Self(0);

            /// The minimum block height (0), the genesis block.
            pub const MIN: Self = Self::ZERO;

            /// The maximum block height.
            pub const MAX: Self = Self(u32::MAX);

            /// Constructs a new block height from a `u32`.
            pub const fn from_u32(inner: u32) -> Self { Self(inner) }

            /// Returns block height as a `u32`.
            pub const fn to_u32(self) -> u32 { self.0 }
        }

        impl fmt::Display for $newtype {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
        }

        crate::impl_parse_str_from_int_infallible!($newtype, u32, from);

        impl From<u32> for $newtype {
            fn from(inner: u32) -> Self { Self::from_u32(inner) }
        }

        impl From<$newtype> for u32 {
            fn from(height: $newtype) -> Self { height.to_u32() }
        }

        #[cfg(feature = "arbitrary")]
        impl<'a> Arbitrary<'a> for $newtype {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                let choice = u.int_in_range(0..=2)?;
                match choice {
                    0 => Ok(Self::ZERO),
                    1 => Ok(Self::MIN),
                    2 => Ok(Self::MAX),
                    _ => Ok(Self::from_u32(u32::arbitrary(u)?)),
                }
            }
        }
    }
}

impl_u32_wrapper! {
    /// A block height. Zero denotes the genesis block.
    ///
    /// This type is not meant for constructing height based timelocks. It is a general purpose
    /// blockheight abstraction. For locktimes please see [`locktime::absolute::Height`].
    ///
    /// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    // Public to try and make it really clear that there are no invariants.
    pub struct BlockHeight(pub u32);
}

impl From<absolute::Height> for BlockHeight {
    /// Converts a [`locktime::absolute::Height`] to a [`BlockHeight`].
    ///
    /// An absolute locktime block height has a maximum value of [`absolute::LOCK_TIME_THRESHOLD`]
    /// minus one, while [`BlockHeight`] may take the full range of `u32`.
    fn from(h: absolute::Height) -> Self { Self::from_u32(h.to_u32()) }
}

impl TryFrom<BlockHeight> for absolute::Height {
    type Error = absolute::ConversionError;

    /// Converts a [`BlockHeight`] to a [`locktime::absolute::Height`].
    ///
    /// An absolute locktime block height has a maximum value of [`absolute::LOCK_TIME_THRESHOLD`]
    /// minus one, while [`BlockHeight`] may take the full range of `u32`.
    fn try_from(h: BlockHeight) -> Result<Self, Self::Error> {
        absolute::Height::from_u32(h.to_u32())
    }
}

impl_u32_wrapper! {
    /// An unsigned block interval.
    ///
    /// Block interval is an integer type representing a difference between the heights of two blocks.
    ///
    /// This type is not meant for constructing relative height based timelocks. It is a general
    /// purpose block interval abstraction. For locktimes please see [`locktime::relative::Height`].
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    // Public to try and make it really clear that there are no invariants.
    pub struct BlockInterval(pub u32);
}

impl From<relative::HeightInterval> for BlockInterval {
    /// Converts a [`locktime::relative::HeightInterval`] to a [`BlockInterval`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn from(h: relative::HeightInterval) -> Self { Self::from_u32(h.to_height().into()) }
}

impl TryFrom<BlockInterval> for relative::HeightInterval {
    type Error = TooBigForRelativeBlockHeightIntervalError;

    /// Converts a [`BlockInterval`] to a [`locktime::relative::HeightInterval`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn try_from(h: BlockInterval) -> Result<Self, Self::Error> {
        let h = h.to_u32();

        if h > u32::from(u16::MAX) {
            return Err(TooBigForRelativeBlockHeightIntervalError(h));
        }
        Ok(relative::HeightInterval::from(h as u16)) // Cast ok, value checked above.
    }
}

impl_u32_wrapper! {
    /// The median timestamp of 11 consecutive blocks.
    ///
    /// This type is not meant for constructing time-based timelocks. It is a general purpose
    /// MTP abstraction. For locktimes please see [`locktime::absolute::Mtp`].
    ///
    /// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    // Public to try and make it really clear that there are no invariants.
    pub struct BlockMtp(pub u32);
}

impl BlockMtp {
    /// Constructs a [`BlockMtp`] by computing the median‐time‐past from the last 11 block timestamps
    ///
    /// Because block timestamps are not monotonic, this function internally sorts them;
    /// it is therefore not important what order they appear in the array; use whatever
    /// is most convenient.
    pub fn new(mut timestamps: [crate::BlockTime; 11]) -> Self {
        timestamps.sort_unstable();
        Self::from_u32(u32::from(timestamps[5]))
    }
}

impl From<absolute::Mtp> for BlockMtp {
    /// Converts a [`locktime::absolute::Mtp`] to a [`BlockMtp`].
    ///
    /// An absolute locktime MTP has a minimum value of [`absolute::LOCK_TIME_THRESHOLD`],
    /// while [`BlockMtp`] may take the full range of `u32`.
    fn from(h: absolute::Mtp) -> Self { Self::from_u32(h.to_u32()) }
}

impl TryFrom<BlockMtp> for absolute::Mtp {
    type Error = absolute::ConversionError;

    /// Converts a [`BlockHeight`] to a [`locktime::absolute::Height`].
    ///
    /// An absolute locktime MTP has a minimum value of [`absolute::LOCK_TIME_THRESHOLD`],
    /// while [`BlockMtp`] may take the full range of `u32`.
    fn try_from(h: BlockMtp) -> Result<Self, Self::Error> { absolute::Mtp::from_u32(h.to_u32()) }
}

impl_u32_wrapper! {
    /// An unsigned difference between two [`BlockMtp`]s.
    ///
    /// This type is not meant for constructing time-based timelocks. It is a general purpose
    /// MTP abstraction. For locktimes please see [`locktime::relative::MtpInterval`].
    ///
    /// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    // Public to try and make it really clear that there are no invariants.
    pub struct BlockMtpInterval(pub u32);
}

impl BlockMtpInterval {
    /// Converts a [`BlockMtpInterval`] to a [`locktime::relative::MtpInterval`], rounding down.
    ///
    /// Relative timelock MTP intervals have a resolution of 512 seconds, while
    /// [`BlockMtpInterval`], like all block timestamp types, has a one-second resolution.
    ///
    /// # Errors
    ///
    /// Errors if the MTP is out-of-range (in excess of 512 times `u16::MAX` seconds, or about
    /// 388 days) for a time-based relative locktime.
    #[inline]
    pub const fn to_relative_mtp_interval_floor(
        self,
    ) -> Result<relative::MtpInterval, relative::TimeOverflowError> {
        relative::MtpInterval::from_seconds_floor(self.to_u32())
    }

    /// Converts a [`BlockMtpInterval`] to a [`locktime::relative::MtpInterval`], rounding up.
    ///
    /// Relative timelock MTP intervals have a resolution of 512 seconds, while
    /// [`BlockMtpInterval`], like all block timestamp types, has a one-second resolution.
    ///
    /// # Errors
    ///
    /// Errors if the MTP is out-of-range (in excess of 512 times `u16::MAX` seconds, or about
    /// 388 days) for a time-based relative locktime.
    #[inline]
    pub const fn to_relative_mtp_interval_ceil(
        self,
    ) -> Result<relative::MtpInterval, relative::TimeOverflowError> {
        relative::MtpInterval::from_seconds_ceil(self.to_u32())
    }
}

impl From<relative::MtpInterval> for BlockMtpInterval {
    /// Converts a [`locktime::relative::MtpInterval`] to a [`BlockMtpInterval `].
    ///
    /// A relative locktime MTP interval has a resolution of 512 seconds, and a maximum value
    /// of `u16::MAX` 512-second intervals. [`BlockMtpInterval`] may take the full range of
    /// `u32`.
    fn from(h: relative::MtpInterval) -> Self { Self::from_u32(h.to_seconds()) }
}

/// Error returned when the block interval is too big to be used as a relative lock time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooBigForRelativeBlockHeightIntervalError(u32);

impl fmt::Display for TooBigForRelativeBlockHeightIntervalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "block interval is too big to be used as a relative lock time: {} (max: {})",
            self.0,
            relative::HeightInterval::MAX
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooBigForRelativeBlockHeightIntervalError {}

crate::internal_macros::impl_op_for_references! {
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

    // interval - interval = interval
    impl ops::Sub<BlockInterval> for BlockInterval {
        type Output = BlockInterval;

        fn sub(self, rhs: BlockInterval) -> Self::Output {
            let height = self.to_u32() - rhs.to_u32();
            BlockInterval::from_u32(height)
        }
    }

    // height - height = interval
    impl ops::Sub<BlockMtp> for BlockMtp {
        type Output = BlockMtpInterval;

        fn sub(self, rhs: BlockMtp) -> Self::Output {
            let interval = self.to_u32() - rhs.to_u32();
            BlockMtpInterval::from_u32(interval)
        }
    }

    // height + interval = height
    impl ops::Add<BlockMtpInterval> for BlockMtp {
        type Output = BlockMtp;

        fn add(self, rhs: BlockMtpInterval) -> Self::Output {
            let height = self.to_u32() + rhs.to_u32();
            BlockMtp::from_u32(height)
        }
    }

    // height - interval = height
    impl ops::Sub<BlockMtpInterval> for BlockMtp {
        type Output = BlockMtp;

        fn sub(self, rhs: BlockMtpInterval) -> Self::Output {
            let height = self.to_u32() - rhs.to_u32();
            BlockMtp::from_u32(height)
        }
    }

    // interval + interval = interval
    impl ops::Add<BlockMtpInterval> for BlockMtpInterval {
        type Output = BlockMtpInterval;

        fn add(self, rhs: BlockMtpInterval) -> Self::Output {
            let height = self.to_u32() + rhs.to_u32();
            BlockMtpInterval::from_u32(height)
        }
    }

    // interval - interval = interval
    impl ops::Sub<BlockMtpInterval> for BlockMtpInterval {
        type Output = BlockMtpInterval;

        fn sub(self, rhs: BlockMtpInterval) -> Self::Output {
            let height = self.to_u32() - rhs.to_u32();
            BlockMtpInterval::from_u32(height)
        }
    }
}

crate::internal_macros::impl_add_assign!(BlockInterval);
crate::internal_macros::impl_sub_assign!(BlockInterval);
crate::internal_macros::impl_add_assign!(BlockMtpInterval);
crate::internal_macros::impl_sub_assign!(BlockMtpInterval);

impl core::iter::Sum for BlockInterval {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.map(|interval| interval.0).sum();
        BlockInterval::from_u32(sum)
    }
}

impl<'a> core::iter::Sum<&'a BlockInterval> for BlockInterval {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a BlockInterval>,
    {
        let sum = iter.map(|interval| interval.0).sum();
        BlockInterval::from_u32(sum)
    }
}

impl core::iter::Sum for BlockMtpInterval {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.map(|interval| interval.0).sum();
        BlockMtpInterval::from_u32(sum)
    }
}

impl<'a> core::iter::Sum<&'a BlockMtpInterval> for BlockMtpInterval {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a BlockMtpInterval>,
    {
        let sum = iter.map(|interval| interval.0).sum();
        BlockMtpInterval::from_u32(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let height: u32 = BlockHeight(100).into();
        assert_eq!(height, 100);

        let interval: u32 = BlockInterval(100).into();
        assert_eq!(interval, 100);

        let interval_from_height: BlockInterval = relative::HeightInterval::from(10u16).into();
        assert_eq!(interval_from_height.to_u32(), 10u32);

        let invalid_height_greater =
            relative::HeightInterval::try_from(BlockInterval(u32::from(u16::MAX) + 1));
        assert!(invalid_height_greater.is_err());

        let valid_height = relative::HeightInterval::try_from(BlockInterval(u32::from(u16::MAX)));
        assert!(valid_height.is_ok());
    }

    // These tests are supposed to comprise an exhaustive list of available operations.
    #[test]
    fn all_available_ops() {
        // height - height = interval
        assert!(BlockHeight(10) - BlockHeight(7) == BlockInterval(3));

        // height + interval = height
        assert!(BlockHeight(100) + BlockInterval(1) == BlockHeight(101));

        // height - interval == height
        assert!(BlockHeight(100) - BlockInterval(1) == BlockHeight(99));

        // interval + interval = interval
        assert!(BlockInterval(1) + BlockInterval(2) == BlockInterval(3));

        // interval - interval = interval
        assert!(BlockInterval(10) - BlockInterval(7) == BlockInterval(3));

        assert!(
            [BlockInterval(1), BlockInterval(2), BlockInterval(3)].iter().sum::<BlockInterval>()
                == BlockInterval(6)
        );
        assert!(
            [BlockInterval(4), BlockInterval(5), BlockInterval(6)]
                .into_iter()
                .sum::<BlockInterval>()
                == BlockInterval(15)
        );

        // interval += interval
        let mut int = BlockInterval(1);
        int += BlockInterval(2);
        assert_eq!(int, BlockInterval(3));

        // interval -= interval
        let mut int = BlockInterval(10);
        int -= BlockInterval(7);
        assert_eq!(int, BlockInterval(3));
    }
}
