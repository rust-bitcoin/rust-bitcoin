// SPDX-License-Identifier: CC0-1.0

//! Block height and interval types.
//!
//! These types are thin wrappers around `u32`, no invariants implemented or implied.
//!
//! These are general types for abstracting over block heights, they are not designed to use with
//! lock times. If you are creating lock times you should be using the
//! [`locktime::absolute::Height`] and [`locktime::relative::NumberOfBlocks`] types.
//!
//! The difference between these types and the locktime types is that these types are thin wrappers
//! whereas the locktime types contain more complex locktime specific abstractions.

#[cfg(feature = "encoding")]
use core::convert::Infallible;
use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(feature = "encoding")]
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

        impl fmt::Display for $newtype {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
        }

        crate::parse_int::impl_parse_str_from_int_infallible!($newtype, u32, from);

        impl From<u32> for $newtype {
            fn from(inner: u32) -> Self { Self::from_u32(inner) }
        }

        impl From<$newtype> for u32 {
            fn from(height: $newtype) -> Self { height.to_u32() }
        }

        #[cfg(feature = "serde")]
        impl Serialize for $newtype {
            #[inline]
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                u32::serialize(&self.to_u32(), s)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $newtype {
            #[inline]
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(Self::from_u32(u32::deserialize(d)?))
            }
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
    pub struct BlockHeight(u32);
}

impl BlockHeight {
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

    /// Attempt to subtract two [`BlockHeight`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<BlockHeightInterval> {
        self.to_u32().checked_sub(other.to_u32()).map(BlockHeightInterval)
    }

    /// Attempt to add an interval to this [`BlockHeight`], returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_add(self, other: BlockHeightInterval) -> Option<Self> {
        self.to_u32().checked_add(other.to_u32()).map(Self)
    }
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
    fn try_from(h: BlockHeight) -> Result<Self, Self::Error> { Self::from_u32(h.to_u32()) }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype! {
    /// The encoder for the [`BlockHeight`] type.
    pub struct BlockHeightEncoder(encoding::ArrayEncoder<4>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for BlockHeight {
    type Encoder<'e> = BlockHeightEncoder;
    fn encoder(&self) -> Self::Encoder<'_> {
        BlockHeightEncoder(encoding::ArrayEncoder::without_length_prefix(
            self.to_u32().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`BlockHeight`] type.
#[cfg(feature = "encoding")]
pub struct BlockHeightDecoder(encoding::ArrayDecoder<4>);

#[cfg(feature = "encoding")]
impl Default for BlockHeightDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl BlockHeightDecoder {
    /// Constructs a new [`BlockHeight`] decoder.
    pub fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for BlockHeightDecoder {
    type Output = BlockHeight;
    type Error = BlockHeightDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(BlockHeightDecoderError)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let n = u32::from_le_bytes(self.0.end().map_err(BlockHeightDecoderError)?);
        Ok(BlockHeight::from_u32(n))
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for BlockHeight {
    type Decoder = BlockHeightDecoder;
    fn decoder() -> Self::Decoder { BlockHeightDecoder(encoding::ArrayDecoder::<4>::new()) }
}

/// An error consensus decoding an `BlockHeight`.
#[cfg(feature = "encoding")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeightDecoderError(encoding::UnexpectedEofError);

#[cfg(feature = "encoding")]
impl From<Infallible> for BlockHeightDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "encoding")]
impl fmt::Display for BlockHeightDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "block height decoder error"; self.0)
    }
}

#[cfg(all(feature = "std", feature = "encoding"))]
impl std::error::Error for BlockHeightDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

impl_u32_wrapper! {
    /// An unsigned block interval.
    ///
    /// Block interval is an integer type representing a difference between the heights of two blocks.
    ///
    /// This type is not meant for constructing relative height based timelocks. It is a general
    /// purpose block interval abstraction. For locktimes please see [`locktime::relative::NumberOfBlocks`].
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BlockHeightInterval(u32);
}

impl BlockHeightInterval {
    /// Block interval 0.
    pub const ZERO: Self = Self(0);

    /// The minimum block interval, equivalent to `Self::ZERO`.
    pub const MIN: Self = Self::ZERO;

    /// The maximum block interval.
    pub const MAX: Self = Self(u32::MAX);

    /// Constructs a new block interval from a `u32`.
    pub const fn from_u32(inner: u32) -> Self { Self(inner) }

    /// Returns block interval as a `u32`.
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Attempt to subtract two [`BlockHeightInterval`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.to_u32().checked_sub(other.to_u32()).map(Self)
    }

    /// Attempt to add two [`BlockHeightInterval`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.to_u32().checked_add(other.to_u32()).map(Self)
    }
}

impl From<relative::NumberOfBlocks> for BlockHeightInterval {
    /// Converts a [`locktime::relative::NumberOfBlocks`] to a [`BlockHeightInterval`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockHeightInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn from(h: relative::NumberOfBlocks) -> Self { Self::from_u32(h.to_height().into()) }
}

impl TryFrom<BlockHeightInterval> for relative::NumberOfBlocks {
    type Error = TooBigForRelativeHeightError;

    /// Converts a [`BlockHeightInterval`] to a [`locktime::relative::NumberOfBlocks`].
    ///
    /// A relative locktime block height has a maximum value of `u16::MAX` where as a
    /// [`BlockHeightInterval`] is a thin wrapper around a `u32`, the two types are not interchangeable.
    fn try_from(h: BlockHeightInterval) -> Result<Self, Self::Error> {
        u16::try_from(h.to_u32())
            .map(Self::from)
            .map_err(|_| TooBigForRelativeHeightError(h.into()))
    }
}

impl_u32_wrapper! {
    /// The median timestamp of 11 consecutive blocks.
    ///
    /// This type is not meant for constructing time-based timelocks. It is a general purpose
    /// MTP abstraction. For locktimes please see [`locktime::absolute::MedianTimePast`].
    ///
    /// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BlockMtp(u32);
}

impl BlockMtp {
    /// Block MTP 0.
    ///
    /// Since MTP is a timestamp, 0 is before Bitcoin was invented. This const may still be useful
    /// for some use cases e.g., folding a sum of intervals.
    pub const ZERO: Self = Self(0);

    /// The minimum block MTP, equivalent to `Self::ZERO`.
    pub const MIN: Self = Self::ZERO;

    /// The maximum block MTP.
    pub const MAX: Self = Self(u32::MAX);

    /// Constructs a new block MTP from a `u32`.
    pub const fn from_u32(inner: u32) -> Self { Self(inner) }

    /// Returns block MTP as a `u32`.
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Constructs a [`BlockMtp`] by computing the median‐time‐past from the last 11 block timestamps
    ///
    /// Because block timestamps are not monotonic, this function internally sorts them;
    /// it is therefore not important what order they appear in the array; use whatever
    /// is most convenient.
    pub fn new(mut timestamps: [crate::BlockTime; 11]) -> Self {
        timestamps.sort_unstable();
        Self::from_u32(u32::from(timestamps[5]))
    }

    /// Attempt to subtract two [`BlockMtp`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<BlockMtpInterval> {
        self.to_u32().checked_sub(other.to_u32()).map(BlockMtpInterval)
    }

    /// Attempt to add an interval to this [`BlockMtp`], returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_add(self, other: BlockMtpInterval) -> Option<Self> {
        self.to_u32().checked_add(other.to_u32()).map(Self)
    }
}

impl From<absolute::MedianTimePast> for BlockMtp {
    /// Converts a [`locktime::absolute::MedianTimePast`] to a [`BlockMtp`].
    ///
    /// An absolute locktime MTP has a minimum value of [`absolute::LOCK_TIME_THRESHOLD`],
    /// while [`BlockMtp`] may take the full range of `u32`.
    fn from(h: absolute::MedianTimePast) -> Self { Self::from_u32(h.to_u32()) }
}

impl TryFrom<BlockMtp> for absolute::MedianTimePast {
    type Error = absolute::ConversionError;

    /// Converts a [`BlockHeight`] to a [`locktime::absolute::Height`].
    ///
    /// An absolute locktime MTP has a minimum value of [`absolute::LOCK_TIME_THRESHOLD`],
    /// while [`BlockMtp`] may take the full range of `u32`.
    fn try_from(h: BlockMtp) -> Result<Self, Self::Error> { Self::from_u32(h.to_u32()) }
}

impl_u32_wrapper! {
    /// An unsigned difference between two [`BlockMtp`]s.
    ///
    /// This type is not meant for constructing time-based timelocks. It is a general purpose
    /// MTP abstraction. For locktimes please see [`locktime::relative::NumberOf512Seconds`].
    ///
    /// This is a thin wrapper around a `u32` that may take on all values of a `u32`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BlockMtpInterval(u32);
}

impl BlockMtpInterval {
    /// Block MTP interval 0.
    pub const ZERO: Self = Self(0);

    /// The minimum block MTP interval, equivalent to `Self::ZERO`.
    pub const MIN: Self = Self::ZERO;

    /// The maximum block MTP interval.
    pub const MAX: Self = Self(u32::MAX);

    /// Constructs a new block MTP interval from a `u32`.
    pub const fn from_u32(inner: u32) -> Self { Self(inner) }

    /// Returns block MTP interval as a `u32`.
    pub const fn to_u32(self) -> u32 { self.0 }

    /// Converts a [`BlockMtpInterval`] to a [`locktime::relative::NumberOf512Seconds`], rounding down.
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
    ) -> Result<relative::NumberOf512Seconds, relative::TimeOverflowError> {
        relative::NumberOf512Seconds::from_seconds_floor(self.to_u32())
    }

    /// Converts a [`BlockMtpInterval`] to a [`locktime::relative::NumberOf512Seconds`], rounding up.
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
    ) -> Result<relative::NumberOf512Seconds, relative::TimeOverflowError> {
        relative::NumberOf512Seconds::from_seconds_ceil(self.to_u32())
    }

    /// Attempt to subtract two [`BlockMtpInterval`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.to_u32().checked_sub(other.to_u32()).map(Self)
    }

    /// Attempt to add two [`BlockMtpInterval`]s, returning `None` if overflow occurred.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.to_u32().checked_add(other.to_u32()).map(Self)
    }
}

impl From<relative::NumberOf512Seconds> for BlockMtpInterval {
    /// Converts a [`locktime::relative::NumberOf512Seconds`] to a [`BlockMtpInterval `].
    ///
    /// A relative locktime MTP interval has a resolution of 512 seconds, and a maximum value
    /// of `u16::MAX` 512-second intervals. [`BlockMtpInterval`] may take the full range of
    /// `u32`.
    fn from(h: relative::NumberOf512Seconds) -> Self { Self::from_u32(h.to_seconds()) }
}

/// Error returned when the block interval is too big to be used as a relative lock time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooBigForRelativeHeightError(u32);

impl fmt::Display for TooBigForRelativeHeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "block interval is too big to be used as a relative lock time: {} (max: {})",
            self.0,
            relative::NumberOfBlocks::MAX
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TooBigForRelativeHeightError {}

crate::internal_macros::impl_op_for_references! {
    // height - height = interval
    impl ops::Sub<BlockHeight> for BlockHeight {
        type Output = BlockHeightInterval;

        fn sub(self, rhs: BlockHeight) -> Self::Output {
            let interval = self.to_u32() - rhs.to_u32();
            BlockHeightInterval::from_u32(interval)
        }
    }

    // height + interval = height
    impl ops::Add<BlockHeightInterval> for BlockHeight {
        type Output = BlockHeight;

        fn add(self, rhs: BlockHeightInterval) -> Self::Output {
            let height = self.to_u32() + rhs.to_u32();
            BlockHeight::from_u32(height)
        }
    }

    // height - interval = height
    impl ops::Sub<BlockHeightInterval> for BlockHeight {
        type Output = BlockHeight;

        fn sub(self, rhs: BlockHeightInterval) -> Self::Output {
            let height = self.to_u32() - rhs.to_u32();
            BlockHeight::from_u32(height)
        }
    }

    // interval + interval = interval
    impl ops::Add<BlockHeightInterval> for BlockHeightInterval {
        type Output = BlockHeightInterval;

        fn add(self, rhs: BlockHeightInterval) -> Self::Output {
            let height = self.to_u32() + rhs.to_u32();
            BlockHeightInterval::from_u32(height)
        }
    }

    // interval - interval = interval
    impl ops::Sub<BlockHeightInterval> for BlockHeightInterval {
        type Output = BlockHeightInterval;

        fn sub(self, rhs: BlockHeightInterval) -> Self::Output {
            let height = self.to_u32() - rhs.to_u32();
            BlockHeightInterval::from_u32(height)
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

crate::internal_macros::impl_add_assign!(BlockHeightInterval);
crate::internal_macros::impl_sub_assign!(BlockHeightInterval);
crate::internal_macros::impl_add_assign!(BlockMtpInterval);
crate::internal_macros::impl_sub_assign!(BlockMtpInterval);

impl core::iter::Sum for BlockHeightInterval {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.map(Self::to_u32).sum();
        Self::from_u32(sum)
    }
}

impl<'a> core::iter::Sum<&'a Self> for BlockHeightInterval {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let sum = iter.map(|interval| interval.to_u32()).sum();
        Self::from_u32(sum)
    }
}

impl core::iter::Sum for BlockMtpInterval {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.map(Self::to_u32).sum();
        Self::from_u32(sum)
    }
}

impl<'a> core::iter::Sum<&'a Self> for BlockMtpInterval {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let sum = iter.map(|interval| interval.to_u32()).sum();
        Self::from_u32(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locktime::relative::NumberOf512Seconds;

    #[test]
    fn sanity_check() {
        let height: u32 = BlockHeight(100).into();
        assert_eq!(height, 100);

        let interval: u32 = BlockHeightInterval(100).into();
        assert_eq!(interval, 100);

        let interval_from_height: BlockHeightInterval =
            relative::NumberOfBlocks::from(10u16).into();
        assert_eq!(interval_from_height.to_u32(), 10u32);

        let invalid_height_greater =
            relative::NumberOfBlocks::try_from(BlockHeightInterval(u32::from(u16::MAX) + 1));
        assert!(invalid_height_greater.is_err());

        let valid_height =
            relative::NumberOfBlocks::try_from(BlockHeightInterval(u32::from(u16::MAX)));
        assert!(valid_height.is_ok());
    }

    // These tests are supposed to comprise an exhaustive list of available operations.
    #[test]
    fn all_available_ops() {
        // height - height = interval
        assert!(BlockHeight(10) - BlockHeight(7) == BlockHeightInterval(3));

        // height + interval = height
        assert!(BlockHeight(100) + BlockHeightInterval(1) == BlockHeight(101));

        // height - interval == height
        assert!(BlockHeight(100) - BlockHeightInterval(1) == BlockHeight(99));

        // interval + interval = interval
        assert!(BlockHeightInterval(1) + BlockHeightInterval(2) == BlockHeightInterval(3));

        // interval - interval = interval
        assert!(BlockHeightInterval(10) - BlockHeightInterval(7) == BlockHeightInterval(3));

        // Sum for BlockHeightInterval by reference and by value
        assert!(
            [BlockHeightInterval(1), BlockHeightInterval(2), BlockHeightInterval(3)]
                .iter()
                .sum::<BlockHeightInterval>()
                == BlockHeightInterval(6)
        );
        assert!(
            [BlockHeightInterval(4), BlockHeightInterval(5), BlockHeightInterval(6)]
                .into_iter()
                .sum::<BlockHeightInterval>()
                == BlockHeightInterval(15)
        );

        // Sum for BlockMtpInterval by reference and by value
        assert!(
            [BlockMtpInterval(1), BlockMtpInterval(2), BlockMtpInterval(3)]
                .iter()
                .sum::<BlockMtpInterval>()
                == BlockMtpInterval(6)
        );
        assert!(
            [BlockMtpInterval(4), BlockMtpInterval(5), BlockMtpInterval(6)]
                .into_iter()
                .sum::<BlockMtpInterval>()
                == BlockMtpInterval(15)
        );

        // interval += interval
        let mut int = BlockHeightInterval(1);
        int += BlockHeightInterval(2);
        assert_eq!(int, BlockHeightInterval(3));

        // interval -= interval
        let mut int = BlockHeightInterval(10);
        int -= BlockHeightInterval(7);
        assert_eq!(int, BlockHeightInterval(3));
    }

    #[test]
    fn block_height_checked() {
        let a = BlockHeight(10);
        let b = BlockHeight(5);
        assert_eq!(a.checked_sub(b), Some(BlockHeightInterval(5)));
        assert_eq!(a.checked_add(BlockHeightInterval(5)), Some(BlockHeight(15)));
        assert_eq!(a.checked_sub(BlockHeight(11)), None);
        assert_eq!(a.checked_add(BlockHeightInterval(u32::MAX - 5)), None);
    }

    #[test]
    fn block_height_interval_checked() {
        let a = BlockHeightInterval(10);
        let b = BlockHeightInterval(5);
        assert_eq!(a.checked_sub(b), Some(BlockHeightInterval(5)));
        assert_eq!(a.checked_add(b), Some(BlockHeightInterval(15)));
        assert_eq!(a.checked_sub(BlockHeightInterval(11)), None);
        assert_eq!(a.checked_add(BlockHeightInterval(u32::MAX - 5)), None);
    }

    #[test]
    fn block_mtp_interval_checked() {
        let a = BlockMtpInterval(10);
        let b = BlockMtpInterval(5);
        assert_eq!(a.checked_sub(b), Some(BlockMtpInterval(5)));
        assert_eq!(a.checked_add(b), Some(BlockMtpInterval(15)));
        assert_eq!(a.checked_sub(BlockMtpInterval(11)), None);
        assert_eq!(a.checked_add(BlockMtpInterval(u32::MAX - 5)), None);
    }

    #[test]
    fn block_mtp_checked() {
        let a = BlockMtp(10);
        let b = BlockMtp(5);
        assert_eq!(a.checked_sub(b), Some(BlockMtpInterval(5)));
        assert_eq!(a.checked_add(BlockMtpInterval(5)), Some(BlockMtp(15)));
        assert_eq!(a.checked_sub(BlockMtp(11)), None);
        assert_eq!(a.checked_add(BlockMtpInterval(u32::MAX - 5)), None);
    }

    #[test]
    fn block_mtp_interval_from_number_of_512seconds() {
        let n = NumberOf512Seconds::from_seconds_floor(0).unwrap();
        let interval = BlockMtpInterval::from(n);
        assert_eq!(interval, BlockMtpInterval(0));
        let n = NumberOf512Seconds::from_seconds_floor(1024).unwrap();
        let interval = BlockMtpInterval::from(n);
        assert_eq!(interval, BlockMtpInterval(1024));
    }
}
