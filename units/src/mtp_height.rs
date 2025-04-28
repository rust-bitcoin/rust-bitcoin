// SPDX-License-Identifier: CC0-1.0

//! Median Time Past (MTP) and height - used for working lock times.

use crate::{BlockHeight, BlockTime};

/// A structure containing both Median Time Past (MTP) and current
/// absolute block height, used for validating relative locktimes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtpAndHeight {
    /// The Median Time Past (median of the last 11 blocks' timestamps)
    mtp: BlockTime,
    /// The current block height,
    height: BlockHeight,
}

impl MtpAndHeight {
    /// Constructs an [`MtpAndHeight`] by computing the median‐time‐past from the last 11 block timestamps
    ///
    /// # Parameters
    ///
    /// * `height` - The absolute height of the chain tip
    /// * `timestamps` - An array of timestamps from the most recent 11 blocks, where
    ///   - `timestamps[0]` is the timestamp at height `height - 10`
    ///   - `timestamps[1]` is the timestamp at height `height - 9`
    ///   - …
    ///   - `timestamps[10]` is the timestamp at height `height`
    pub fn new(height: BlockHeight, timestamps: [BlockTime; 11]) -> Self {
        let mut mtp_timestamps = timestamps;
        mtp_timestamps.sort_unstable();
        let mtp = mtp_timestamps[5];

        MtpAndHeight { mtp, height }
    }

    /// Returns the median-time-past component.
    pub fn to_mtp(self) -> BlockTime { self.mtp }

    /// Returns the block-height component.
    pub fn to_height(self) -> BlockHeight { self.height }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_chain_computes_mtp() {
        let height = BlockHeight::from_u32(100);
        let timestamps = [
            BlockTime::from_u32(10),
            BlockTime::from_u32(3),
            BlockTime::from_u32(5),
            BlockTime::from_u32(8),
            BlockTime::from_u32(1),
            BlockTime::from_u32(4),
            BlockTime::from_u32(6),
            BlockTime::from_u32(9),
            BlockTime::from_u32(2),
            BlockTime::from_u32(7),
            BlockTime::from_u32(0),
        ];

        let result = MtpAndHeight::new(height, timestamps);
        assert_eq!(result.height, height);
        assert_eq!(result.mtp.to_u32(), 5);
    }
}
