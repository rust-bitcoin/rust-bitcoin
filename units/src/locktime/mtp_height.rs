// SPDX-License-Identifier: CC0-1.0

//! Provides [`MtpAndHeight`] structure for the `rust-bitcoin` `relative::LockTime` type.

use super::relative::{Height, Time, TimeOverflowError};
use crate::BlockTime;

/// A structure containing both Median Time Past (MTP) and current block height,
/// used for validating relative locktimes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MtpAndHeight {
    /// The Median Time Past (median of the last 11 blocks' timestamps)
    pub mtp: BlockTime,
    /// The current block height,
    pub height: Height,
}

impl MtpAndHeight {
    /// Build from the tip height and exactly 11 block-time (for MTP).
    ///
    /// # Parameters
    /// * `height` - The height of the chain tip
    /// * `timestamps` - Exactly 11 most recent timestamps of block headers in chronological order
    ///
    /// # Returns
    /// * A new `MtpAndHeight` with computed MTP and the provided height
    pub fn new(height: Height, timestamps: [BlockTime; 11]) -> Self {
        // Collect timestamps and get mtp
        let mut mtp_timestamps = timestamps;
        mtp_timestamps.sort_unstable();
        let mtp = mtp_timestamps[5];

        MtpAndHeight { mtp, height }
    }

    /// Convert the MTP seconds to a Time value for comparison with relative timelocks
    ///
    /// # Errors
    /// Returns a [`TimeOverflowError`] if the `mtp_seconds` value exceeds the valid range
    /// for a [`Time`] object.
    pub fn mtp_as_time(self) -> Result<Time, TimeOverflowError> {
        Time::from_seconds_floor(self.mtp.to_u32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_timestamps(start: u32, step: u16) -> [BlockTime; 11] {
        let mut timestamps = [BlockTime::from_u32(0); 11];
        for (i, ts) in timestamps.iter_mut().enumerate() {
            *ts = BlockTime::from_u32(start.saturating_sub((step * i as u16).into()));
        }
        timestamps
    }

    #[test]
    fn test_mtp_as_time() {
        let timestamps: [BlockTime; 11] = generate_timestamps(15_650_344, 600);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(15_245_344, 600);

        let current_height = Height::from_height(500);
        let utxo_height = Height::from_height(250);

        let chain_state = MtpAndHeight::new(current_height, timestamps);
        let utxo_state = MtpAndHeight::new(utxo_height, utxo_timestamps);

        let chain_state_mtp_as_time = chain_state.mtp_as_time().unwrap();
        let utxo_state_mtp_as_time = utxo_state.mtp_as_time().unwrap();

        assert_eq!(chain_state.mtp, BlockTime::from_u32(15_647_344));
        assert_eq!(chain_state.height, current_height);
        assert_eq!(utxo_state.mtp, BlockTime::from_u32(15_242_344));
        assert_eq!(utxo_state.height, utxo_height);

        assert_eq!(chain_state_mtp_as_time, Time::from_512_second_intervals(30561));
        assert_eq!(utxo_state_mtp_as_time, Time::from_512_second_intervals(29770));
    }

    #[test]
    fn test_mtp_as_time_error() {
        // using over-bloated figure that throws error when converting [`Test`]
        let timestamps: [BlockTime; 11] = generate_timestamps(1_400_000_000, 600);
        let utxo_timestamps: [BlockTime; 11] = generate_timestamps(1_250_600_340, 600);

        let current_height = Height::from_height(500);
        let utxo_height = Height::from_height(200);

        let chain_state = MtpAndHeight::new(current_height, timestamps);
        let utxo_state = MtpAndHeight::new(utxo_height, utxo_timestamps);

        let chain_state_mtp_as_time = chain_state.mtp_as_time();
        let utxo_state_mtp_as_time = utxo_state.mtp_as_time();
        assert_eq!(
            chain_state_mtp_as_time.err().unwrap(),
            TimeOverflowError { seconds: 1_399_997_000 }
        );
        assert_eq!(
            utxo_state_mtp_as_time.err().unwrap(),
            TimeOverflowError { seconds: 1_250_597_340 }
        );
    }

    #[test]
    fn valid_chain_computes_mtp() {
        let utxo_height = Height::from(980);
        let utxo_timestamps = generate_timestamps(1_647_010_695, 600);

        let current_height = Height::from_height(1000);
        let current_timestamps = generate_timestamps(1_647_026_892, 600);

        // Create MtpAndHeight instance
        let chain_state = MtpAndHeight::new(current_height, current_timestamps);
        let utxo_state = MtpAndHeight::new(utxo_height, utxo_timestamps);

        // Expected values
        // MTP is the median of the 11 timestamps, which is the 6th value (index 5 after sorting)
        let mut sorted_timestamps = current_timestamps;
        sorted_timestamps.sort_unstable();
        let expected_mtp = sorted_timestamps[5];

        let mut sorted_utxo_timestamps = utxo_timestamps;
        sorted_utxo_timestamps.sort_unstable();
        let expected_utxo_mtp = sorted_utxo_timestamps[5];

        // Verify MTP calculation
        assert_eq!(chain_state.mtp, expected_mtp);
        assert_eq!(utxo_state.mtp, expected_utxo_mtp);

        // Verify height values
        assert_eq!(chain_state.height, current_height);
        assert_eq!(utxo_state.height, utxo_height);
    }
}
