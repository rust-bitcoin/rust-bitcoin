// SPDX-License-Identifier: CC0-1.0

//! Working with Bitcoin lock times.
//!
//! Bitcoin has two lock time mechanisms:
//!
//! - **Absolute lock times** (`nLockTime` / `OP_CHECKLOCKTIMEVERIFY`): a transaction
//!   cannot be mined until a certain block height or time.
//! - **Relative lock times** (`nSequence` / `OP_CHECKSEQUENCEVERIFY`, BIP-68/112): a
//!   transaction input cannot be spent until a certain number of blocks or time has
//!   elapsed since the referenced output was mined.
//!
//! This example covers both, including the height/time threshold, satisfaction
//! checks, and the relationship between `Sequence` and relative lock times.

use bitcoin_units::locktime::absolute::{self, Height, LockTime, MedianTimePast};
use bitcoin_units::locktime::relative::{
    self, LockTime as RelLockTime, NumberOf512Seconds, NumberOfBlocks,
};
use bitcoin_units::{BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval};

fn main() {
    absolute_lock_times();
    absolute_satisfaction();
    relative_lock_times();
    relative_satisfaction();
    block_height_and_mtp_types();
}

/// Absolute lock times encode either a block height or a UNIX timestamp in a
/// single `u32`. The threshold is 500,000,000: values below it are block
/// heights, values at or above are timestamps (median time past).
fn absolute_lock_times() {
    // Values below 500,000,000 are block heights.
    assert!(absolute::is_block_height(499_999_999));
    assert!(!absolute::is_block_height(500_000_000));

    // from_consensus auto-dispatches based on the threshold.
    let by_height = LockTime::from_consensus(800_000);
    assert!(by_height.is_block_height());

    let by_time = LockTime::from_consensus(1_700_000_000);
    assert!(by_time.is_block_time());

    // Typed constructors enforce the correct range.
    let h = Height::from_u32(800_000).expect("valid height");
    assert_eq!(h.to_u32(), 800_000);

    let t = MedianTimePast::from_u32(1_700_000_000).expect("valid MTP");
    assert_eq!(t.to_u32(), 1_700_000_000);

    // Heights and times cannot be compared across units.
    let lock_h = LockTime::from(h);
    let lock_t = LockTime::from(t);
    assert!(!lock_h.is_same_unit(&lock_t));

    // nLockTime 0 is always satisfied — the transaction can be included in any block.
    assert_eq!(LockTime::ZERO, LockTime::from_consensus(0));
}

/// An absolute lock time is satisfied when the chain tip has reached the
/// specified height or time.
fn absolute_satisfaction() {
    let lock = LockTime::from_height(100).expect("valid");

    let chain_height = Height::from_u32(99).unwrap();
    let chain_mtp = MedianTimePast::from_u32(500_000_100).unwrap();

    // Height 99 satisfies lock 100: the tx can be mined in block 100
    // (is_satisfied_by checks lock_height <= chain_tip + 1).
    assert!(lock.is_satisfied_by(chain_height, chain_mtp));

    // Height 98 does not satisfy it.
    let too_early = Height::from_u32(98).unwrap();
    assert!(!lock.is_satisfied_by(too_early, chain_mtp));

    // is_implied_by: "if other is satisfied, does that guarantee self is too?"
    let earlier_lock = LockTime::from_height(50).expect("valid");
    let later_lock = LockTime::from_height(200).expect("valid");
    assert!(earlier_lock.is_implied_by(later_lock));
    assert!(!later_lock.is_implied_by(earlier_lock));
}

/// Relative lock times are encoded in the transaction's `nSequence` field.
/// They specify how many blocks or 512-second intervals must pass after the
/// referenced UTXO was mined before the input can be spent.
fn relative_lock_times() {
    // Lock by block count (u16 range: 0–65535 blocks).
    let lock_blocks = RelLockTime::from_height(144); // ~1 day of blocks
    assert!(lock_blocks.is_block_height());
    assert_eq!(lock_blocks.to_consensus_u32() & 0xFFFF, 144);

    // Lock by time: 512-second intervals (u16 range).
    // 144 intervals = 144 * 512 = 73,728 seconds ≈ 20.5 hours
    let lock_time = RelLockTime::from_512_second_intervals(144);
    assert!(lock_time.is_block_time());

    // Convenience: construct from seconds (rounds to 512s intervals).
    let one_day = RelLockTime::from_seconds_floor(86_400).expect("within range");
    assert!(one_day.is_block_time());
    // 86,400 / 512 = 168.75, floor = 168 intervals
    if let relative::LockTime::Time(t) = one_day {
        assert_eq!(t.to_512_second_intervals(), 168);
        assert_eq!(t.to_seconds(), 168 * 512); // 86,016 seconds
    }

    // Ceiling variant rounds up.
    let one_day_ceil = RelLockTime::from_seconds_ceil(86_400).expect("within range");
    if let relative::LockTime::Time(t) = one_day_ceil {
        assert_eq!(t.to_512_second_intervals(), 169); // ceil(168.75) = 169
    }
}

/// A relative lock time is satisfied when enough blocks or time have elapsed
/// since the UTXO being spent was mined.
fn relative_satisfaction() {
    let lock = NumberOfBlocks::from_height(6); // wait 6 blocks

    // UTXO was mined at height 1000, chain tip is 1005.
    let utxo_height = BlockHeight::from_u32(1000);
    let chain_tip = BlockHeight::from_u32(1005);

    // 1005 - 1000 + 1 = 6 >= 6, so the lock is satisfied.
    assert!(lock.is_satisfied_by(chain_tip, utxo_height).unwrap());

    // At height 1004: 1004 - 1000 + 1 = 5 < 6, not yet satisfied.
    let too_soon = BlockHeight::from_u32(1004);
    assert!(!lock.is_satisfied_by(too_soon, utxo_height).unwrap());

    // Time-based relative lock: 1 hour = 3600s, needs ceil(3600/512) = 8 intervals.
    let time_lock = NumberOf512Seconds::from_seconds_ceil(3600).unwrap();
    assert_eq!(time_lock.to_512_second_intervals(), 8); // ceil(7.03) = 8
    assert_eq!(time_lock.to_seconds(), 4096); // 8 * 512

    let utxo_mtp = BlockMtp::from_u32(1_700_000_000);
    // Need 4096 seconds to pass.
    let chain_mtp = BlockMtp::from_u32(1_700_004_096);
    assert!(time_lock.is_satisfied_by(chain_mtp, utxo_mtp).unwrap());
}

/// `BlockHeight` and `BlockMtp` are general-purpose thin wrappers (no range
/// restrictions) for use outside the lock time context. They support checked
/// arithmetic via interval types.
fn block_height_and_mtp_types() {
    let height = BlockHeight::from_u32(800_000);
    let interval = BlockHeightInterval::from_u32(100);

    // Height + interval arithmetic.
    let future = height.checked_add(interval).expect("no overflow");
    assert_eq!(future.to_u32(), 800_100);

    // Height - height = interval.
    let diff = future.checked_sub(height).expect("future >= height");
    assert_eq!(diff, interval);

    // Convert between lock time types and block types.
    let lock_height = Height::from_u32(800_000).unwrap();
    let block_height = BlockHeight::from(lock_height);
    assert_eq!(block_height.to_u32(), 800_000);

    // The reverse conversion is fallible (BlockHeight can exceed 499,999,999).
    let big = BlockHeight::from_u32(500_000_000);
    assert!(Height::try_from(big).is_err());
}
