// SPDX-License-Identifier: CC0-1.0

#![allow(deprecated)]

use bitcoin_units::locktime::{absolute, relative};
use bitcoin_units::{Amount, FeeRate, Sequence, SignedAmount, Weight};

const WEIGHT_FROM_VB: Weight = Weight::from_vb_unwrap(2);
const WEIGHT_FROM_WITNESS: Weight = Weight::from_witness_data_size(3);
const WEIGHT_FROM_NON_WITNESS: Weight = Weight::from_non_witness_data_size(3);
const RBF: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
const ABS: Option<SignedAmount> = SignedAmount::ONE_SAT.checked_abs();
const HEIGHT_U32: u32 = absolute::Height::MAX.to_consensus_u32();
const MTP_U32: u32 = absolute::MedianTimePast::MAX.to_consensus_u32();
const BLOCKS_VALUE: u16 = relative::NumberOfBlocks::MAX.value();
const BLOCKS_U32: u32 = relative::NumberOfBlocks::MAX.to_consensus_u32();
const SECONDS_VALUE: u16 = relative::NumberOf512Seconds::MAX.value();
const SECONDS_U32: u32 = relative::NumberOf512Seconds::MAX.to_consensus_u32();

#[test]
fn weight_constructors() {
    assert_eq!(WEIGHT_FROM_VB, Weight::from_wu(8));
    assert_eq!(WEIGHT_FROM_WITNESS, Weight::from_wu(3));
    assert_eq!(WEIGHT_FROM_NON_WITNESS, Weight::from_wu(12));
}

#[test]
#[should_panic = "checked_mul overflowed"]
fn weight_from_vb_unwrap_overflow() { let _ = Weight::from_vb_unwrap(u64::MAX); }

#[test]
fn sequence_items() {
    assert_eq!(RBF, Sequence::ENABLE_LOCKTIME_AND_RBF);
    #[cfg(feature = "alloc")]
    assert_eq!(Sequence::from_consensus(0xFFFF_FFFD).to_hex(), "fffffffd");
}

#[test]
#[cfg(feature = "alloc")]
fn compact_target_to_hex() {
    assert_eq!(bitcoin_units::CompactTarget::from_consensus(0x1d00_ffff).to_hex(), "1d00ffff");
}

#[test]
fn signed_amount_checked_abs() {
    assert_eq!(ABS, Some(SignedAmount::ONE_SAT));
    assert_eq!(
        SignedAmount::from_sat(-100).unwrap().checked_abs(),
        SignedAmount::from_sat(100).ok()
    );
}

#[test]
fn fee_rate_fees() {
    let fee_rate = FeeRate::from_sat_per_vb(2);
    let weight = Weight::from_vb(3).unwrap();
    assert_eq!(fee_rate.fee_wu(weight), Some(fee_rate.to_fee(weight)));
    assert_eq!(fee_rate.fee_wu(Weight::MAX), None);
    assert_eq!(fee_rate.fee_vb(3), Some(Amount::from_sat(6).unwrap()));
    assert_eq!(fee_rate.fee_vb(u64::MAX), None);
}

#[test]
fn absolute_locktime_items() {
    assert_eq!(
        absolute::LockTime::from_time(1_653_195_600),
        absolute::LockTime::from_mtp(1_653_195_600)
    );
    assert_eq!(absolute::Height::from_consensus(10), absolute::Height::from_u32(10));
    assert_eq!(HEIGHT_U32, absolute::Height::MAX.to_u32());
    assert_eq!(
        absolute::MedianTimePast::from_consensus(1_653_195_600),
        absolute::MedianTimePast::from_u32(1_653_195_600)
    );
    assert_eq!(MTP_U32, absolute::MedianTimePast::MAX.to_u32());
}

#[test]
fn relative_locktime_items() {
    assert_eq!(BLOCKS_VALUE, relative::NumberOfBlocks::MAX.to_height());
    assert_eq!(
        BLOCKS_U32,
        relative::LockTime::from(relative::NumberOfBlocks::MAX).to_consensus_u32()
    );
    assert_eq!(SECONDS_VALUE, relative::NumberOf512Seconds::MAX.to_512_second_intervals());
    assert_eq!(
        SECONDS_U32,
        relative::LockTime::from(relative::NumberOf512Seconds::MAX).to_consensus_u32()
    );
}
