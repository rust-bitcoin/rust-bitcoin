// SPDX-License-Identifier: CC0-1.0

//! Calculating transaction fees.
//!
//! A Bitcoin transaction fee is the product of a fee rate and the transaction's weight.
//! This example demonstrates the relationship between [`Amount`], [`FeeRate`], and [`Weight`],
//! and covers construction, multiplication, rounding, and inverse calculations.

use bitcoin_units::{Amount, FeeRate, Weight};

fn main() {
    constructing_a_fee_rate();
    calculating_fee_from_weight_and_rate();
    rounding_behavior();
    deriving_fee_rate_from_fee_and_weight();
    deriving_weight_from_fee_and_rate();
    fee_rate_constants();
}

/// Fee rates can be expressed in different units. The most common is sat/vB, used by
/// wallets and block explorers. Protocol-level code often uses sat/kwu (per 1,000
/// weight units) instead. Both constructors produce the same internal representation.
fn constructing_a_fee_rate() {
    // 1 sat/vB is the standard minimum relay fee rate.
    let rate_vb = FeeRate::from_sat_per_vb(1);

    // 1 sat/vB == 250 sat/kwu because 1 vbyte == 4 weight units,
    // so 1 sat/vB == 1 sat per 4 wu == 250 sat per 1000 wu.
    let rate_kwu = FeeRate::from_sat_per_kwu(250);
    assert_eq!(rate_vb, rate_kwu);

    // Conversion back to display units. Since the internal representation has
    // higher precision than sat/vB, floor and ceil variants are provided.
    assert_eq!(rate_vb.to_sat_per_vb_floor(), 1);
    assert_eq!(rate_vb.to_sat_per_kwu_floor(), 250);
}

/// The total fee for a transaction is `fee_rate * weight`. Both `FeeRate::to_fee`
/// and the `*` operator are available; `to_fee` returns a plain `Amount` (saturating
/// to `Amount::MAX` on overflow), while `*` returns a `NumOpResult<Amount>`.
fn calculating_fee_from_weight_and_rate() {
    let rate = FeeRate::from_sat_per_vb(2);
    let weight = Weight::from_vb(3).expect("3 vB does not overflow");

    // Using the convenience method (saturates on overflow).
    let fee = rate.to_fee(weight);
    assert_eq!(fee, Amount::from_sat_u32(6));

    // Using the checked method.
    let fee = rate.mul_by_weight(weight).expect("no overflow");
    assert_eq!(fee, Amount::from_sat_u32(6));

    // Using operator syntax — both orderings work.
    assert_eq!((rate * weight).unwrap(), Amount::from_sat_u32(6));
    assert_eq!((weight * rate).unwrap(), Amount::from_sat_u32(6));
}

/// Fee multiplication rounds **up** (ceiling). This ensures a transaction always
/// pays *at least* enough — rounding down could produce a fee below the required
/// minimum, causing rejection.
fn rounding_behavior() {
    // A typical segwit transaction: 381 weight units at 864 sat/kwu.
    //
    // Exact arithmetic: 864 * 381 / 1000 = 329,184 / 1000 = 329.184
    // Rounding up:      ceil(329.184) = 330 satoshis
    let rate = FeeRate::from_sat_per_kwu(864);
    let weight = Weight::from_wu(381);
    let fee = rate.to_fee(weight);
    assert_eq!(fee, Amount::from_sat_u32(330));
}

/// Given a fee and a weight, you can derive the effective fee rate.
///
/// Two variants exist:
/// - `div_by_weight_floor`: rounds down — the minimum rate that *was* paid.
/// - `div_by_weight_ceil`:  rounds up — the minimum rate that *would* pay at least this fee.
fn deriving_fee_rate_from_fee_and_weight() {
    let fee = Amount::from_sat_u32(329);
    let weight = Weight::from_wu(381);

    // Floor: what rate was effectively paid?
    // 329 * 1000 / 381 = 863.51... → floor → 863 sat/kwu
    let rate_floor = fee.div_by_weight_floor(weight).expect("non-zero weight");
    assert_eq!(rate_floor, FeeRate::from_sat_per_kwu(863));

    // Ceil: what is the minimum rate that would produce at least 329 sats for 381 wu?
    // 329 * 1000 / 381 = 863.51... → ceil → 864 sat/kwu
    let rate_ceil = fee.div_by_weight_ceil(weight).expect("non-zero weight");
    assert_eq!(rate_ceil, FeeRate::from_sat_per_kwu(864));
}

/// Given a fee budget and a rate, you can derive the maximum weight you can afford.
///
/// - `div_by_fee_rate_floor`: rounds down — the largest weight that stays within budget.
/// - `div_by_fee_rate_ceil`:  rounds up — the smallest weight whose fee meets the amount.
fn deriving_weight_from_fee_and_rate() {
    let budget = Amount::from_sat_u32(1000);
    let rate = FeeRate::from_sat_per_kwu(3);

    // Floor: what is the heaviest transaction I can afford?
    // 1000 * 1000 / ceil(3) = 1,000,000 / 3 = 333,333.33... → floor → 333,333 wu
    let max_weight = budget.div_by_fee_rate_floor(rate).expect("non-zero rate");
    assert_eq!(max_weight, Weight::from_wu(333_333));

    // Ceil: what is the lightest transaction that would cost at least 1000 sats?
    let min_weight = budget.div_by_fee_rate_ceil(rate).expect("non-zero rate");
    assert_eq!(min_weight, Weight::from_wu(333_334));

    // The `/` operator uses floor division.
    assert_eq!((budget / rate).unwrap(), Weight::from_wu(333_333));
}

/// The library provides two commonly-used fee rate constants.
fn fee_rate_constants() {
    // BROADCAST_MIN: the default minimum relay fee (1 sat/vB).
    assert_eq!(FeeRate::BROADCAST_MIN, FeeRate::from_sat_per_vb(1));

    // DUST: the fee rate used to calculate the dust threshold (3 sat/vB).
    assert_eq!(FeeRate::DUST, FeeRate::from_sat_per_vb(3));
}
