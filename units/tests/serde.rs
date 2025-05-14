// SPDX-License-Identifier: CC0-1.0

//! Test the `serde` implementations for types in `units`.

#![cfg(feature = "alloc")]
#![cfg(feature = "serde")]

use bincode::serialize;
use bitcoin_units::locktime::{absolute, relative};
use bitcoin_units::{amount, fee_rate, Amount, BlockHeight, BlockInterval, FeeRate, SignedAmount, Weight};
use serde::{Deserialize, Serialize};

/// A struct that includes all the types that implement or support `serde` traits.
#[derive(Debug, Serialize, Deserialize)]
struct Serde {
    #[serde(with = "amount::serde::as_sat")]
    unsigned_as_sat: Amount,
    #[serde(with = "amount::serde::as_btc")]
    unsigned_as_btc: Amount,
    #[serde(with = "amount::serde::as_sat::opt")]
    unsigned_opt_as_sat: Option<Amount>,
    #[serde(with = "amount::serde::as_btc::opt")]
    unsigned_opt_as_btc: Option<Amount>,

    #[serde(with = "amount::serde::as_sat")]
    signed_as_sat: SignedAmount,
    #[serde(with = "amount::serde::as_btc")]
    signed_as_btc: SignedAmount,
    #[serde(with = "amount::serde::as_sat::opt")]
    signed_opt_as_sat: Option<SignedAmount>,
    #[serde(with = "amount::serde::as_btc::opt")]
    signed_opt_as_btc: Option<SignedAmount>,

    #[serde(with = "fee_rate::serde::as_sat_per_vb_floor")]
    vb_floor: FeeRate,
    #[serde(with = "fee_rate::serde::as_sat_per_vb_ceil")]
    vb_ceil: FeeRate,
    #[serde(with = "fee_rate::serde::as_sat_per_kwu")]
    kwu: FeeRate,
    #[serde(with = "fee_rate::serde::as_sat_per_vb_floor::opt")]
    opt_vb_floor: Option<FeeRate>,
    #[serde(with = "fee_rate::serde::as_sat_per_vb_ceil::opt")]
    opt_vb_ceil: Option<FeeRate>,
    #[serde(with = "fee_rate::serde::as_sat_per_kwu::opt")]
    opt_kwu: Option<FeeRate>,

    a: BlockHeight,
    b: BlockInterval,
    c: absolute::Height,
    d: absolute::MedianTimePast,
    e: relative::Height,
    f: relative::Time,
    g: Weight,
}

impl Serde {
    /// Constructs an arbitrary instance.
    fn new() -> Self {
        Self {
            unsigned_as_sat: Amount::MAX,
            unsigned_as_btc: Amount::MAX,

            unsigned_opt_as_sat: Some(Amount::MAX),
            unsigned_opt_as_btc: Some(Amount::MAX),

            signed_as_sat: SignedAmount::MAX,
            signed_as_btc: SignedAmount::MAX,

            signed_opt_as_sat: Some(SignedAmount::MAX),
            signed_opt_as_btc: Some(SignedAmount::MAX),

            vb_floor: FeeRate::BROADCAST_MIN,
            vb_ceil: FeeRate::BROADCAST_MIN,
            kwu: FeeRate::BROADCAST_MIN,

            opt_vb_floor: Some(FeeRate::BROADCAST_MIN),
            opt_vb_ceil: Some(FeeRate::BROADCAST_MIN),
            opt_kwu: Some(FeeRate::BROADCAST_MIN),

            a: BlockHeight::MAX,
            b: BlockInterval::MAX,
            c: absolute::Height::MAX,
            d: absolute::MedianTimePast::MAX,
            e: relative::Height::MAX,
            f: relative::Time::MAX,
            g: Weight::MAX,
        }
    }
}

#[test]
fn serde_regression() {
    let t = Serde::new();
    let got = serialize(&t).unwrap();
    let want = include_bytes!("data/serde_bincode");
    assert_eq!(got, want);
}
