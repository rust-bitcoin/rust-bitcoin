// SPDX-License-Identifier: CC0-1.0

//! Test the `serde` implementations for types in `units`.

#![cfg(feature = "alloc")]
#![cfg(feature = "serde")]

use bincode::serialize;
use bitcoin_units::absolute::{Height, LockTime as AbsoluteLockTime, MedianTimePast};
use bitcoin_units::relative::{LockTime as RelativeLockTime, NumberOf512Seconds, NumberOfBlocks};
use bitcoin_units::{
    amount, fee_rate, Amount, BlockHeight, BlockHeightInterval, BlockTime, FeeRate, Sequence,
    SignedAmount, Weight,
};
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
    #[serde(with = "fee_rate::serde::as_sat_per_kwu_floor")]
    kwu: FeeRate,
    #[serde(with = "fee_rate::serde::as_sat_per_vb_floor::opt")]
    opt_vb_floor: Option<FeeRate>,
    #[serde(with = "fee_rate::serde::as_sat_per_vb_ceil::opt")]
    opt_vb_ceil: Option<FeeRate>,
    #[serde(with = "fee_rate::serde::as_sat_per_kwu_floor::opt")]
    opt_kwu: Option<FeeRate>,

    block_height: BlockHeight,
    block_height_interval: BlockHeightInterval,
    weight: Weight,

    block_time: BlockTime,
    seq: Sequence,

    abs_locktime: AbsoluteLockTime,
    rel_locktime: RelativeLockTime,
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

            block_height: BlockHeight::MAX,
            block_height_interval: BlockHeightInterval::MAX,
            weight: Weight::MAX,

            block_time: BlockTime::from_u32(1_742_979_600),
            seq: Sequence::MAX,
            abs_locktime: AbsoluteLockTime::Blocks(Height::MAX),
            rel_locktime: RelativeLockTime::Blocks(NumberOfBlocks::MAX),
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

#[track_caller]
fn sat(sat: u64) -> Amount { Amount::from_sat(sat).unwrap() }

#[track_caller]
fn ssat(ssat: i64) -> SignedAmount { SignedAmount::from_sat(ssat).unwrap() }

#[test]
#[cfg(feature = "serde")]
fn serde_amount_as_sat() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "crate::amount::serde::as_sat")]
        pub amt: Amount,
        #[serde(with = "crate::amount::serde::as_sat")]
        pub samt: SignedAmount,
    }

    serde_test::assert_tokens(
        &T { amt: sat(123_456_789), samt: ssat(-123_456_789) },
        &[
            serde_test::Token::Struct { name: "T", len: 2 },
            serde_test::Token::Str("amt"),
            serde_test::Token::I64(123_456_789),
            serde_test::Token::Str("samt"),
            serde_test::Token::I64(-123_456_789),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_amount_as_btc() {
    use serde_json;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "crate::amount::serde::as_btc")]
        pub amt: Amount,
        #[serde(with = "crate::amount::serde::as_btc")]
        pub samt: SignedAmount,
    }

    let orig = T { amt: sat(20_000_000__000_000_01), samt: ssat(-20_000_000__000_000_01) };

    let json = "{\"amt\": 20000000.00000001, \
                \"samt\": -20000000.00000001}";
    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_amount_as_str() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "crate::amount::serde::as_str")]
        pub amt: Amount,
        #[serde(with = "crate::amount::serde::as_str")]
        pub samt: SignedAmount,
    }

    serde_test::assert_tokens(
        &T { amt: sat(123_456_789), samt: ssat(-123_456_789) },
        &[
            serde_test::Token::Struct { name: "T", len: 2 },
            serde_test::Token::String("amt"),
            serde_test::Token::String("1.23456789"),
            serde_test::Token::String("samt"),
            serde_test::Token::String("-1.23456789"),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_amount_as_btc_opt() {
    use serde_json;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
    struct T {
        #[serde(default, with = "crate::amount::serde::as_btc::opt")]
        pub amt: Option<Amount>,
        #[serde(default, with = "crate::amount::serde::as_btc::opt")]
        pub samt: Option<SignedAmount>,
    }

    let with = T { amt: Some(sat(2_500_000_00)), samt: Some(ssat(-2_500_000_00)) };
    let without = T { amt: None, samt: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T = serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value =
        serde_json::from_str("{\"amt\": 2.5, \"samt\": -2.5}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());

    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_amount_as_sat_opt() {
    use serde_json;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
    struct T {
        #[serde(default, with = "crate::amount::serde::as_sat::opt")]
        pub amt: Option<Amount>,
        #[serde(default, with = "crate::amount::serde::as_sat::opt")]
        pub samt: Option<SignedAmount>,
    }

    let with = T { amt: Some(sat(2_500_000_00)), samt: Some(ssat(-2_500_000_00)) };
    let without = T { amt: None, samt: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T = serde_json::from_str("{\"amt\": 250000000, \"samt\": -250000000}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value =
        serde_json::from_str("{\"amt\": 250000000, \"samt\": -250000000}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());

    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_amount_as_str_opt() {
    use serde_json;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
    struct T {
        #[serde(default, with = "crate::amount::serde::as_str::opt")]
        pub amt: Option<Amount>,
        #[serde(default, with = "crate::amount::serde::as_str::opt")]
        pub samt: Option<SignedAmount>,
    }

    let with = T { amt: Some(sat(123_456_789)), samt: Some(ssat(-123_456_789)) };
    let without = T { amt: None, samt: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T =
        serde_json::from_str("{\"amt\": \"1.23456789\", \"samt\": \"-1.23456789\"}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value =
        serde_json::from_str("{\"amt\": \"1.23456789\", \"samt\": \"-1.23456789\"}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());

    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[track_caller]
fn fee_rate_vb(vb: u32) -> FeeRate { FeeRate::from_sat_per_vb(vb) }

#[track_caller]
fn fee_rate_kwu(vb: u32) -> FeeRate { FeeRate::from_sat_per_kwu(vb) }

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_vb_floor() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "fee_rate::serde::as_sat_per_vb_floor")]
        pub fee_rate: FeeRate,
    }

    serde_test::assert_tokens(
        &T { fee_rate: fee_rate_vb(123_456_789) },
        &[
            serde_test::Token::Struct { name: "T", len: 1 },
            serde_test::Token::Str("fee_rate"),
            serde_test::Token::U64(123_456_789),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_kwu_floor() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "crate::fee_rate::serde::as_sat_per_kwu_floor")]
        pub fee_rate: FeeRate,
    }

    serde_test::assert_tokens(
        &T { fee_rate: fee_rate_kwu(123_456_789) },
        &[
            serde_test::Token::Struct { name: "T", len: 1 },
            serde_test::Token::Str("fee_rate"),
            serde_test::Token::U64(123_456_789),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_vb_ceil() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(with = "fee_rate::serde::as_sat_per_vb_ceil")]
        pub fee_rate: FeeRate,
    }

    serde_test::assert_tokens(
        &T { fee_rate: fee_rate_vb(123_456_789) },
        &[
            serde_test::Token::Struct { name: "T", len: 1 },
            serde_test::Token::Str("fee_rate"),
            serde_test::Token::U64(123_456_789),
            serde_test::Token::StructEnd,
        ],
    );
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_floor_vs_ceil() {
    use serde_json;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Floor {
        #[serde(with = "fee_rate::serde::as_sat_per_vb_floor")]
        fee_rate: FeeRate,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Ceil {
        #[serde(with = "fee_rate::serde::as_sat_per_vb_ceil")]
        fee_rate: FeeRate,
    }

    let fee_rate = FeeRate::from_sat_per_kwu(251);

    let floor = Floor { fee_rate };
    let ceil = Ceil { fee_rate };

    let floor_json = serde_json::to_string(&floor).unwrap();
    let ceil_json = serde_json::to_string(&ceil).unwrap();

    assert!(floor_json.contains("\"fee_rate\":1"));
    assert!(ceil_json.contains("\"fee_rate\":2"));
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_kwu_floor_opt() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(default, with = "crate::fee_rate::serde::as_sat_per_kwu_floor::opt")]
        pub fee_rate: Option<FeeRate>,
    }

    let with = T { fee_rate: Some(fee_rate_kwu(123_456_789)) };
    let without = T { fee_rate: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());
    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_vb_floor_opt() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(default, with = "crate::fee_rate::serde::as_sat_per_vb_floor::opt")]
        pub fee_rate: Option<FeeRate>,
    }

    let with = T { fee_rate: Some(fee_rate_vb(123_456_789)) };
    let without = T { fee_rate: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());
    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_fee_rate_as_sat_per_vb_ceil_opt() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        #[serde(default, with = "crate::fee_rate::serde::as_sat_per_vb_ceil::opt")]
        pub fee_rate: Option<FeeRate>,
    }

    let with = T { fee_rate: Some(fee_rate_vb(123_456_789)) };
    let without = T { fee_rate: None };

    // Test Roundtripping
    for s in [&with, &without] {
        let v = serde_json::to_string(s).unwrap();
        let w: T = serde_json::from_str(&v).unwrap();
        assert_eq!(w, *s);
    }

    let t: T = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(t, with);

    let t: T = serde_json::from_str("{}").unwrap();
    assert_eq!(t, without);

    let value_with: serde_json::Value = serde_json::from_str("{\"fee_rate\": 123456789}").unwrap();
    assert_eq!(with, serde_json::from_value(value_with).unwrap());
    let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
    assert_eq!(without, serde_json::from_value(value_without).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_block_height() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub block_height: BlockHeight,
    }

    let orig = T { block_height: BlockHeight::from_u32(123_456_789) };

    let json = "{\"block_height\": 123456789}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_block_interval() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub block_interval: BlockHeightInterval,
    }

    let orig = T { block_interval: BlockHeightInterval::from_u32(144) };

    let json = "{\"block_interval\": 144}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_weight() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub weight: Weight,
    }

    let orig = T { weight: Weight::from_wu(25) };

    let json = "{\"weight\": 25}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_block_time() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub block_time: BlockTime,
    }

    let orig = T { block_time: BlockTime::from_u32(123_456_789) };

    let json = "{\"block_time\": 123456789}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_sequence_from_hex() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub sequence: Sequence,
    }

    let orig = T { sequence: Sequence::from_hex("0x0040ffff").unwrap() };

    let json = "{\"sequence\": 4259839}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_locktime_from_blocks() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub a_lt: AbsoluteLockTime,
        pub r_lt: RelativeLockTime,
    }

    let orig = T {
        a_lt: AbsoluteLockTime::Blocks(Height::from_u32(1_000).unwrap()),
        r_lt: RelativeLockTime::Blocks(NumberOfBlocks::from_height(1_000)),
    };

    let json = "{\"a_lt\": 1000, \"r_lt\": 1000}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}

#[test]
#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
fn serde_as_locktime_from_time() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct T {
        pub a_lt: AbsoluteLockTime,
        pub r_lt: RelativeLockTime,
    }

    let orig = T {
        a_lt: AbsoluteLockTime::Seconds(MedianTimePast::from_u32(1_653_195_600).unwrap()),
        r_lt: RelativeLockTime::Time(NumberOf512Seconds::from_512_second_intervals(70)),
    };

    let json = "{\"a_lt\": 1653195600, \"r_lt\": 4194374}";

    let t: T = serde_json::from_str(json).unwrap();
    assert_eq!(t, orig);

    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(t, serde_json::from_value(value).unwrap());
}
