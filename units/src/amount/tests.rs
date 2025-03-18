// SPDX-License-Identifier: CC0-1.0

//! Unit tests for the `amount` module.

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use std::panic;

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};

use super::*;
#[cfg(feature = "alloc")]
use crate::{FeeRate, Weight};

#[track_caller]
fn sat(sat: u64) -> Amount { Amount::from_sat(sat).unwrap() }

#[track_caller]
fn ssat(ssat: i64) -> SignedAmount { SignedAmount::from_sat(ssat).unwrap() }

#[test]
fn sanity_check() {
    assert_eq!(ssat(-100).abs(), ssat(100));
    assert_eq!(ssat(-100).signum(), -1);
    assert_eq!(ssat(0).signum(), 0);
    assert_eq!(ssat(100).signum(), 1);
    assert_eq!(SignedAmount::from(sat(100)), ssat(100));
    assert!(!ssat(-100).is_positive());
    assert!(ssat(100).is_positive());

    #[cfg(feature = "alloc")]
    {
        assert_eq!(Amount::from_float_in(0_f64, Denomination::Bitcoin).unwrap(), sat(0));
        assert_eq!(Amount::from_float_in(2_f64, Denomination::Bitcoin).unwrap(), sat(200_000_000));
        assert!(Amount::from_float_in(-100_f64, Denomination::Bitcoin).is_err());
    }

    let result = NumOpResult::Valid(sat(123));
    assert_eq!(Some(sat(123)), result.ok());
    assert!(result.is_valid());
    assert!(!result.is_error());
}

#[test]
fn check_if_num_is_too_precise() {
    assert_eq!(is_too_precise("1234", 3).unwrap(), 3);
    assert_eq!(is_too_precise("1234.1234", 3).unwrap(), 3);
}

#[test]
#[cfg(feature = "alloc")]
fn from_str_zero() {
    let denoms = ["BTC", "cBTC", "mBTC", "uBTC", "bits", "sats"];
    for denom in denoms {
        for v in &["0", "000"] {
            let s = format!("{} {}", v, denom);
            match s.parse::<Amount>() {
                Err(e) => panic!("failed to crate amount from {}: {:?}", s, e),
                Ok(amount) => assert_eq!(amount, Amount::ZERO),
            }
        }

        let s = format!("-0 {}", denom);
        match s.parse::<Amount>() {
            Err(e) => assert_eq!(
                e,
                ParseError(ParseErrorInner::Amount(ParseAmountError(
                    ParseAmountErrorInner::OutOfRange(OutOfRangeError::negative())
                )))
            ),
            Ok(_) => panic!("unsigned amount from {}", s),
        }
        match s.parse::<SignedAmount>() {
            Err(e) => panic!("failed to crate amount from {}: {:?}", s, e),
            Ok(amount) => assert_eq!(amount, SignedAmount::ZERO),
        }
    }
}

#[test]
fn from_str_zero_without_denomination() {
    let _a = Amount::from_str("0").unwrap();
    let _a = Amount::from_str("0.0").unwrap();
    let _a = Amount::from_str("00.0").unwrap();

    assert!(Amount::from_str("-0").is_err());
    assert!(Amount::from_str("-0.0").is_err());
    assert!(Amount::from_str("-00.0").is_err());

    let _a = SignedAmount::from_str("-0").unwrap();
    let _a = SignedAmount::from_str("-0.0").unwrap();
    let _a = SignedAmount::from_str("-00.0").unwrap();

    let _a = SignedAmount::from_str("0").unwrap();
    let _a = SignedAmount::from_str("0.0").unwrap();
    let _a = SignedAmount::from_str("00.0").unwrap();
}

#[test]
fn from_int_btc() {
    let amt = Amount::from_int_btc_const(2).unwrap();
    assert_eq!(sat(200_000_000), amt);
}

#[test]
fn amount_try_from_signed_amount() {
    let sa_positive = ssat(123);
    let ua_positive = Amount::try_from(sa_positive).unwrap();
    assert_eq!(ua_positive, sat(123));

    let sa_negative = ssat(-123);
    let result = Amount::try_from(sa_negative);
    assert_eq!(result, Err(OutOfRangeError { is_signed: false, is_greater_than_max: false }));
}

#[test]
fn mul_div() {
    let op_result_sat = |a| NumOpResult::Valid(sat(a));
    let op_result_ssat = |a| NumOpResult::Valid(ssat(a));

    assert_eq!(sat(14) * 3, op_result_sat(42));
    assert_eq!(sat(14) / 2, op_result_sat(7));
    assert_eq!(sat(14) % 3, op_result_sat(2));
    assert_eq!(ssat(-14) * 3, op_result_ssat(-42));
    assert_eq!(ssat(-14) / 2, op_result_ssat(-7));
    assert_eq!(ssat(-14) % 3, op_result_ssat(-2));
}

#[test]
fn neg() {
    let amount = -ssat(2);
    assert_eq!(amount.to_sat(), -2);
}

#[test]
fn add() {
    assert!(sat(0) + sat(0) == sat(0).into());
    assert!(sat(127) + sat(179) == sat(306).into());

    assert!(ssat(0) + ssat(0) == ssat(0).into());
    assert!(ssat(127) + ssat(179) == ssat(306).into());
    assert!(ssat(-127) + ssat(179) == ssat(52).into());
    assert!(ssat(127) + ssat(-179) == ssat(-52).into());
    assert!(ssat(-127) + ssat(-179) == ssat(-306).into());
}

#[test]
fn sub() {
    assert!(sat(0) - sat(0) == sat(0).into());
    assert!(sat(179) - sat(127) == sat(52).into());
    assert!((sat(127) - sat(179)).is_error());

    assert!(ssat(0) - ssat(0) == ssat(0).into());
    assert!(ssat(127) - ssat(179) == ssat(-52).into());
    assert!(ssat(-127) - ssat(179) == ssat(-306).into());
    assert!(ssat(127) - ssat(-179) == ssat(306).into());
    assert!(ssat(-127) - ssat(-179) == ssat(52).into());
}

#[test]
fn checked_arithmetic() {
    assert_eq!(SignedAmount::MAX.checked_add(ssat(1)), None);
    assert_eq!(SignedAmount::MIN.checked_sub(ssat(1)), None);
    assert_eq!(Amount::MAX.checked_add(sat(1)), None);
    assert_eq!(Amount::MIN.checked_sub(sat(1)), None);

    assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
    assert_eq!(ssat(-6).checked_div(2), Some(ssat(-3)));
}

#[test]
fn positive_sub() {
    assert_eq!(ssat(10).positive_sub(ssat(7)).unwrap(), ssat(3));
    assert!(ssat(-10).positive_sub(ssat(7)).is_none());
    assert!(ssat(10).positive_sub(ssat(-7)).is_none());
    assert!(ssat(10).positive_sub(ssat(11)).is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_weight_ceil() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = sat(1).checked_div_by_weight_ceil(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = sat(329).checked_div_by_weight_ceil(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round up to 864
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(864));

    let fee_rate = Amount::ONE_SAT.checked_div_by_weight_ceil(Weight::ZERO);
    assert!(fee_rate.is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_weight_floor() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = sat(1).checked_div_by_weight_floor(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = sat(329).checked_div_by_weight_floor(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round down to 863
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863));

    let fee_rate = Amount::ONE_SAT.checked_div_by_weight_floor(Weight::ZERO);
    assert!(fee_rate.is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_fee_rate() {
    let amount = sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(2);

    // Test floor division
    let weight = amount.checked_div_by_fee_rate_floor(fee_rate).unwrap();
    // 1000 sats / (2 sats/kwu) = 500,000 wu
    assert_eq!(weight, Weight::from_wu(500_000));

    // Test ceiling division
    let weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(weight, Weight::from_wu(500_000)); // Same result for exact division

    // Test truncation behavior
    let amount = sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(3);
    let floor_weight = amount.checked_div_by_fee_rate_floor(fee_rate).unwrap();
    let ceil_weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(floor_weight, Weight::from_wu(333_333));
    assert_eq!(ceil_weight, Weight::from_wu(333_334));

    // Test division by zero
    let zero_fee_rate = FeeRate::from_sat_per_kwu(0);
    assert!(amount.checked_div_by_fee_rate_floor(zero_fee_rate).is_none());
    assert!(amount.checked_div_by_fee_rate_ceil(zero_fee_rate).is_none());

    // Test with maximum amount
    let max_amount = Amount::MAX;
    let small_fee_rate = FeeRate::from_sat_per_kwu(1);
    let weight = max_amount.checked_div_by_fee_rate_floor(small_fee_rate).unwrap();
    // 21_000_000_0000_0000 sats / (1 sat/kwu) = 2_100_000_000_000_000_000 wu
    assert_eq!(weight, Weight::from_wu(2_100_000_000_000_000_000));
}

#[cfg(feature = "alloc")]
#[test]
fn floating_point() {
    use super::Denomination as D;
    let f = Amount::from_float_in;
    let sf = SignedAmount::from_float_in;

    assert_eq!(f(11.22, D::Bitcoin), Ok(sat(1_122_000_000)));
    assert_eq!(sf(-11.22, D::MilliBitcoin), Ok(ssat(-1_122_000)));
    assert_eq!(f(11.22, D::Bit), Ok(sat(1122)));
    assert_eq!(f(0.000_123_4, D::Bitcoin), Ok(sat(12_340)));
    assert_eq!(sf(-0.000_123_45, D::Bitcoin), Ok(ssat(-12_345)));

    assert_eq!(f(11.22, D::Satoshi), Err(TooPreciseError { position: 3 }.into()));
    assert_eq!(f(42.123_456_781, D::Bitcoin), Err(TooPreciseError { position: 11 }.into()));
    assert_eq!(sf(-184_467_440_738.0, D::Bitcoin), Err(OutOfRangeError::too_small().into()));
    assert_eq!(
        f(18_446_744_073_709_551_617.0, D::Satoshi),
        Err(OutOfRangeError::too_big(false).into())
    );

    assert_eq!(
        f(Amount::MAX.to_float_in(D::Satoshi) + 1.0, D::Satoshi),
        Err(OutOfRangeError::too_big(false).into())
    );

    assert_eq!(
        sf(SignedAmount::MAX.to_float_in(D::Satoshi) + 1.0, D::Satoshi),
        Err(OutOfRangeError::too_big(true).into())
    );

    let btc = move |f| SignedAmount::from_btc(f).unwrap();
    assert_eq!(btc(2.5).to_float_in(D::Bitcoin), 2.5);
    assert_eq!(btc(-2.5).to_float_in(D::CentiBitcoin), -250.0);
    assert_eq!(btc(-2.5).to_float_in(D::MilliBitcoin), -2500.0);
    assert_eq!(btc(2.5).to_float_in(D::Satoshi), 250_000_000.0);

    let btc = move |f| Amount::from_btc(f).unwrap();
    assert_eq!(&btc(0.0012).to_float_in(D::Bitcoin).to_string(), "0.0012");
}

#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn parsing() {
    use super::ParseAmountError as E;

    let den_btc = Denomination::Bitcoin;
    let den_sat = Denomination::Satoshi;
    let p = Amount::from_str_in;
    let sp = SignedAmount::from_str_in;

    assert_eq!(
        p("x", den_btc),
        Err(E::from(InvalidCharacterError { invalid_char: 'x', position: 0 }))
    );
    assert_eq!(
        p("-", den_btc),
        Err(E::from(MissingDigitsError { kind: MissingDigitsKind::OnlyMinusSign }))
    );
    assert_eq!(
        sp("-", den_btc),
        Err(E::from(MissingDigitsError { kind: MissingDigitsKind::OnlyMinusSign }))
    );
    assert_eq!(
        p("-1.0x", den_btc),
        Err(E::from(InvalidCharacterError { invalid_char: 'x', position: 4 }))
    );
    assert_eq!(
        p("0.0 ", den_btc),
        Err(E::from(InvalidCharacterError { invalid_char: ' ', position: 3 }))
    );
    assert_eq!(
        p("0.000.000", den_btc),
        Err(E::from(InvalidCharacterError { invalid_char: '.', position: 5 }))
    );
    #[cfg(feature = "alloc")]
    let more_than_max = format!("{}", Amount::MAX.to_sat() + 1);
    #[cfg(feature = "alloc")]
    assert_eq!(p(&more_than_max, den_btc), Err(OutOfRangeError::too_big(false).into()));
    assert_eq!(p("0.000000042", den_btc), Err(TooPreciseError { position: 10 }.into()));
    assert_eq!(p("1.0000000", den_sat), Ok(sat(1)));
    assert_eq!(p("1.1", den_sat), Err(TooPreciseError { position: 2 }.into()));
    assert_eq!(p("1000.1", den_sat), Err(TooPreciseError { position: 5 }.into()));
    assert_eq!(p("1001.0000000", den_sat), Ok(sat(1001)));
    assert_eq!(p("1000.0000001", den_sat), Err(TooPreciseError { position: 11 }.into()));

    assert_eq!(p("1", den_btc), Ok(sat(1_000_000_00)));
    assert_eq!(sp("-.5", den_btc), Ok(ssat(-500_000_00)));
    #[cfg(feature = "alloc")]
    assert_eq!(sp(&SignedAmount::MIN.to_sat().to_string(), den_sat), Ok(SignedAmount::MIN));
    assert_eq!(p("1.1", den_btc), Ok(sat(1_100_000_00)));
    assert_eq!(p("100", den_sat), Ok(sat(100)));
    assert_eq!(p("55", den_sat), Ok(sat(55)));
    assert_eq!(p("2100000000000000", den_sat), Ok(sat(21_000_000__000_000_00)));
    assert_eq!(p("2100000000000000.", den_sat), Ok(sat(21_000_000__000_000_00)));
    assert_eq!(p("21000000", den_btc), Ok(sat(21_000_000__000_000_00)));

    // exactly 50 chars.
    assert_eq!(
        p("100000000000000.0000000000000000000000000000000000", Denomination::Bitcoin),
        Err(OutOfRangeError::too_big(false).into())
    );
    // more than 50 chars.
    assert_eq!(
        p("100000000000000.00000000000000000000000000000000000", Denomination::Bitcoin),
        Err(E(ParseAmountErrorInner::InputTooLarge(InputTooLargeError { len: 51 })))
    );
}

#[test]
#[cfg(feature = "alloc")]
fn to_string() {
    use super::Denomination as D;

    assert_eq!(Amount::ONE_BTC.to_string_in(D::Bitcoin), "1");
    assert_eq!(format!("{:.8}", Amount::ONE_BTC.display_in(D::Bitcoin)), "1.00000000");
    assert_eq!(Amount::ONE_BTC.to_string_in(D::Satoshi), "100000000");
    assert_eq!(Amount::ONE_SAT.to_string_in(D::Bitcoin), "0.00000001");
    assert_eq!(ssat(-42).to_string_in(D::Bitcoin), "-0.00000042");

    assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1 BTC");
    assert_eq!(SignedAmount::ONE_BTC.to_string_with_denomination(D::Satoshi), "100000000 satoshi");
    assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::Bitcoin), "0.00000001 BTC");
    assert_eq!(ssat(-42).to_string_with_denomination(D::Bitcoin), "-0.00000042 BTC");
}

// May help identify a problem sooner
#[cfg(feature = "alloc")]
#[test]
fn test_repeat_char() {
    let mut buf = String::new();
    repeat_char(&mut buf, '0', 0).unwrap();
    assert_eq!(buf.len(), 0);
    repeat_char(&mut buf, '0', 42).unwrap();
    assert_eq!(buf.len(), 42);
    assert!(buf.chars().all(|c| c == '0'));
}

// Creates individual test functions to make it easier to find which check failed.
macro_rules! check_format_non_negative {
    ($denom:ident; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert_eq!(format!($format_string, sat($val).display_in(Denomination::$denom)), $expected);
                assert_eq!(format!($format_string, ssat($val as i64).display_in(Denomination::$denom)), $expected);
            }
        )*
    }
}

macro_rules! check_format_non_negative_show_denom {
    ($denom:ident, $denom_suffix:literal; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert_eq!(format!($format_string, sat($val).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
                assert_eq!(format!($format_string, ssat($val as i64).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
            }
        )*
    }
}

check_format_non_negative! {
    Satoshi;
    sat_check_fmt_non_negative_0, 0, "{}", "0";
    sat_check_fmt_non_negative_1, 0, "{:2}", " 0";
    sat_check_fmt_non_negative_2, 0, "{:02}", "00";
    sat_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
    sat_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
    sat_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
    sat_check_fmt_non_negative_6, 1, "{}", "1";
    sat_check_fmt_non_negative_7, 1, "{:2}", " 1";
    sat_check_fmt_non_negative_8, 1, "{:02}", "01";
    sat_check_fmt_non_negative_9, 1, "{:.1}", "1.0";
    sat_check_fmt_non_negative_10, 1, "{:4.1}", " 1.0";
    sat_check_fmt_non_negative_11, 1, "{:04.1}", "01.0";
    sat_check_fmt_non_negative_12, 10, "{}", "10";
    sat_check_fmt_non_negative_13, 10, "{:2}", "10";
    sat_check_fmt_non_negative_14, 10, "{:02}", "10";
    sat_check_fmt_non_negative_15, 10, "{:3}", " 10";
    sat_check_fmt_non_negative_16, 10, "{:03}", "010";
    sat_check_fmt_non_negative_17, 10, "{:.1}", "10.0";
    sat_check_fmt_non_negative_18, 10, "{:5.1}", " 10.0";
    sat_check_fmt_non_negative_19, 10, "{:05.1}", "010.0";
    sat_check_fmt_non_negative_20, 1, "{:<2}", "1 ";
    sat_check_fmt_non_negative_21, 1, "{:<02}", "01";
    sat_check_fmt_non_negative_22, 1, "{:<3.1}", "1.0";
    sat_check_fmt_non_negative_23, 1, "{:<4.1}", "1.0 ";
}

check_format_non_negative_show_denom! {
    Satoshi, " satoshi";
    sat_check_fmt_non_negative_show_denom_0, 0, "{}", "0";
    sat_check_fmt_non_negative_show_denom_1, 0, "{:2}", "0";
    sat_check_fmt_non_negative_show_denom_2, 0, "{:02}", "0";
    sat_check_fmt_non_negative_show_denom_3, 0, "{:9}", "0";
    sat_check_fmt_non_negative_show_denom_4, 0, "{:09}", "0";
    sat_check_fmt_non_negative_show_denom_5, 0, "{:10}", " 0";
    sat_check_fmt_non_negative_show_denom_6, 0, "{:010}", "00";
    sat_check_fmt_non_negative_show_denom_7, 0, "{:.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_8, 0, "{:11.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_9, 0, "{:011.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_10, 0, "{:12.1}", " 0.0";
    sat_check_fmt_non_negative_show_denom_11, 0, "{:012.1}", "00.0";
    sat_check_fmt_non_negative_show_denom_12, 1, "{}", "1";
    sat_check_fmt_non_negative_show_denom_13, 1, "{:10}", " 1";
    sat_check_fmt_non_negative_show_denom_14, 1, "{:010}", "01";
    sat_check_fmt_non_negative_show_denom_15, 1, "{:.1}", "1.0";
    sat_check_fmt_non_negative_show_denom_16, 1, "{:12.1}", " 1.0";
    sat_check_fmt_non_negative_show_denom_17, 1, "{:012.1}", "01.0";
    sat_check_fmt_non_negative_show_denom_18, 10, "{}", "10";
    sat_check_fmt_non_negative_show_denom_19, 10, "{:10}", "10";
    sat_check_fmt_non_negative_show_denom_20, 10, "{:010}", "10";
    sat_check_fmt_non_negative_show_denom_21, 10, "{:11}", " 10";
    sat_check_fmt_non_negative_show_denom_22, 10, "{:011}", "010";
}

check_format_non_negative! {
    Bitcoin;
    btc_check_fmt_non_negative_0, 0, "{}", "0";
    btc_check_fmt_non_negative_1, 0, "{:2}", " 0";
    btc_check_fmt_non_negative_2, 0, "{:02}", "00";
    btc_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
    btc_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
    btc_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
    btc_check_fmt_non_negative_6, 1, "{}", "0.00000001";
    btc_check_fmt_non_negative_7, 1, "{:2}", "0.00000001";
    btc_check_fmt_non_negative_8, 1, "{:02}", "0.00000001";
    btc_check_fmt_non_negative_9, 1, "{:.1}", "0.0";
    btc_check_fmt_non_negative_10, 1, "{:11}", " 0.00000001";
    btc_check_fmt_non_negative_11, 1, "{:11.1}", "        0.0";
    btc_check_fmt_non_negative_12, 1, "{:011.1}", "000000000.0";
    btc_check_fmt_non_negative_13, 1, "{:.9}", "0.000000010";
    btc_check_fmt_non_negative_14, 1, "{:11.9}", "0.000000010";
    btc_check_fmt_non_negative_15, 1, "{:011.9}", "0.000000010";
    btc_check_fmt_non_negative_16, 1, "{:12.9}", " 0.000000010";
    btc_check_fmt_non_negative_17, 1, "{:012.9}", "00.000000010";
    btc_check_fmt_non_negative_18, 100_000_000, "{}", "1";
    btc_check_fmt_non_negative_19, 100_000_000, "{:2}", " 1";
    btc_check_fmt_non_negative_20, 100_000_000, "{:02}", "01";
    btc_check_fmt_non_negative_21, 100_000_000, "{:.1}", "1.0";
    btc_check_fmt_non_negative_22, 100_000_000, "{:4.1}", " 1.0";
    btc_check_fmt_non_negative_23, 100_000_000, "{:04.1}", "01.0";
    btc_check_fmt_non_negative_24, 110_000_000, "{}", "1.1";
    btc_check_fmt_non_negative_25, 100_000_001, "{}", "1.00000001";
    btc_check_fmt_non_negative_26, 100_000_001, "{:1}", "1.00000001";
    btc_check_fmt_non_negative_27, 100_000_001, "{:.1}", "1.0";
    btc_check_fmt_non_negative_28, 100_000_001, "{:10}", "1.00000001";
    btc_check_fmt_non_negative_29, 100_000_001, "{:11}", " 1.00000001";
    btc_check_fmt_non_negative_30, 100_000_001, "{:011}", "01.00000001";
    btc_check_fmt_non_negative_31, 100_000_001, "{:.8}", "1.00000001";
    btc_check_fmt_non_negative_32, 100_000_001, "{:.9}", "1.000000010";
    btc_check_fmt_non_negative_33, 100_000_001, "{:11.9}", "1.000000010";
    btc_check_fmt_non_negative_34, 100_000_001, "{:12.9}", " 1.000000010";
    btc_check_fmt_non_negative_35, 100_000_001, "{:012.9}", "01.000000010";
    btc_check_fmt_non_negative_36, 100_000_001, "{:+011.8}", "+1.00000001";
    btc_check_fmt_non_negative_37, 100_000_001, "{:+12.8}", " +1.00000001";
    btc_check_fmt_non_negative_38, 100_000_001, "{:+012.8}", "+01.00000001";
    btc_check_fmt_non_negative_39, 100_000_001, "{:+12.9}", "+1.000000010";
    btc_check_fmt_non_negative_40, 100_000_001, "{:+012.9}", "+1.000000010";
    btc_check_fmt_non_negative_41, 100_000_001, "{:+13.9}", " +1.000000010";
    btc_check_fmt_non_negative_42, 100_000_001, "{:+013.9}", "+01.000000010";
    btc_check_fmt_non_negative_43, 100_000_001, "{:<10}", "1.00000001";
    btc_check_fmt_non_negative_44, 100_000_001, "{:<11}", "1.00000001 ";
    btc_check_fmt_non_negative_45, 100_000_001, "{:<011}", "01.00000001";
    btc_check_fmt_non_negative_46, 100_000_001, "{:<11.9}", "1.000000010";
    btc_check_fmt_non_negative_47, 100_000_001, "{:<12.9}", "1.000000010 ";
    btc_check_fmt_non_negative_48, 100_000_001, "{:<12}", "1.00000001  ";
    btc_check_fmt_non_negative_49, 100_000_001, "{:^11}", "1.00000001 ";
    btc_check_fmt_non_negative_50, 100_000_001, "{:^11.9}", "1.000000010";
    btc_check_fmt_non_negative_51, 100_000_001, "{:^12.9}", "1.000000010 ";
    btc_check_fmt_non_negative_52, 100_000_001, "{:^12}", " 1.00000001 ";
    btc_check_fmt_non_negative_53, 100_000_001, "{:^12.9}", "1.000000010 ";
    btc_check_fmt_non_negative_54, 100_000_001, "{:^13.9}", " 1.000000010 ";
}

check_format_non_negative_show_denom! {
    Bitcoin, " BTC";
    btc_check_fmt_non_negative_show_denom_0, 1, "{:14.1}", "       0.0";
    btc_check_fmt_non_negative_show_denom_1, 1, "{:14.8}", "0.00000001";
    btc_check_fmt_non_negative_show_denom_2, 1, "{:15}", " 0.00000001";
    btc_check_fmt_non_negative_show_denom_3, 1, "{:015}", "00.00000001";
    btc_check_fmt_non_negative_show_denom_4, 1, "{:.9}", "0.000000010";
    btc_check_fmt_non_negative_show_denom_5, 1, "{:15.9}", "0.000000010";
    btc_check_fmt_non_negative_show_denom_6, 1, "{:16.9}", " 0.000000010";
    btc_check_fmt_non_negative_show_denom_7, 1, "{:016.9}", "00.000000010";
}

check_format_non_negative_show_denom! {
    Bitcoin, " BTC ";
    btc_check_fmt_non_negative_show_denom_align_0, 1, "{:<15}", "0.00000001";
    btc_check_fmt_non_negative_show_denom_align_1, 1, "{:^15}", "0.00000001";
    btc_check_fmt_non_negative_show_denom_align_2, 1, "{:^16}", " 0.00000001";
}

#[test]
fn unsigned_signed_conversion() {
    let max_sats: u64 = Amount::MAX.to_sat();

    assert_eq!(sat(max_sats).to_signed(), ssat(max_sats as i64));
    assert_eq!(ssat(max_sats as i64).to_unsigned(), Ok(sat(max_sats)));
    assert_eq!(ssat(max_sats as i64).to_unsigned().unwrap().to_signed(), ssat(max_sats as i64));
}

#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
#[allow(clippy::items_after_statements)] // Define functions where we use them.
fn from_str() {
    use ParseDenominationError::*;

    use super::ParseAmountError as E;

    assert_eq!(
        "x BTC".parse::<Amount>(),
        Err(InvalidCharacterError { invalid_char: 'x', position: 0 }.into())
    );
    assert_eq!(
        "xBTC".parse::<Amount>(),
        Err(Unknown(UnknownDenominationError("xBTC".into())).into()),
    );
    assert_eq!(
        "5 BTC BTC".parse::<Amount>(),
        Err(Unknown(UnknownDenominationError("BTC BTC".into())).into()),
    );
    assert_eq!(
        "5BTC BTC".parse::<Amount>(),
        Err(E::from(InvalidCharacterError { invalid_char: 'B', position: 1 }).into())
    );
    assert_eq!(
        "5 5 BTC".parse::<Amount>(),
        Err(Unknown(UnknownDenominationError("5 BTC".into())).into()),
    );

    #[track_caller]
    fn ok_case(s: &str, expected: Amount) {
        assert_eq!(s.parse::<Amount>().unwrap(), expected);
        assert_eq!(s.replace(' ', "").parse::<Amount>().unwrap(), expected);
    }

    #[track_caller]
    fn case(s: &str, expected: Result<Amount, impl Into<ParseError>>) {
        let expected = expected.map_err(Into::into);
        assert_eq!(s.parse::<Amount>(), expected);
        assert_eq!(s.replace(' ', "").parse::<Amount>(), expected);
    }

    #[track_caller]
    fn ok_scase(s: &str, expected: SignedAmount) {
        assert_eq!(s.parse::<SignedAmount>().unwrap(), expected);
        assert_eq!(s.replace(' ', "").parse::<SignedAmount>().unwrap(), expected);
    }

    #[track_caller]
    fn scase(s: &str, expected: Result<SignedAmount, impl Into<ParseError>>) {
        let expected = expected.map_err(Into::into);
        assert_eq!(s.parse::<SignedAmount>(), expected);
        assert_eq!(s.replace(' ', "").parse::<SignedAmount>(), expected);
    }

    case("5 BCH", Err(Unknown(UnknownDenominationError("BCH".into()))));

    case("-1 BTC", Err(OutOfRangeError::negative()));
    case("-0.0 BTC", Err(OutOfRangeError::negative()));
    case("0.123456789 BTC", Err(TooPreciseError { position: 10 }));
    scase("-0.1 satoshi", Err(TooPreciseError { position: 3 }));
    case("0.123456 mBTC", Err(TooPreciseError { position: 7 }));
    scase("-1.001 bits", Err(TooPreciseError { position: 5 }));
    scase("-21000001 BTC", Err(OutOfRangeError::too_small()));
    scase("21000001 BTC", Err(OutOfRangeError::too_big(true)));
    scase("-2100000000000001 SAT", Err(OutOfRangeError::too_small()));
    scase("2100000000000001 SAT", Err(OutOfRangeError::too_big(true)));
    case("21000001 BTC", Err(OutOfRangeError::too_big(false)));
    case("18446744073709551616 sat", Err(OutOfRangeError::too_big(false)));

    ok_case(".5 bits", sat(50));
    ok_scase("-.5 bits", ssat(-50));
    ok_case("0.00253583 BTC", sat(253_583));
    ok_scase("-5 satoshi", ssat(-5));
    ok_case("0.10000000 BTC", sat(100_000_00));
    ok_scase("-100 bits", ssat(-10_000));
    ok_case("21000000 BTC", Amount::MAX);
    ok_scase("21000000 BTC", SignedAmount::MAX);
    ok_scase("-21000000 BTC", SignedAmount::MIN);
}

#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn to_from_string_in() {
    use super::Denomination as D;
    let ua_str = Amount::from_str_in;
    let ua_sat = Amount::from_sat_unchecked;
    let sa_str = SignedAmount::from_str_in;
    let sa_sat = SignedAmount::from_sat_unchecked;

    assert_eq!("0.5", ua_sat(50).to_string_in(D::Bit));
    assert_eq!("-0.5", sa_sat(-50).to_string_in(D::Bit));
    assert_eq!("0.00253583", ua_sat(253_583).to_string_in(D::Bitcoin));
    assert_eq!("-5", sa_sat(-5).to_string_in(D::Satoshi));
    assert_eq!("0.1", ua_sat(100_000_00).to_string_in(D::Bitcoin));
    assert_eq!("-0.1", sa_sat(-100_000_00).to_string_in(D::Bitcoin));

    assert_eq!("0.253583", ua_sat(253_583).to_string_in(D::CentiBitcoin));
    assert_eq!("-0.253583", sa_sat(-253_583).to_string_in(D::CentiBitcoin));
    assert_eq!("10", ua_sat(100_000_00).to_string_in(D::CentiBitcoin));
    assert_eq!("-10", sa_sat(-100_000_00).to_string_in(D::CentiBitcoin));

    assert_eq!("2.53583", ua_sat(253_583).to_string_in(D::MilliBitcoin));
    assert_eq!("-2.53583", sa_sat(-253_583).to_string_in(D::MilliBitcoin));
    assert_eq!("100", ua_sat(100_000_00).to_string_in(D::MilliBitcoin));
    assert_eq!("-100", sa_sat(-100_000_00).to_string_in(D::MilliBitcoin));

    assert_eq!("2535.83", ua_sat(253_583).to_string_in(D::MicroBitcoin));
    assert_eq!("-2535.83", sa_sat(-253_583).to_string_in(D::MicroBitcoin));
    assert_eq!("100000", ua_sat(100_000_00).to_string_in(D::MicroBitcoin));
    assert_eq!("-100000", sa_sat(-100_000_00).to_string_in(D::MicroBitcoin));

    assert_eq!("0.5", ua_sat(50).to_string_in(D::Bit));
    assert_eq!("100", ua_sat(10_000).to_string_in(D::Bit));
    assert_eq!("-0.5", sa_sat(-50).to_string_in(D::Bit));
    assert_eq!("-100", sa_sat(-10_000).to_string_in(D::Bit));

    assert_eq!("5", ua_sat(5).to_string_in(D::Satoshi));
    assert_eq!("-5", sa_sat(-5).to_string_in(D::Satoshi));

    assert_eq!("0.50", format!("{:.2}", ua_sat(50).display_in(D::Bit)));
    assert_eq!("-0.50", format!("{:.2}", sa_sat(-50).display_in(D::Bit)));

    assert_eq!("0.10000000", format!("{:.8}", ua_sat(100_000_00).display_in(D::Bitcoin)));
    assert_eq!("-100.00", format!("{:.2}", sa_sat(-10_000).display_in(D::Bit)));

    assert_eq!(ua_str(&ua_sat(500).to_string_in(D::Bitcoin), D::Bitcoin), Ok(ua_sat(500)));
    assert_eq!(ua_str(&ua_sat(1).to_string_in(D::CentiBitcoin), D::CentiBitcoin), Ok(ua_sat(1)));
    assert_eq!(
        ua_str(&ua_sat(1_000_000_000_000).to_string_in(D::MilliBitcoin), D::MilliBitcoin),
        Ok(ua_sat(1_000_000_000_000))
    );
    assert_eq!(ua_str(&ua_sat(1).to_string_in(D::MicroBitcoin), D::MicroBitcoin), Ok(ua_sat(1)));
    assert_eq!(ua_str(&ua_sat(21_000_000).to_string_in(D::Bit), D::Bit), Ok(ua_sat(21_000_000)));
    assert_eq!(ua_str(&ua_sat(0).to_string_in(D::Satoshi), D::Satoshi), Ok(ua_sat(0)));

    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Bitcoin), D::Bitcoin).is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::CentiBitcoin), D::CentiBitcoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::MilliBitcoin), D::MilliBitcoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::MicroBitcoin), D::MicroBitcoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Bit), D::Bit).is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Satoshi), D::Satoshi).is_ok());

    assert_eq!(
        sa_str(&SignedAmount::MAX.to_string_in(D::Satoshi), D::MicroBitcoin),
        Err(OutOfRangeError::too_big(true).into())
    );
    // Test an overflow bug in `abs()`
    assert_eq!(
        sa_str(&SignedAmount::MIN.to_string_in(D::Satoshi), D::MicroBitcoin),
        Err(OutOfRangeError::too_small().into())
    );
}

#[cfg(feature = "alloc")]
#[test]
fn to_string_with_denomination_from_str_roundtrip() {
    use ParseDenominationError::*;

    use super::Denomination as D;

    let amt = sat(42);
    let denom = Amount::to_string_with_denomination;
    assert_eq!(denom(amt, D::Bitcoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::CentiBitcoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::MilliBitcoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::MicroBitcoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::Bit).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::Satoshi).parse::<Amount>(), Ok(amt));

    assert_eq!(
        "42 satoshi BTC".parse::<Amount>(),
        Err(Unknown(UnknownDenominationError("satoshi BTC".into())).into()),
    );
    assert_eq!(
        "-42 satoshi BTC".parse::<SignedAmount>(),
        Err(Unknown(UnknownDenominationError("satoshi BTC".into())).into()),
    );
}

#[cfg(feature = "serde")]
#[test]
fn serde_as_sat() {
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
            serde_test::Token::U64(123_456_789),
            serde_test::Token::Str("samt"),
            serde_test::Token::I64(-123_456_789),
            serde_test::Token::StructEnd,
        ],
    );
}

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_as_btc() {
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

    // errors
    let t: Result<T, serde_json::Error> =
        serde_json::from_str("{\"amt\": 1000000.000000001, \"samt\": 1}");
    assert!(t.unwrap_err().to_string().contains(
        &ParseAmountError(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 16 }))
            .to_string()
    ));
    let t: Result<T, serde_json::Error> = serde_json::from_str("{\"amt\": -1, \"samt\": 1}");
    assert!(t.unwrap_err().to_string().contains(&OutOfRangeError::negative().to_string()));
}

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[test]
fn serde_as_str() {
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

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_as_btc_opt() {
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

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_as_sat_opt() {
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

#[cfg(feature = "serde")]
#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn serde_as_str_opt() {
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

#[test]
fn sum_amounts() {
    assert_eq!([].iter().sum::<NumOpResult<Amount>>(), Amount::ZERO.into());
    assert_eq!([].iter().sum::<NumOpResult<SignedAmount>>(), SignedAmount::ZERO.into());

    let results =
        [NumOpResult::Valid(sat(42)), NumOpResult::Valid(sat(1337)), NumOpResult::Valid(sat(21))];
    assert_eq!(results.iter().sum::<NumOpResult<Amount>>(), NumOpResult::Valid(sat(1400)));

    let signed_results = [
        NumOpResult::Valid(ssat(42)),
        NumOpResult::Valid(ssat(1337)),
        NumOpResult::Valid(ssat(21)),
    ];
    assert_eq!(
        signed_results.iter().sum::<NumOpResult<SignedAmount>>(),
        NumOpResult::Valid(ssat(1400))
    );

    let amounts = [sat(42), sat(1337), sat(21)];
    assert_eq!(
        amounts.iter().map(|a| NumOpResult::Valid(*a)).sum::<NumOpResult<Amount>>(),
        sat(1400).into(),
    );
    assert_eq!(
        amounts.into_iter().map(NumOpResult::Valid).sum::<NumOpResult<Amount>>(),
        sat(1400).into(),
    );

    let amounts = [ssat(-42), ssat(1337), ssat(21)];
    assert_eq!(
        amounts.iter().map(NumOpResult::from).sum::<NumOpResult<SignedAmount>>(),
        ssat(1316).into(),
    );
    assert_eq!(
        amounts.into_iter().map(NumOpResult::from).sum::<NumOpResult<SignedAmount>>(),
        ssat(1316).into()
    );
}

#[test]
fn checked_sum_amounts() {
    assert_eq!([].into_iter().checked_sum(), Some(Amount::ZERO));
    assert_eq!([].into_iter().checked_sum(), Some(SignedAmount::ZERO));

    let amounts = [sat(42), sat(1337), sat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, Some(sat(1400)));

    let amounts = [Amount::MAX_MONEY, sat(1337), sat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, None);

    let amounts = [SignedAmount::MIN, ssat(-1), ssat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, None);

    let amounts = [SignedAmount::MAX, ssat(1), ssat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, None);

    let amounts = [ssat(42), ssat(3301), ssat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, Some(ssat(3364)));
}

#[test]
fn denomination_string_acceptable_forms() {
    // Exhaustive list of valid forms.
    let valid = [
        "BTC", "btc", "cBTC", "cbtc", "mBTC", "mbtc", "uBTC", "ubtc", "µBTC", "µbtc", "bit",
        "bits", "BIT", "BITS", "SATOSHI", "satoshi", "SATOSHIS", "satoshis", "SAT", "sat", "SATS",
        "sats",
    ];
    for denom in valid {
        assert!(denom.parse::<Denomination>().is_ok());
    }
}

#[test]
fn disallow_confusing_forms() {
    let confusing = ["CBTC", "Cbtc", "MBTC", "Mbtc", "UBTC", "Ubtc"];
    for denom in confusing {
        match denom.parse::<Denomination>() {
            Ok(_) => panic!("from_str should error for {}", denom),
            Err(ParseDenominationError::PossiblyConfusing(_)) => {}
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[test]
fn disallow_unknown_denomination() {
    // Non-exhaustive list of unknown forms.
    let unknown = ["NBTC", "ABC", "abc", "mSat", "msat"];
    for denom in unknown {
        match denom.parse::<Denomination>() {
            Ok(_) => panic!("from_str should error for {}", denom),
            Err(ParseDenominationError::Unknown(_)) => (),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[test]
#[cfg(feature = "alloc")]
fn trailing_zeros_for_amount() {
    assert_eq!(format!("{}", sat(1_000_000)), "0.01 BTC");
    assert_eq!(format!("{}", Amount::ONE_SAT), "0.00000001 BTC");
    assert_eq!(format!("{}", Amount::ONE_BTC), "1 BTC");
    assert_eq!(format!("{}", sat(1)), "0.00000001 BTC");
    assert_eq!(format!("{}", sat(10)), "0.0000001 BTC");
    assert_eq!(format!("{:.2}", sat(10)), "0.00 BTC");
    assert_eq!(format!("{:.2}", sat(100)), "0.00 BTC");
    assert_eq!(format!("{:.2}", sat(1000)), "0.00 BTC");
    assert_eq!(format!("{:.2}", sat(10_000)), "0.00 BTC");
    assert_eq!(format!("{:.2}", sat(100_000)), "0.00 BTC");
    assert_eq!(format!("{:.2}", sat(1_000_000)), "0.01 BTC");
    assert_eq!(format!("{:.2}", sat(10_000_000)), "0.10 BTC");
    assert_eq!(format!("{:.2}", sat(100_000_000)), "1.00 BTC");
    assert_eq!(format!("{:.2}", sat(500_000)), "0.01 BTC");
    assert_eq!(format!("{:.2}", sat(9_500_000)), "0.10 BTC");
    assert_eq!(format!("{:.2}", sat(99_500_000)), "1.00 BTC");
    assert_eq!(format!("{}", sat(100_000_000)), "1 BTC");
    assert_eq!(format!("{}", sat(40_000_000_000)), "400 BTC");
    assert_eq!(format!("{:.10}", sat(100_000_000)), "1.0000000000 BTC");
    assert_eq!(format!("{}", sat(400_000_000_000_010)), "4000000.0000001 BTC");
    assert_eq!(format!("{}", sat(400_000_000_000_000)), "4000000 BTC");
}

#[test]
fn add_sub_combos() {
    // Checks lhs op rhs for all reference combos.
    macro_rules! check_ref {
        ($($lhs:ident $op:tt $rhs:ident = $ans:ident);* $(;)?) => {
            $(
                assert_eq!($lhs $op $rhs, $ans);
                assert_eq!(&$lhs $op $rhs, $ans);
                assert_eq!($lhs $op &$rhs, $ans);
                assert_eq!(&$lhs $op &$rhs, $ans);
            )*
        }
    }

    // Checks lhs op rhs for all amount and `NumOpResult` combos.
    macro_rules! check_res {
        ($($amount:ident, $op:tt, $lhs:literal, $rhs:literal, $ans:literal);* $(;)?) => {
            $(
                let amt = |sat| $amount::from_sat(sat).unwrap();

                let sat_lhs = amt($lhs);
                let sat_rhs = amt($rhs);

                let res_lhs = NumOpResult::from(sat_lhs);
                let res_rhs = NumOpResult::from(sat_rhs);

                let ans = NumOpResult::from(amt($ans));

                check_ref! {
                    sat_lhs $op sat_rhs = ans;
                    sat_lhs $op res_rhs = ans;
                    res_lhs $op sat_rhs = ans;
                    res_lhs $op res_rhs = ans;
                }
            )*
        }
    }

    // Checks lhs op rhs for both amount types.
    macro_rules! check_op {
        ($($lhs:literal $op:tt $rhs:literal = $ans:literal);* $(;)?) => {
            $(
                check_res!(Amount, $op, $lhs, $rhs, $ans);
                check_res!(SignedAmount, $op, $lhs, $rhs, $ans);
            )*
        }
    }

    // We do not currently support division involving `NumOpResult` and an amount type.
    check_op! {
        307 + 461 = 768;
        461 - 307 = 154;
    }
}

#[test]
fn unsigned_addition() {
    assert_eq!(sat(0) + sat(0), NumOpResult::from(sat(0)));
    assert_eq!(sat(0) + sat(307), NumOpResult::from(sat(307)));
    assert_eq!(sat(307) + sat(0), NumOpResult::from(sat(307)));
    assert_eq!(sat(307) + sat(461), NumOpResult::from(sat(768)));
    assert_eq!(sat(0) + Amount::MAX_MONEY, NumOpResult::from(Amount::MAX_MONEY));
}

#[test]
fn signed_addition() {
    assert_eq!(ssat(0) + ssat(0), NumOpResult::from(ssat(0)));
    assert_eq!(ssat(0) + ssat(307), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) + ssat(0), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) + ssat(461), NumOpResult::from(ssat(768)));
    assert_eq!(ssat(0) + SignedAmount::MAX_MONEY, NumOpResult::from(SignedAmount::MAX_MONEY));

    assert_eq!(ssat(0) + ssat(-307), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) + ssat(0), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) + ssat(461), NumOpResult::from(ssat(154)));
    assert_eq!(ssat(307) + ssat(-461), NumOpResult::from(ssat(-154)));
    assert_eq!(ssat(-307) + ssat(-461), NumOpResult::from(ssat(-768)));
    assert_eq!(
        SignedAmount::MAX_MONEY + -SignedAmount::MAX_MONEY,
        NumOpResult::from(SignedAmount::ZERO)
    );
}

#[test]
fn unsigned_subtraction() {
    assert_eq!(sat(0) - sat(0), NumOpResult::from(sat(0)));
    assert_eq!(sat(307) - sat(0), NumOpResult::from(sat(307)));
    assert_eq!(sat(461) - sat(307), NumOpResult::from(sat(154)));
}

#[test]
fn signed_subtraction() {
    assert_eq!(ssat(0) - ssat(0), NumOpResult::from(ssat(0)));
    assert_eq!(ssat(0) - ssat(307), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(307) - ssat(0), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) - ssat(461), NumOpResult::from(ssat(-154)));
    assert_eq!(ssat(0) - SignedAmount::MAX_MONEY, NumOpResult::from(-SignedAmount::MAX_MONEY));

    assert_eq!(ssat(0) - ssat(-307), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(-307) - ssat(0), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) - ssat(461), NumOpResult::from(ssat(-768)));
    assert_eq!(ssat(307) - ssat(-461), NumOpResult::from(ssat(768)));
    assert_eq!(ssat(-307) - ssat(-461), NumOpResult::from(ssat(154)));
}

#[test]
fn op_int_combos() {
    let res = |n_sat| NumOpResult::from(sat(n_sat));
    let sres = |n_ssat| NumOpResult::from(ssat(n_ssat));

    assert_eq!(sat(23) * 31, res(713));
    assert_eq!(ssat(23) * 31, sres(713));
    assert_eq!(res(23) * 31, res(713));
    assert_eq!(sres(23) * 31, sres(713));

    assert_eq!(31 * sat(23), res(713));
    assert_eq!(31 * ssat(23), sres(713));
    assert_eq!(31 * res(23), res(713));
    assert_eq!(31 * sres(23), sres(713));

    // No remainder.
    assert_eq!(sat(1897) / 7, res(271));
    assert_eq!(ssat(1897) / 7, sres(271));
    assert_eq!(res(1897) / 7, res(271));
    assert_eq!(sres(1897) / 7, sres(271));

    // Truncation works as expected.
    assert_eq!(sat(1901) / 7, res(271));
    assert_eq!(ssat(1901) / 7, sres(271));
    assert_eq!(res(1901) / 7, res(271));
    assert_eq!(sres(1901) / 7, sres(271));

    // No remainder.
    assert_eq!(sat(1897) % 7, res(0));
    assert_eq!(ssat(1897) % 7, sres(0));
    assert_eq!(res(1897) % 7, res(0));
    assert_eq!(sres(1897) % 7, sres(0));

    // Remainder works as expected.
    assert_eq!(sat(1901) % 7, res(4));
    assert_eq!(ssat(1901) % 7, sres(4));
    assert_eq!(res(1901) % 7, res(4));
    assert_eq!(sres(1901) % 7, sres(4));
}

#[test]
fn unsigned_amount_div_by_amount() {
    assert_eq!(sat(0) / sat(7), 0);
    assert_eq!(sat(1897) / sat(7), 271);
}

#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn unsigned_amount_div_by_amount_zero() { let _ = sat(1897) / Amount::ZERO; }

#[test]
fn signed_amount_div_by_amount() {
    assert_eq!(ssat(0) / ssat(7), 0);

    assert_eq!(ssat(1897) / ssat(7), 271);
    assert_eq!(ssat(1897) / ssat(-7), -271);
    assert_eq!(ssat(-1897) / ssat(7), -271);
    assert_eq!(ssat(-1897) / ssat(-7), 271);
}

#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn signed_amount_div_by_amount_zero() { let _ = ssat(1897) / SignedAmount::ZERO; }

#[test]
fn check_const() {
    assert_eq!(SignedAmount::ONE_BTC.to_sat(), 100_000_000);
    assert_eq!(Amount::ONE_BTC.to_sat(), 100_000_000);
    assert_eq!(SignedAmount::FIFTY_BTC.to_sat(), SignedAmount::ONE_BTC.to_sat() * 50);
    assert_eq!(Amount::FIFTY_BTC.to_sat(), Amount::ONE_BTC.to_sat() * 50);
    assert_eq!(Amount::MAX.to_sat() as i64, SignedAmount::MAX.to_sat());
}

// Sanity check than stdlib supports the set of reference combinations for the ops we want.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn sanity_all_ops() {
    let x = 127;

    let _ = x + x;
    let _ = &x + x;
    let _ = x + &x;
    let _ = &x + &x;

    let _ = x - x;
    let _ = &x - x;
    let _ = x - &x;
    let _ = &x - &x;

    let _ = -x;
}

// Verify we have implemented all combinations of ops for the amount types and `NumOpResult` type.
// It's easier to read this test than check the code.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn num_op_result_ops() {
    let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // Explicit type as sanity check.
    let res: NumOpResult<Amount> = sat + sat;
    let sres: NumOpResult<SignedAmount> = ssat + ssat;

    macro_rules! check_op {
        ($(let _ = $lhs:ident $op:tt $rhs:ident);* $(;)?) => {
            $(
                let _ = $lhs $op $rhs;
                let _ = &$lhs $op $rhs;
                let _ = $lhs $op &$rhs;
                let _ = &$lhs $op &$rhs;
            )*
        }
    }

    // We do not currently support division involving `NumOpResult` and an amount type.
    check_op! {
        // Operations where RHS is the result of another operation.
        let _ = sat + res;
        let _ = sat - res;
        // let _ = sat / res;
        let _ = ssat + sres;
        let _ = ssat - sres;
        // let _ = ssat / sres;

        // Operations where LHS is the result of another operation.
        let _ = res + sat;
        let _ = res - sat;
        // let _ = res / sat;
        let _ = sres + ssat;
        let _ = sres - ssat;
        // let _ = sres / ssat;

        // Operations that where both sides are the result of another operation.
        let _ = res + res;
        let _ = res - res;
        // let _ = res / res;
        let _ = sres + sres;
        let _ = sres - sres;
        // let _ = sres / sres;
    };
}

// Verify we have implemented all combinations of ops for the `NumOpResult` type and an integer.
// It's easier to read this test than check the code.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn num_op_result_ops_integer() {
    let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // Explicit type as sanity check.
    let res: NumOpResult<Amount> = sat + sat;
    let sres: NumOpResult<SignedAmount> = ssat + ssat;

    macro_rules! check_op {
        ($(let _ = $lhs:ident $op:tt $rhs:literal);* $(;)?) => {
            $(
                let _ = $lhs $op $rhs;
                let _ = &$lhs $op $rhs;
                let _ = $lhs $op &$rhs;
                let _ = &$lhs $op &$rhs;
            )*
        }
    }
    check_op! {
        // Operations on an amount type and an integer.
        let _ = sat * 3_u64; // Explicit type for the benefit of the reader.
        let _ = sat / 3;
        let _ = sat % 3;

        let _ = ssat * 3_i64; // Explicit type for the benefit of the reader.
        let _ = ssat / 3;
        let _ = ssat % 3;

        // Operations on a `NumOpResult` and integer.
        let _ = res * 3_u64; // Explicit type for the benefit of the reader.
        let _ = res / 3;
        let _ = res % 3;

        let _ = sres * 3_i64; // Explicit type for the benefit of the reader.
        let _ = sres / 3;
        let _ = sres % 3;
    };
}

// Verify we have implemented all `Neg` for the amount types.
#[test]
fn amount_op_result_neg() {
    // TODO: Implement Neg all round.

    // let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // let _ = -sat;
    let _ = -ssat;
    // let _ = -res;
    // let _ = -sres;
}

// Verify we have implemented all `Sum` for the `NumOpResult` type.
#[test]
fn amount_op_result_sum() {
    let res = Amount::from_sat(1).unwrap() + Amount::from_sat(1).unwrap();
    let amounts = [res, res];
    let amount_refs = [&res, &res];

    // Sum iterators.
    let _ = amounts.iter().sum::<NumOpResult<Amount>>();
    let _ = amount_refs.iter().copied().sum::<NumOpResult<Amount>>();
    let _ = amount_refs.into_iter().sum::<NumOpResult<Amount>>();
}
