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

#[test]
fn sanity_check() {
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!(ssat(-100).abs(), ssat(100));
    assert_eq!(ssat(i64::MIN + 1).checked_abs().unwrap(), ssat(i64::MAX));
    assert_eq!(ssat(-100).signum(), -1);
    assert_eq!(ssat(0).signum(), 0);
    assert_eq!(ssat(100).signum(), 1);
    assert!(ssat(i64::MIN).checked_abs().is_none());
    assert!(!ssat(-100).is_positive());
    assert!(ssat(100).is_positive());

    #[cfg(feature = "alloc")]
    {
        assert_eq!(Amount::from_float_in(0_f64, Denomination::Bitcoin).unwrap(), sat(0));
        assert_eq!(Amount::from_float_in(2_f64, Denomination::Bitcoin).unwrap(), sat(200_000_000));
        assert!(Amount::from_float_in(-100_f64, Denomination::Bitcoin).is_err());
    }
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
    let amt = Amount::from_int_btc_const(2);
    assert_eq!(Amount::from_sat(200_000_000), amt);
}

#[test]
fn signed_amount_try_from_amount() {
    let ua_positive = Amount::from_sat(123);
    let sa_positive = SignedAmount::try_from(ua_positive).unwrap();
    assert_eq!(sa_positive, SignedAmount::from_sat(123));

    let ua_max = Amount::MAX;
    let result = SignedAmount::try_from(ua_max);
    assert_eq!(result, Err(OutOfRangeError { is_signed: true, is_greater_than_max: true }));
}

#[test]
fn amount_try_from_signed_amount() {
    let sa_positive = SignedAmount::from_sat(123);
    let ua_positive = Amount::try_from(sa_positive).unwrap();
    assert_eq!(ua_positive, Amount::from_sat(123));

    let sa_negative = SignedAmount::from_sat(-123);
    let result = Amount::try_from(sa_negative);
    assert_eq!(result, Err(OutOfRangeError { is_signed: false, is_greater_than_max: false }));
}

#[test]
fn mul_div() {
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!(sat(14) * 3, sat(42));
    assert_eq!(sat(14) / 2, sat(7));
    assert_eq!(sat(14) % 3, sat(2));
    assert_eq!(ssat(-14) * 3, ssat(-42));
    assert_eq!(ssat(-14) / 2, ssat(-7));
    assert_eq!(ssat(-14) % 3, ssat(-2));

    let mut a = sat(30);
    a /= 3;
    assert_eq!(a, sat(10));
    a %= 3;
    assert_eq!(a, sat(1));
    a *= 3;
    assert_eq!(a, sat(3));

    let mut b = ssat(30);
    b /= 3;
    assert_eq!(b, ssat(10));
    b %= 3;
    assert_eq!(b, ssat(1));
    b *= 3;
    assert_eq!(b, ssat(3));
}

#[test]
fn neg() {
    let amount = -SignedAmount::from_sat(2);
    assert_eq!(amount.to_sat(), -2);
}

#[cfg(feature = "std")]
#[test]
fn overflows() {
    // panic on overflow
    let result = panic::catch_unwind(|| Amount::MAX + Amount::from_sat(1));
    assert!(result.is_err());
    let result = panic::catch_unwind(|| Amount::from_sat(8_446_744_073_709_551_615) * 3);
    assert!(result.is_err());
}

#[test]
fn checked_arithmetic() {
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!(SignedAmount::MAX.checked_add(ssat(1)), None);
    assert_eq!(SignedAmount::MIN.checked_sub(ssat(1)), None);
    assert_eq!(Amount::MAX.checked_add(sat(1)), None);
    assert_eq!(Amount::MIN.checked_sub(sat(1)), None);

    assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
    assert_eq!(ssat(-6).checked_div(2), Some(ssat(-3)));
}

#[test]
#[allow(deprecated_in_future)]
fn unchecked_arithmetic() {
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!(ssat(10).unchecked_add(ssat(20)), ssat(30));
    assert_eq!(ssat(50).unchecked_sub(ssat(10)), ssat(40));
    assert_eq!(sat(5).unchecked_add(sat(7)), sat(12));
    assert_eq!(sat(10).unchecked_sub(sat(7)), sat(3));
}

#[test]
fn positive_sub() {
    let ssat = SignedAmount::from_sat;

    assert_eq!(ssat(10).positive_sub(ssat(7)).unwrap(), ssat(3));
    assert!(ssat(-10).positive_sub(ssat(7)).is_none());
    assert!(ssat(10).positive_sub(ssat(-7)).is_none());
    assert!(ssat(10).positive_sub(ssat(11)).is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_weight_ceil() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = Amount::from_sat(1).checked_div_by_weight_ceil(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = Amount::from_sat(329).checked_div_by_weight_ceil(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round up to 864
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(864));

    let fee_rate = Amount::MAX.checked_div_by_weight_ceil(weight);
    assert!(fee_rate.is_none());

    let fee_rate = Amount::ONE_SAT.checked_div_by_weight_ceil(Weight::ZERO);
    assert!(fee_rate.is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_weight_floor() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = Amount::from_sat(1).checked_div_by_weight_floor(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = Amount::from_sat(329).checked_div_by_weight_floor(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round down to 863
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863));

    let fee_rate = Amount::MAX.checked_div_by_weight_floor(weight);
    assert!(fee_rate.is_none());

    let fee_rate = Amount::ONE_SAT.checked_div_by_weight_floor(Weight::ZERO);
    assert!(fee_rate.is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn amount_checked_div_by_fee_rate() {
    let amount = Amount::from_sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(2);

    // Test floor division
    let weight = amount.checked_div_by_fee_rate_floor(fee_rate).unwrap();
    // 1000 sats / (2 sats/kwu) = 500,000 wu
    assert_eq!(weight, Weight::from_wu(500_000));

    // Test ceiling division
    let weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(weight, Weight::from_wu(500_000)); // Same result for exact division

    // Test truncation behavior
    let amount = Amount::from_sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(3);
    let floor_weight = amount.checked_div_by_fee_rate_floor(fee_rate).unwrap();
    let ceil_weight = amount.checked_div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(floor_weight, Weight::from_wu(333_333));
    assert_eq!(ceil_weight, Weight::from_wu(333_334));

    // Test division by zero
    let zero_fee_rate = FeeRate::from_sat_per_kwu(0);
    assert!(amount.checked_div_by_fee_rate_floor(zero_fee_rate).is_none());
    assert!(amount.checked_div_by_fee_rate_ceil(zero_fee_rate).is_none());

    // Test with maximum fee calculation amount.
    let max = Amount::MAX / 1000;
    let small_fee_rate = FeeRate::from_sat_per_kwu(1);
    let weight = max.checked_div_by_fee_rate_floor(small_fee_rate).unwrap();
    assert_eq!(weight, Weight::from_wu(18_446_744_073_709_551_000));

    let max = max + Amount::from_sat(1);
    assert!(max.checked_div_by_fee_rate_floor(small_fee_rate).is_none());

    // Test overflow case
    let tiny_fee_rate = FeeRate::from_sat_per_kwu(1);
    let large_amount = Amount::from_sat(u64::MAX);
    assert!(large_amount.checked_div_by_fee_rate_floor(tiny_fee_rate).is_none());
    assert!(large_amount.checked_div_by_fee_rate_ceil(tiny_fee_rate).is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn floating_point() {
    use super::Denomination as D;
    let f = Amount::from_float_in;
    let sf = SignedAmount::from_float_in;
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

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

    // Amount can be grater than the max SignedAmount.
    assert!(f(SignedAmount::MAX.to_float_in(D::Satoshi) + 1.0, D::Satoshi).is_ok());

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
    let btc = Denomination::Bitcoin;
    let sat = Denomination::Satoshi;
    let p = Amount::from_str_in;
    let sp = SignedAmount::from_str_in;

    assert_eq!(p("x", btc), Err(E::from(InvalidCharacterError { invalid_char: 'x', position: 0 })));
    assert_eq!(
        p("-", btc),
        Err(E::from(MissingDigitsError { kind: MissingDigitsKind::OnlyMinusSign }))
    );
    assert_eq!(
        sp("-", btc),
        Err(E::from(MissingDigitsError { kind: MissingDigitsKind::OnlyMinusSign }))
    );
    assert_eq!(
        p("-1.0x", btc),
        Err(E::from(InvalidCharacterError { invalid_char: 'x', position: 4 }))
    );
    assert_eq!(
        p("0.0 ", btc),
        Err(E::from(InvalidCharacterError { invalid_char: ' ', position: 3 }))
    );
    assert_eq!(
        p("0.000.000", btc),
        Err(E::from(InvalidCharacterError { invalid_char: '.', position: 5 }))
    );
    #[cfg(feature = "alloc")]
    let more_than_max = format!("1{}", Amount::MAX);
    #[cfg(feature = "alloc")]
    assert_eq!(p(&more_than_max, btc), Err(OutOfRangeError::too_big(false).into()));
    assert_eq!(p("0.000000042", btc), Err(TooPreciseError { position: 10 }.into()));
    assert_eq!(p("1.0000000", sat), Ok(Amount::from_sat(1)));
    assert_eq!(p("1.1", sat), Err(TooPreciseError { position: 2 }.into()));
    assert_eq!(p("1000.1", sat), Err(TooPreciseError { position: 5 }.into()));
    assert_eq!(p("1001.0000000", sat), Ok(Amount::from_sat(1001)));
    assert_eq!(p("1000.0000001", sat), Err(TooPreciseError { position: 11 }.into()));

    assert_eq!(p("1", btc), Ok(Amount::from_sat(1_000_000_00)));
    assert_eq!(sp("-.5", btc), Ok(SignedAmount::from_sat(-500_000_00)));
    #[cfg(feature = "alloc")]
    assert_eq!(sp(&i64::MIN.to_string(), sat), Ok(SignedAmount::from_sat(i64::MIN)));
    assert_eq!(p("1.1", btc), Ok(Amount::from_sat(1_100_000_00)));
    assert_eq!(p("100", sat), Ok(Amount::from_sat(100)));
    assert_eq!(p("55", sat), Ok(Amount::from_sat(55)));
    assert_eq!(p("5500000000000000000", sat), Ok(Amount::from_sat(55_000_000_000_000_000_00)));
    // Should this even pass?
    assert_eq!(p("5500000000000000000.", sat), Ok(Amount::from_sat(55_000_000_000_000_000_00)));
    assert_eq!(p("12345678901.12345678", btc), Ok(Amount::from_sat(12_345_678_901__123_456_78)));

    // make sure satoshi > i64::MAX is checked.
    #[cfg(feature = "alloc")]
    {
        let amount = Amount::from_sat(i64::MAX as u64);
        assert_eq!(Amount::from_str_in(&amount.to_string_in(sat), sat), Ok(amount));
        assert!(SignedAmount::from_str_in(&(amount + Amount::from_sat(1)).to_string_in(sat), sat)
            .is_err());
        assert!(Amount::from_str_in(&(amount + Amount::from_sat(1)).to_string_in(sat), sat).is_ok());
    }

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
    assert_eq!(SignedAmount::from_sat(-42).to_string_in(D::Bitcoin), "-0.00000042");

    assert_eq!(Amount::ONE_BTC.to_string_with_denomination(D::Bitcoin), "1 BTC");
    assert_eq!(SignedAmount::ONE_BTC.to_string_with_denomination(D::Satoshi), "100000000 satoshi");
    assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::Bitcoin), "0.00000001 BTC");
    assert_eq!(
        SignedAmount::from_sat(-42).to_string_with_denomination(D::Bitcoin),
        "-0.00000042 BTC"
    );
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
                assert_eq!(format!($format_string, Amount::from_sat($val).display_in(Denomination::$denom)), $expected);
                assert_eq!(format!($format_string, SignedAmount::from_sat($val as i64).display_in(Denomination::$denom)), $expected);
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
                assert_eq!(format!($format_string, Amount::from_sat($val).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
                assert_eq!(format!($format_string, SignedAmount::from_sat($val as i64).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
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
    let ssat = SignedAmount::from_sat;
    let sat = Amount::from_sat;
    let max_sats: u64 = Amount::MAX.to_sat();

    assert_eq!(SignedAmount::try_from(sat(100)).unwrap(), ssat(100));
    assert_eq!(Amount::try_from(ssat(100)).unwrap(), sat(100));

    assert_eq!(sat(i64::MAX as u64 + 1).to_signed(), Err(OutOfRangeError::too_big(true)));
    assert_eq!(sat(max_sats).to_signed(), Err(OutOfRangeError::too_big(true)));

    assert_eq!(ssat(-100).to_unsigned(), Err(OutOfRangeError::negative()));
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
    scase("-200000000000 BTC", Err(OutOfRangeError::too_small()));
    case("18446744073709551616 sat", Err(OutOfRangeError::too_big(false)));

    ok_case(".5 bits", Amount::from_sat(50));
    ok_scase("-.5 bits", SignedAmount::from_sat(-50));
    ok_case("0.00253583 BTC", Amount::from_sat(253_583));
    ok_scase("-5 satoshi", SignedAmount::from_sat(-5));
    ok_case("0.10000000 BTC", Amount::from_sat(100_000_00));
    ok_scase("-100 bits", SignedAmount::from_sat(-10_000));
    #[cfg(feature = "alloc")]
    ok_scase(&format!("{} SAT", i64::MIN), SignedAmount::from_sat(i64::MIN));
}

#[cfg(feature = "alloc")]
#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per bitcoin.
fn to_from_string_in() {
    use super::Denomination as D;
    let ua_str = Amount::from_str_in;
    let ua_sat = Amount::from_sat;
    let sa_str = SignedAmount::from_str_in;
    let sa_sat = SignedAmount::from_sat;

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

    let amt = Amount::from_sat(42);
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
        &T {
            amt: Amount::from_sat(123_456_789),
            samt: SignedAmount::from_sat(-123_456_789),
        },
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

    let orig = T {
        amt: Amount::from_sat(21_000_000__000_000_01),
        samt: SignedAmount::from_sat(-21_000_000__000_000_01),
    };

    let json = "{\"amt\": 21000000.00000001, \
                \"samt\": -21000000.00000001}";
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
        &T {
            amt: Amount::from_sat(123_456_789),
            samt: SignedAmount::from_sat(-123_456_789),
        },
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

    let with = T {
        amt: Some(Amount::from_sat(2_500_000_00)),
        samt: Some(SignedAmount::from_sat(-2_500_000_00)),
    };
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

    let with = T {
        amt: Some(Amount::from_sat(2_500_000_00)),
        samt: Some(SignedAmount::from_sat(-2_500_000_00)),
    };
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

    let with = T {
        amt: Some(Amount::from_sat(123_456_789)),
        samt: Some(SignedAmount::from_sat(-123_456_789)),
    };
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
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!([].iter().sum::<Amount>(), Amount::ZERO);
    assert_eq!([].iter().sum::<SignedAmount>(), SignedAmount::ZERO);

    let amounts = [sat(42), sat(1337), sat(21)];
    assert_eq!(amounts.iter().sum::<Amount>(), sat(1400));
    let sum = amounts.into_iter().sum::<Amount>();
    assert_eq!(sum, sat(1400));

    let amounts = [ssat(-42), ssat(1337), ssat(21)];
    assert_eq!(amounts.iter().sum::<SignedAmount>(), ssat(1316));
    let sum = amounts.into_iter().sum::<SignedAmount>();
    assert_eq!(sum, ssat(1316));
}

#[test]
fn checked_sum_amounts() {
    let sat = Amount::from_sat;
    let ssat = SignedAmount::from_sat;

    assert_eq!([].into_iter().checked_sum(), Some(Amount::ZERO));
    assert_eq!([].into_iter().checked_sum(), Some(SignedAmount::ZERO));

    let amounts = [sat(42), sat(1337), sat(21)];
    let sum = amounts.into_iter().checked_sum();
    assert_eq!(sum, Some(sat(1400)));

    let amounts = [sat(u64::MAX), sat(1337), sat(21)];
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
    let sat = Amount::from_sat;

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
#[allow(clippy::op_ref)]
fn unsigned_addition() {
    let sat = Amount::from_sat;

    let one = sat(1);
    let two = sat(2);
    let three = sat(3);

    assert!(one + two == three);
    assert!(&one + two == three);
    assert!(one + &two == three);
    assert!(&one + &two == three);
}

#[test]
#[allow(clippy::op_ref)]
fn unsigned_subtract() {
    let sat = Amount::from_sat;

    let one = sat(1);
    let two = sat(2);
    let three = sat(3);

    assert!(three - two == one);
    assert!(&three - two == one);
    assert!(three - &two == one);
    assert!(&three - &two == one);
}

#[test]
fn unsigned_add_assign() {
    let sat = Amount::from_sat;

    let mut f = sat(1);
    f += sat(2);
    assert_eq!(f, sat(3));

    let mut f = sat(1);
    f += &sat(2);
    assert_eq!(f, sat(3));
}

#[test]
fn unsigned_sub_assign() {
    let sat = Amount::from_sat;

    let mut f = sat(3);
    f -= sat(2);
    assert_eq!(f, sat(1));

    let mut f = sat(3);
    f -= &sat(2);
    assert_eq!(f, sat(1));
}

#[test]
#[allow(clippy::op_ref)]
fn signed_addition() {
    let ssat = SignedAmount::from_sat;

    let one = ssat(1);
    let two = ssat(2);
    let three = ssat(3);

    assert!(one + two == three);
    assert!(&one + two == three);
    assert!(one + &two == three);
    assert!(&one + &two == three);
}

#[test]
#[allow(clippy::op_ref)]
fn signed_subtract() {
    let ssat = SignedAmount::from_sat;

    let one = ssat(1);
    let two = ssat(2);
    let three = ssat(3);

    assert!(three - two == one);
    assert!(&three - two == one);
    assert!(three - &two == one);
    assert!(&three - &two == one);
}

#[test]
fn signed_add_assign() {
    let ssat = SignedAmount::from_sat;

    let mut f = ssat(1);
    f += ssat(2);
    assert_eq!(f, ssat(3));

    let mut f = ssat(1);
    f += &ssat(2);
    assert_eq!(f, ssat(3));
}

#[test]
fn signed_sub_assign() {
    let ssat = SignedAmount::from_sat;

    let mut f = ssat(3);
    f -= ssat(2);
    assert_eq!(f, ssat(1));

    let mut f = ssat(3);
    f -= &ssat(2);
    assert_eq!(f, ssat(1));
}

#[test]
fn check_const() {
    assert_eq!(SignedAmount::ONE_BTC.to_sat(), 100_000_000);
    assert_eq!(Amount::ONE_BTC.to_sat(), 100_000_000);
    assert_eq!(SignedAmount::FIFTY_BTC.to_sat(), SignedAmount::ONE_BTC.to_sat() * 50);
    assert_eq!(Amount::FIFTY_BTC.to_sat(), Amount::ONE_BTC.to_sat() * 50);
    assert_eq!(Amount::MAX_MONEY.to_sat() as i64, SignedAmount::MAX_MONEY.to_sat());
}
