// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `units`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
// These imports test "typical" usage by user code.
use bitcoin_units::locktime::{absolute, relative}; // Typical usage is `absolute::LockTime`.
use bitcoin_units::{
    amount, block, fee_rate, locktime, parse, result, time, weight, Amount, BlockHeight,
    BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate, NumOpResult,
    SignedAmount, Weight,
};

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: amount::Denomination,
    b: NumOpResult<Amount>,
    c: result::MathOp,
}

impl Enums {
    fn new() -> Self {
        Self {
            a: amount::Denomination::Bitcoin,
            b: NumOpResult::Valid(Amount::MAX),
            c: result::MathOp::Add,
        }
    }
}

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs {
    // Full path to show alphabetic sort order.
    a: amount::Amount,
    b: amount::Display,
    c: amount::SignedAmount,
    d: block::BlockHeight,
    e: block::BlockHeightInterval,
    f: block::BlockMtp,
    g: block::BlockMtpInterval,
    h: fee_rate::FeeRate,
    i: locktime::absolute::Height,
    j: locktime::absolute::MedianTimePast,
    k: locktime::relative::NumberOf512Seconds,
    l: locktime::relative::NumberOfBlocks,
    m: time::BlockTime,
    n: weight::Weight,
}

impl Structs {
    fn max() -> Self {
        Self {
            a: Amount::MAX,
            b: Amount::MAX.display_in(amount::Denomination::Bitcoin),
            c: SignedAmount::MAX,
            d: BlockHeight::MAX,
            e: BlockHeightInterval::MAX,
            f: BlockMtp::MAX,
            g: BlockMtpInterval::MAX,
            h: FeeRate::MAX,
            i: absolute::Height::MAX,
            j: absolute::MedianTimePast::MAX,
            k: relative::NumberOf512Seconds::MAX,
            l: relative::NumberOfBlocks::MAX,
            m: BlockTime::from_u32(u32::MAX),
            n: Weight::MAX,
        }
    }
}

/// A struct that includes all public non-error types.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Types {
    a: Enums,
    b: Structs,
}

impl Types {
    fn new() -> Self { Self { a: Enums::new(), b: Structs::max() } }
}

/// A struct that includes all public non-error non-helper structs.
// C-COMMON-TRAITS excluding `Default` and `Display`. `Display` is done in `./str.rs`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CommonTraits {
    // Full path to show alphabetic sort order.
    a: amount::Amount,
    // b: amount::Display,
    c: amount::SignedAmount,
    d: block::BlockHeight,
    e: block::BlockHeightInterval,
    f: block::BlockMtp,
    g: block::BlockMtpInterval,
    h: fee_rate::FeeRate,
    i: locktime::absolute::Height,
    j: locktime::absolute::MedianTimePast,
    k: locktime::relative::NumberOf512Seconds,
    l: locktime::relative::NumberOfBlocks,
    m: time::BlockTime,
    n: weight::Weight,
}

/// A struct that includes all types that implement `Default`.
#[derive(Debug, Default, PartialEq, Eq)] // C-COMMON-TRAITS: `Default`
struct Default {
    a: Amount,
    b: SignedAmount,
    c: BlockHeightInterval,
    d: BlockMtpInterval,
    e: relative::NumberOf512Seconds,
    f: relative::NumberOfBlocks,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: amount::InputTooLargeError,
    b: amount::InvalidCharacterError,
    c: amount::MissingDenominationError,
    d: amount::MissingDigitsError,
    e: amount::OutOfRangeError,
    f: amount::ParseAmountError,
    g: amount::ParseDenominationError,
    h: amount::ParseError,
    i: amount::PossiblyConfusingDenominationError,
    j: amount::TooPreciseError,
    k: amount::UnknownDenominationError,
    l: block::TooBigForRelativeHeightError,
    #[cfg(feature = "serde")]
    m: fee_rate::serde::OverflowError,
    n: locktime::absolute::ConversionError,
    o: locktime::absolute::ParseHeightError,
    p: locktime::absolute::ParseTimeError,
    q: locktime::relative::InvalidHeightError,
    r: locktime::relative::InvalidTimeError,
    s: locktime::relative::TimeOverflowError,
    t: parse::ParseIntError,
    u: parse::PrefixedHexError,
    v: parse::UnprefixedHexError,
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_units::{amount, block, fee_rate, locktime, parse, time, weight};
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_units::{
        Amount, BlockHeight, BlockHeightInterval, BlockInterval, BlockMtp, BlockMtpInterval,
        BlockTime, FeeRate, NumOpResult, SignedAmount, Weight,
    };
}

#[test]
fn api_can_use_all_types_from_module_amount() {
    use bitcoin_units::amount::{
        Amount, Denomination, Display, InputTooLargeError, InvalidCharacterError,
        MissingDenominationError, MissingDigitsError, OutOfRangeError, ParseAmountError,
        ParseDenominationError, ParseError, PossiblyConfusingDenominationError, SignedAmount,
        TooPreciseError, UnknownDenominationError,
    };
}

#[test]
fn api_can_use_all_types_from_module_block() {
    use bitcoin_units::block::{
        BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, TooBigForRelativeHeightError,
    };
}

#[test]
fn api_can_use_all_types_from_module_fee_rate() {
    #[cfg(feature = "serde")]
    use bitcoin_units::fee_rate::serde::OverflowError;
    use bitcoin_units::fee_rate::FeeRate;
}

#[test]
fn api_can_use_all_types_from_module_locktime_absolute() {
    use bitcoin_units::locktime::absolute::error::{
        ConversionError as _, ParseHeightError as _, ParseTimeError as _,
    };
    use bitcoin_units::locktime::absolute::{
        ConversionError, Height, MedianTimePast, ParseHeightError, ParseTimeError,
    };
}

#[test]
fn api_can_use_all_types_from_module_locktime_relative() {
    use bitcoin_units::locktime::relative::error::{
        InvalidHeightError as _, InvalidTimeError as _, TimeOverflowError as _,
    };
    use bitcoin_units::locktime::relative::{
        Height, InvalidHeightError, InvalidTimeError, NumberOf512Seconds, NumberOfBlocks, Time,
        TimeOverflowError,
    };
}

#[test]
fn api_can_use_all_types_from_module_parse() {
    use bitcoin_units::parse::{ParseIntError, PrefixedHexError, UnprefixedHexError};
}

#[test]
fn api_can_use_all_types_from_module_time() {
    use bitcoin_units::time::BlockTime;
}

#[test]
fn api_can_use_all_types_from_module_weight() {
    use bitcoin_units::weight::Weight;
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    let t = Types::new();

    let debug = format!("{:?}", t.a.a);
    assert!(!debug.is_empty());

    let debug = format!("{:?}", t.b.a);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.b);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.c);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.d);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.e);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.f);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.g);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.h);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.i);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.j);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.k);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.l);
    assert!(!debug.is_empty());
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Types>();
    assert_sync::<Types>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

#[test]
fn regression_default() {
    let got: Default = Default::default();
    let want = Default {
        a: Amount::ZERO,
        b: SignedAmount::ZERO,
        c: BlockHeightInterval::ZERO,
        d: BlockMtpInterval::ZERO,
        e: relative::NumberOf512Seconds::ZERO,
        f: relative::NumberOfBlocks::ZERO,
    };
    assert_eq!(got, want);
}

#[test]
fn dyn_compatible() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        // These traits are explicitly not dyn compatible.
        // b: Box<dyn amount::serde::SerdeAmount>,
        // c: Box<dyn amount::serde::SerdeAmountForOpt>,
        // d: Box<dyn parse::Integer>, // Because of core::num::ParseIntError
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Types {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Types { a: Enums::arbitrary(u)?, b: Structs::arbitrary(u)? };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Structs {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Structs {
            a: Amount::arbitrary(u)?,
            // Skip the `Display` type.
            b: Amount::MAX.display_in(amount::Denomination::Bitcoin),
            c: SignedAmount::arbitrary(u)?,
            d: BlockHeight::arbitrary(u)?,
            e: BlockHeightInterval::arbitrary(u)?,
            f: BlockMtp::arbitrary(u)?,
            g: BlockMtpInterval::arbitrary(u)?,
            h: FeeRate::arbitrary(u)?,
            i: absolute::Height::arbitrary(u)?,
            j: absolute::MedianTimePast::arbitrary(u)?,
            k: relative::NumberOf512Seconds::arbitrary(u)?,
            l: relative::NumberOfBlocks::arbitrary(u)?,
            m: BlockTime::arbitrary(u)?,
            n: Weight::arbitrary(u)?,
        };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Enums {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Enums {
            a: amount::Denomination::arbitrary(u)?,
            b: NumOpResult::<Amount>::arbitrary(u)?,
            c: result::MathOp::arbitrary(u)?,
        };
        Ok(a)
    }
}
