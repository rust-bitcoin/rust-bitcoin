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
    amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight, Amount,
    BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate, NumOpResult,
    Sequence, SignedAmount, Weight,
};

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: amount::Denomination,
    b: absolute::LockTime,
    c: relative::LockTime,
    d: result::MathOp,
    e: result::NumOpResult<Amount>,
}

impl Enums {
    fn new() -> Self {
        Self {
            a: amount::Denomination::Bitcoin,
            b: absolute::LockTime::Blocks(absolute::Height::MAX),
            c: relative::LockTime::Blocks(relative::NumberOfBlocks::MAX),
            d: result::MathOp::Add,
            e: result::NumOpResult::Valid(Amount::MAX),
        }
    }
}

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
                 // Does not include encoders and decoders.
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
    m: pow::CompactTarget,
    n: sequence::Sequence,
    o: time::BlockTime,
    p: weight::Weight,
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
            m: pow::CompactTarget::from_consensus(u32::MAX),
            n: sequence::Sequence::MAX,
            o: BlockTime::from_u32(u32::MAX),
            p: Weight::MAX,
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
    m: pow::CompactTarget,
    n: time::BlockTime,
    o: weight::Weight,
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
    g: Sequence,
}

/// A struct that includes all public error types (excl. decode errors).
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: amount::error::InputTooLargeError,
    b: amount::error::InvalidCharacterError,
    c: amount::error::MissingDenominationError,
    d: amount::error::MissingDigitsError,
    e: amount::error::OutOfRangeError,
    f: amount::error::ParseAmountError,
    g: amount::error::ParseDenominationError,
    h: amount::error::ParseError,
    i: amount::error::PossiblyConfusingDenominationError,
    j: amount::error::TooPreciseError,
    k: amount::error::UnknownDenominationError,
    l: block::TooBigForRelativeHeightError,
    #[cfg(feature = "serde")]
    m: fee_rate::serde::OverflowError,
    n: locktime::absolute::ConversionError,
    o: locktime::absolute::ParseHeightError,
    p: locktime::absolute::ParseTimeError,
    q: locktime::relative::InvalidHeightError,
    r: locktime::relative::InvalidTimeError,
    s: locktime::relative::TimeOverflowError,
    t: parse_int::ParseIntError,
    u: parse_int::PrefixedHexError,
    v: parse_int::UnprefixedHexError,
    #[cfg(feature = "encoding")]
    w: pow::CompactTargetDecoderError,
}

/// A struct that includes all public decoder error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
#[cfg(feature = "encoding")]
struct DecoderErrors {
    a: amount::error::AmountDecoderError,
    b: block::BlockHeightDecoderError,
    c: locktime::absolute::LockTimeDecoderError,
    d: sequence::SequenceDecoderError,
    e: time::BlockTimeDecoderError,
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_units::{
        amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
    };
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_units::{
        Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime,
        CompactTarget, FeeRate, NumOpResult, Sequence, SignedAmount, Weight,
    };
}

#[test]
fn api_can_use_all_types_from_module_amount() {
    use bitcoin_units::amount::{
        Amount, Denomination, Display, OutOfRangeError, ParseAmountError, ParseDenominationError,
        ParseError, SignedAmount,
    };
    #[cfg(feature = "encoding")]
    use bitcoin_units::amount::{AmountDecoder, AmountDecoderError, AmountEncoder};
}

#[test]
fn api_can_use_all_types_from_module_amount_error() {
    use bitcoin_units::amount::error::{
        BadPositionError, InputTooLargeError, InvalidCharacterError, MissingDenominationError,
        MissingDigitsError, OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
    };
}

#[test]
fn api_can_use_all_types_from_module_block() {
    use bitcoin_units::block::{
        BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, TooBigForRelativeHeightError,
    };
    #[cfg(feature = "encoding")]
    use bitcoin_units::block::{BlockHeightDecoder, BlockHeightDecoderError, BlockHeightEncoder};
}

#[test]
fn api_can_use_all_types_from_module_sequence() {
    use bitcoin_units::sequence::Sequence;
    #[cfg(feature = "encoding")]
    use bitcoin_units::sequence::{SequenceDecoder, SequenceDecoderError, SequenceEncoder};
}

#[test]
fn api_can_use_all_types_from_module_fee_rate() {
    #[cfg(feature = "serde")]
    use bitcoin_units::fee_rate::serde::OverflowError;
    use bitcoin_units::fee_rate::FeeRate;
}

#[test]
fn api_can_use_all_types_from_module_locktime_absolute() {
    #[cfg(feature = "encoding")]
    use bitcoin_units::locktime::absolute::error::LockTimeDecoderError as _;
    use bitcoin_units::locktime::absolute::error::{
        ConversionError as _, IncompatibleHeightError as _, IncompatibleTimeError as _,
        ParseHeightError as _, ParseTimeError as _,
    };
    use bitcoin_units::locktime::absolute::{
        ConversionError, IncompatibleHeightError, IncompatibleTimeError, ParseHeightError,
        ParseTimeError,
    };
    #[cfg(feature = "encoding")]
    use bitcoin_units::locktime::absolute::{
        LockTimeDecoder, LockTimeDecoderError, LockTimeEncoder,
    };
}

#[test]
fn api_can_use_all_types_from_module_locktime_relative() {
    use bitcoin_units::locktime::relative::error::{
        DisabledLockTimeError as _, InvalidHeightError as _, InvalidTimeError as _,
        TimeOverflowError as _,
    };
    use bitcoin_units::locktime::relative::{
        DisabledLockTimeError, InvalidHeightError, InvalidTimeError, NumberOf512Seconds,
        NumberOfBlocks, TimeOverflowError,
    };
}

#[test]
fn api_can_use_all_types_from_module_parse() {
    use bitcoin_units::parse_int::{ParseIntError, PrefixedHexError, UnprefixedHexError};
}

#[test]
fn api_can_use_all_types_from_module_pow() {
    use bitcoin_units::pow::CompactTarget;
    #[cfg(feature = "encoding")]
    use bitcoin_units::pow::{
        CompactTargetDecoder, CompactTargetDecoderError, CompactTargetEncoder,
    };
}

#[test]
fn api_can_use_all_types_from_module_time() {
    use bitcoin_units::time::BlockTime;
    #[cfg(feature = "encoding")]
    use bitcoin_units::time::{BlockTimeDecoder, BlockTimeDecoderError, BlockTimeEncoder};
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
    let debug = format!("{:?}", t.a.b);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.a.c);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.a.d);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.a.e);
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
    let debug = format!("{:?}", t.b.m);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.n);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.o);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.p);
    assert!(!debug.is_empty());
}

macro_rules! assert_format_matches {
    ($type:expr, $num:expr) => {
        let got = format!("{:o}", $type);
        let want = format!("{:o}", $num);
        assert_eq!(got, want);

        let got = format!("{:b}", $type);
        let want = format!("{:b}", $num);
        assert_eq!(got, want);

        let got = format!("{:x}", $type);
        let want = format!("{:x}", $num);
        assert_eq!(got, want);

        let got = format!("{:X}", $type);
        let want = format!("{:X}", $num);
        assert_eq!(got, want);
    };
}
#[test]
fn api_all_wrapper_types_fmt_as_inner() {
    // Confirm that for a set of pseudo-random numbers, formatting is equivalent to the inner value
    let mut rand_num = 10;
    for _ in 0..50 {
        assert_format_matches!(Amount::from_sat_u32(rand_num), rand_num);
        assert_format_matches!(BlockHeight::from(rand_num), rand_num);
        assert_format_matches!(BlockHeightInterval::from(rand_num), rand_num);
        assert_format_matches!(BlockMtp::from(rand_num), rand_num);
        assert_format_matches!(BlockMtpInterval::from(rand_num), rand_num);
        assert_format_matches!(BlockTime::from(rand_num), rand_num);
        assert_format_matches!(
            relative::NumberOfBlocks::from_height(rand_num as u16),
            rand_num as u16
        );
        assert_format_matches!(
            relative::NumberOf512Seconds::from_512_second_intervals(rand_num as u16),
            rand_num as u16
        );
        assert_format_matches!(Sequence::from_consensus(rand_num), rand_num);
        assert_format_matches!(Weight::from_wu(rand_num.into()), u64::from(rand_num));

        if let Ok(height) = absolute::Height::from_u32(rand_num) {
            assert_format_matches!(height, rand_num);
        }
        if let Ok(mtp) = absolute::MedianTimePast::from_u32(rand_num) {
            assert_format_matches!(mtp, rand_num);
        }
        if let Ok(ssat) = SignedAmount::from_sat(i64::from(rand_num)) {
            assert_format_matches!(ssat, rand_num);
            assert_format_matches!(-ssat, -i64::from(rand_num));
        }

        rand_num = rand_num.wrapping_mul(1039).wrapping_add(677);
    }
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
        g: Sequence::MAX,
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
        let a = Self { a: Enums::arbitrary(u)?, b: Structs::arbitrary(u)? };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Structs {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Self {
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
            m: pow::CompactTarget::from_consensus(u.int_in_range(0..=u32::MAX)?),
            n: sequence::Sequence::arbitrary(u)?,
            o: BlockTime::arbitrary(u)?,
            p: Weight::arbitrary(u)?,
        };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Enums {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Self {
            a: amount::Denomination::arbitrary(u)?,
            b: absolute::LockTime::arbitrary(u)?,
            c: relative::LockTime::arbitrary(u)?,
            d: result::MathOp::arbitrary(u)?,
            e: result::NumOpResult::<Amount>::arbitrary(u)?,
        };
        Ok(a)
    }
}
