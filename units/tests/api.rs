// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin-units`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

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
/// C-COMMON-TRAITS: `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`
// None of these implement `PartialOrd` or `Ord`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Enums {
    a: amount::Denomination,
    b: absolute::LockTime,
    c: relative::LockTime,
    d: result::MathOp,
    e: result::NumOpResult<Amount>,
}

/// An enum that includes all public non-error enums that implement `Hash`.
/// C-COMMON-TRAITS: `Hash`
#[derive(Hash)]
struct EnumsHash {
    a: amount::Denomination,
    b: absolute::LockTime,
    c: relative::LockTime,
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
/// C-COMMON-TRAITS: `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
// Does not include encoders, decoders, or `amount::Display`.
struct Structs {
    // Full path to show alphabetic sort order.
    a: amount::Amount,
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

/// A struct that includes all public error types (excl. decode errors).
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: amount::ParseError,
    b: amount::ParseAmountError,
    c: amount::OutOfRangeError,
    d: amount::TooPreciseError,
    e: amount::InputTooLargeError,
    f: amount::MissingDigitsError,
    g: amount::InvalidCharacterError,
    h: amount::BadPositionError,
    i: amount::MissingDenominationError,
    j: amount::UnknownDenominationError,
    k: amount::PossiblyConfusingDenominationError,
    l: amount::AmountDecoderError,
    m: block::TooBigForRelativeHeightError,
    n:block::BlockHeightDecoderError,
    #[cfg(feature = "serde")]
    o: fee_rate::serde::OverflowError,
    p: locktime::absolute::LockTimeDecoderError,
    q: locktime::absolute::IncompatibleHeightError,
    r: locktime::absolute::IncompatibleTimeError,
    s: locktime::absolute::ParseHeightError,
    t: locktime::absolute::ParseTimeError,
    u: locktime::absolute::ConversionError,
    v: locktime::relative::DisabledLockTimeError,
    w: locktime::relative::IncompatibleHeightError,
    x: locktime::relative::IncompatibleTimeError,
    y: locktime::relative::TimeOverflowError,
    z: locktime::relative::InvalidHeightError,
    aa: locktime::relative::InvalidTimeError,
    ab: parse_int::ParseIntError,
    ac: parse_int::PrefixedHexError,
    ad: parse_int::UnprefixedHexError,
    #[cfg(feature = "encoding")]
    ae: pow::CompactTargetDecoderError,
    af: pow::ParseWorkError,
    ag: pow::ParseTargetError,
    ah: result::NumOpError,
    ai: sequence::SequenceDecoderError,
    aj: time::BlockTimeDecoderError,
}

/// A struct that includes all public decoder types.
#[derive(Default)] // All decoders implement `Default` (P-DECODERS).
#[cfg(feature = "encoding")]
struct Decoders {
    a: amount::AmountDecoder,
    b: block::BlockHeightDecoder,
    c: locktime::absolute::LockTimeDecoder,
    d: pow::CompactTargetDecoder,
    e: sequence::SequenceDecoder,
    f: time::BlockTimeDecoder,
}

/// A struct that includes all public decoder error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
#[cfg(feature = "encoding")]
struct DecoderErrors {
    a: amount::error::AmountDecoderError,
    b: block::BlockHeightDecoderError,
    c: locktime::absolute::LockTimeDecoderError,
    d: pow::CompactTargetDecoderError,
    e: sequence::SequenceDecoderError,
    f: time::BlockTimeDecoderError,
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn all_types_implement_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<Enums>();
    is_send_sync::<Errors>();
    is_send_sync::<Structs>();
}

/// C-DEBUG-NONEMPTY: Tests that all public non-error types have non-empty Debug.
#[test]
fn c_debug_nonempty() {
    let t = Types::new();
    // TODO: Test error types.
    // let errors = Errors::new();

    assert!(!format!("{:?}", t.a.a).is_empty());
    assert!(!format!("{:?}", t.a.b).is_empty());
    assert!(!format!("{:?}", t.a.c).is_empty());
    assert!(!format!("{:?}", t.a.d).is_empty());
    assert!(!format!("{:?}", t.a.e).is_empty());

    assert!(!format!("{:?}", t.b.a).is_empty());
    assert!(!format!("{:?}", t.b.c).is_empty());
    assert!(!format!("{:?}", t.b.d).is_empty());
    assert!(!format!("{:?}", t.b.e).is_empty());
    assert!(!format!("{:?}", t.b.f).is_empty());
    assert!(!format!("{:?}", t.b.g).is_empty());
    assert!(!format!("{:?}", t.b.h).is_empty());
    assert!(!format!("{:?}", t.b.i).is_empty());
    assert!(!format!("{:?}", t.b.j).is_empty());
    assert!(!format!("{:?}", t.b.k).is_empty());
    assert!(!format!("{:?}", t.b.l).is_empty());
    assert!(!format!("{:?}", t.b.m).is_empty());
    assert!(!format!("{:?}", t.b.n).is_empty());
    assert!(!format!("{:?}", t.b.o).is_empty());
    assert!(!format!("{:?}", t.b.p).is_empty());
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn c_good_err_display() {
    fn assert_display<T: core::fmt::Display>() {}

    assert_display::<amount::ParseError>();
    assert_display::<amount::ParseAmountError>();
    assert_display::<amount::OutOfRangeError>();
    assert_display::<amount::TooPreciseError>();
    assert_display::<amount::InputTooLargeError>();
    assert_display::<amount::MissingDigitsError>();
    assert_display::<amount::InvalidCharacterError>();
    assert_display::<amount::BadPositionError>();
    assert_display::<amount::MissingDenominationError>();
    assert_display::<amount::UnknownDenominationError>();
    assert_display::<amount::PossiblyConfusingDenominationError>();
    assert_display::<amount::AmountDecoderError>();
    assert_display::<block::TooBigForRelativeHeightError>();
    assert_display::<block::BlockHeightDecoderError>();
    #[cfg(feature = "serde")]
    assert_display::<fee_rate::serde::OverflowError>();
    assert_display::<locktime::absolute::LockTimeDecoderError>();
    assert_display::<locktime::absolute::IncompatibleHeightError>();
    assert_display::<locktime::absolute::IncompatibleTimeError>();
    assert_display::<locktime::absolute::ParseHeightError>();
    assert_display::<locktime::absolute::ParseTimeError>();
    assert_display::<locktime::absolute::ConversionError>();
    assert_display::<locktime::relative::DisabledLockTimeError>();
    assert_display::<locktime::relative::IncompatibleHeightError>();
    assert_display::<locktime::relative::IncompatibleTimeError>();
    assert_display::<locktime::relative::TimeOverflowError>();
    assert_display::<locktime::relative::InvalidHeightError>();
    assert_display::<locktime::relative::InvalidTimeError>();
    assert_display::<parse_int::ParseIntError>();
    assert_display::<parse_int::PrefixedHexError>();
    assert_display::<parse_int::UnprefixedHexError>();
    #[cfg(feature = "encoding")]
    assert_display::<pow::CompactTargetDecoderError>();
    assert_display::<pow::ParseWorkError>();
    assert_display::<pow::ParseTargetError>();
    assert_display::<result::NumOpError>();
    assert_display::<sequence::SequenceDecoderError>();
    assert_display::<time::BlockTimeDecoderError>();
}

/// C-OBJECT: Tests that traits are object-safe where appropriate.
#[test]
fn c_object() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        // These traits are explicitly not dyn compatible.
        // b: Box<dyn amount::serde::SerdeAmount>,
        // c: Box<dyn amount::serde::SerdeAmountForOpt>,
        // d: Box<dyn parse::Integer>, // Because of core::num::ParseIntError
    }
}

/// C-SERDE: Tests that serde traits are implemented where expected.
#[test]
#[cfg(feature = "serde")]
fn c_serde() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    // assert_serde::<amount::Denomination>();
    assert_serde::<absolute::LockTime>();
    assert_serde::<relative::LockTime>();
    // assert_serde::<result::MathOp>();
    // assert_serde::<result::NumOpResult<Amount>>();
    assert_serde::<BlockHeight>();
    assert_serde::<BlockHeightInterval>();
    assert_serde::<BlockMtp>();
    assert_serde::<BlockMtpInterval>();
    assert_serde::<locktime::absolute::Height>();
    assert_serde::<locktime::absolute::MedianTimePast>();
    assert_serde::<locktime::relative::NumberOf512Seconds>();
    assert_serde::<locktime::relative::NumberOfBlocks>();
    assert_serde::<pow::CompactTarget>();
    assert_serde::<BlockTime>();
    assert_serde::<Weight>();
    assert_serde::<Sequence>();
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

/// C-NEWTYPE: Newtype wrappers format identically to their inner types, maintaining transparency.
#[test]
fn c_newtype_transparent_format() {
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
            relative::NumberOfBlocks::from_count(rand_num as u16),
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

/// P-CONSISTENT-EXPORTS: Tests that modules are exported from the crate root.
#[test]
fn p_consistent_exports_crate_modules() {
    use bitcoin_units::{
        amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that type aliases are exported from the crate root.
#[test]
fn p_consistent_exports_crate_types() {
    use bitcoin_units::{
        Amount, BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime,
        CompactTarget, FeeRate, NumOpResult, Sequence, SignedAmount, Weight,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `amount` module.
#[test]
fn p_consistent_exports_amount() {
    use bitcoin_units::amount::{
        Amount, Denomination, Display, OutOfRangeError, ParseAmountError, ParseDenominationError,
        ParseError, SignedAmount,
    };
    #[cfg(feature = "encoding")]
    use bitcoin_units::amount::{AmountDecoder, AmountDecoderError, AmountEncoder};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `amount::error` module.
#[test]
fn p_consistent_exports_amount_error() {
    use bitcoin_units::amount::error::{
        BadPositionError, InputTooLargeError, InvalidCharacterError, MissingDenominationError,
        MissingDigitsError, OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `block` module.
#[test]
fn p_consistent_exports_block() {
    use bitcoin_units::block::{
        BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, TooBigForRelativeHeightError,
    };
    #[cfg(feature = "encoding")]
    use bitcoin_units::block::{BlockHeightDecoder, BlockHeightDecoderError, BlockHeightEncoder};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `sequence` module.
#[test]
fn p_consistent_exports_sequence() {
    use bitcoin_units::sequence::Sequence;
    #[cfg(feature = "encoding")]
    use bitcoin_units::sequence::{SequenceDecoder, SequenceDecoderError, SequenceEncoder};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `fee_rate` module.
#[test]
fn p_consistent_exports_fee_rate() {
    #[cfg(feature = "serde")]
    use bitcoin_units::fee_rate::serde::OverflowError;
    use bitcoin_units::fee_rate::FeeRate;
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::absolute` module.
#[test]
fn p_consistent_exports_locktime_absolute() {
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

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::relative` module.
#[test]
fn p_consistent_exports_locktime_relative() {
    use bitcoin_units::locktime::relative::error::{
        DisabledLockTimeError as _, InvalidHeightError as _, InvalidTimeError as _,
        TimeOverflowError as _,
    };
    use bitcoin_units::locktime::relative::{
        DisabledLockTimeError, InvalidHeightError, InvalidTimeError, NumberOf512Seconds,
        NumberOfBlocks, TimeOverflowError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `parse_int` module.
#[test]
fn p_consistent_exports_parse() {
    use bitcoin_units::parse_int::{ParseIntError, PrefixedHexError, UnprefixedHexError};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `result` module.
#[test]
fn p_consistent_exports_result() {
    use bitcoin_units::result::{MathOp, NumOpError, NumOpResult};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `pow` module.
#[test]
fn p_consistent_exports_pow() {
    use bitcoin_units::pow::CompactTarget;
    #[cfg(feature = "encoding")]
    use bitcoin_units::pow::{
        CompactTargetDecoder, CompactTargetDecoderError, CompactTargetEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `time` module.
#[test]
fn p_consistent_exports_time() {
    use bitcoin_units::time::BlockTime;
    #[cfg(feature = "encoding")]
    use bitcoin_units::time::{BlockTimeDecoder, BlockTimeDecoderError, BlockTimeEncoder};
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `weight` module.
#[test]
fn p_consistent_exports_weight() {
    use bitcoin_units::weight::Weight;
}

/// P-DEFAULT-CHANGE: Tests regression for Default implementation values.
#[test]
fn p_default_change() {
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

/// P-DECODERS: Tests that decoders implement a constructor method.
#[test]
#[cfg(feature = "encoding")]
fn p_decoders_implement_new() {
    let _ = amount::AmountDecoder::new();
    let _ = block::BlockHeightDecoder::new();
    let _ = locktime::absolute::LockTimeDecoder::new();
    let _ = pow::CompactTargetDecoder::new();
    let _ = sequence::SequenceDecoder::new();
    let _ = time::BlockTimeDecoder::new();
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
