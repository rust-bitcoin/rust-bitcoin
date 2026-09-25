// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin-units`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

// Intentionally put all features so that gates don't kill readability.
#![cfg(feature = "encoding")]
#![cfg(feature = "serde")]
#![cfg(feature = "arbitrary")]
#![cfg(feature = "std")]
#![allow(dead_code)]
#![allow(unused_imports)]

use arbitrary::{Arbitrary, Unstructured};
// These imports test "typical" usage by user code.
use bitcoin_units::locktime::{absolute, relative}; // Typical usage is `absolute::LockTime`.
use bitcoin_units::{
    amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight, Amount,
    BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate, NumOpResult,
    Sequence, SignedAmount, Weight,
};

include!("../../include/api_test_tooling.rs");

// Groups of units public types for testing semantics. Each type is listed once, in one group.
type_groups! {
    $ units;
    // The value types.
    group structs = [
        amount::Amount,
        amount::SignedAmount,
        block::BlockHeight,
        block::BlockHeightInterval,
        block::BlockMtp,
        block::BlockMtpInterval,
        fee_rate::FeeRate,
        locktime::absolute::Height,
        locktime::absolute::MedianTimePast,
        locktime::relative::NumberOf512Seconds,
        locktime::relative::NumberOfBlocks,
        pow::CompactTarget,
        pow::Target,
        pow::Work,
        sequence::Sequence,
        time::BlockTime,
        weight::Weight,
    ];
    // All public non-error enums.
    group enums = [
        amount::Denomination,
        locktime::absolute::LockTime,
        locktime::relative::LockTime,
        result::MathOp,
        result::NumOpResult<Amount>,
    ];
    // Formatting adapters.
    group adapters = [amount::Display];
    // Every error type, feature gated ones included.
    group errors = [
        amount::AmountDecoderError,
        amount::BadPositionError,
        amount::InvalidCharacterError,
        amount::MissingDenominationError,
        amount::MissingDigitsError,
        amount::OutOfRangeError,
        amount::ParseAmountError,
        amount::ParseDenominationError,
        amount::ParseError,
        amount::PossiblyConfusingDenominationError,
        amount::TooPreciseError,
        amount::UnknownDenominationError,
        block::BlockHeightDecoderError,
        block::TooBigForRelativeHeightError,
        fee_rate::serde::OverflowError,
        locktime::absolute::ConversionError,
        locktime::absolute::IncompatibleHeightError,
        locktime::absolute::IncompatibleTimeError,
        locktime::absolute::LockTimeDecoderError,
        locktime::absolute::ParseHeightError,
        locktime::absolute::ParseTimeError,
        locktime::relative::DisabledLockTimeError,
        locktime::relative::IncompatibleHeightError,
        locktime::relative::IncompatibleTimeError,
        locktime::relative::InvalidHeightError,
        locktime::relative::InvalidTimeError,
        locktime::relative::IsSatisfiedByError,
        locktime::relative::IsSatisfiedByHeightError,
        locktime::relative::IsSatisfiedByTimeError,
        locktime::relative::TimeOverflowError,
        parse_int::ParseIntError,
        parse_int::PrefixedHexError,
        parse_int::UnprefixedHexError,
        pow::CompactTargetDecoderError,
        pow::ParseTargetError,
        pow::ParseWorkError,
        result::NumOpError,
        sequence::SequenceDecoderError,
        time::BlockTimeDecoderError,
    ];
    // All public decoder types.
    group decoders = [
        amount::AmountDecoder,
        block::BlockHeightDecoder,
        locktime::absolute::LockTimeDecoder,
        pow::CompactTargetDecoder,
        sequence::SequenceDecoder,
        time::BlockTimeDecoder,
    ];
    // All public encoder types. The lifetime is a `PhantomData` marker, so `'static` probes work.
    group encoders = [
        amount::AmountEncoder<'static>,
        block::BlockHeightEncoder<'static>,
        locktime::absolute::LockTimeEncoder<'static>,
        pow::CompactTargetEncoder<'static>,
        sequence::SequenceEncoder<'static>,
        time::BlockTimeEncoder<'static>,
    ];
    // Every encoder and decoder.
    union codecs = decoders | encoders;
    // Every public type that is not an error, encoder or decoder.
    union public_types = structs | enums | adapters;
    // Every public type.
    union all = public_types | errors | codecs;
}

#[test]
fn clone_trait() {
    // C-COMMON-TRAITS: Every public type implements `Clone`.
    // REQUIRED BY DEPENDENCY: Copy, and the derives on `LockTime`, `NumOpResult` and errors.
    units!(all, assert_implements, Clone);
}

#[test]
fn copy_trait() {
    // C-COMMON-TRAITS: Every value type and enum is `Copy`.
    // POLICY: Value types use the standard derive set.
    // REQUIRED BY DEPENDENCY: `LockTime` derives `Copy` over its heights and times.
    units!(structs, assert_implements, Copy);
    units!(enums, assert_implements, Copy);

    // TODO: DO NOT IMPLEMENT
    // A formatting adapter is just for printing.
    units!(adapters, assert_does_not_implement, Copy);

    // POLICY: Errors do not derive `Copy` unless they have to.
    units!(
        errors,
        assert_does_not_implement,
        Copy,
        except [
            // REQUIRED BY DEPENDENCY: `NumOpResult` is `Copy` and holds it.
            result::NumOpError,
        ]
    );

    // FORBIDDEN BY DEPENDENCY: consensus_encoding codecs derive only `Debug, Clone`.
    units!(codecs, assert_does_not_implement, Copy);
}

#[test]
fn debug_trait() {
    // C-DEBUG, C-GOOD-ERR: Every public type implements `Debug`.
    // POLICY: Errors derive `Debug`, value types use the standard derive set.
    // REQUIRED BY DEPENDENCY: std::error::Error
    // REQUIRED BY DEPENDENCY: The derives on `relative::LockTime`, `NumOpResult` and errors.
    units!(all, assert_implements, Debug);
}

#[test]
fn default_trait() {
    // TODO: DO NOT IMPLEMENT
    // Do not assume a natural default exists for these.
    units!(
        structs,
        assert_does_not_implement,
        Default,
        except [
            // TODO: IMPLEMENT
            // Zero is an ok default for an amount.
            amount::Amount,
            amount::SignedAmount,
            // TODO: IMPLEMENT
            // Zero is an ok default for an interval.
            block::BlockHeightInterval,
            block::BlockMtpInterval,
            locktime::relative::NumberOf512Seconds,
            locktime::relative::NumberOfBlocks,
        ]
    );

    // TODO: DO NOT IMPLEMENT
    // Formatting adapter has nothing to default to.
    units!(adapters, assert_does_not_implement, Default);

    // TODO: DO NOT IMPLEMENT
    // No variant is a natural default.
    units!(enums, assert_does_not_implement, Default);

    // TODO: DO NOT IMPLEMENT
    // There is no default failure.
    units!(errors, assert_does_not_implement, Default);

    // P-DECODERS: Decoders have a default constructor.
    units!(decoders, assert_implements, Default);
    // FORBIDDEN BY DEPENDENCY: consensus_encoding encoders have no `Default`.
    units!(encoders, assert_does_not_implement, Default);
}

#[test]
fn display_trait() {
    // TODO: IMPLEMENT
    // Every value type, enum and formatting adapter prints.
    units!(
        public_types,
        assert_implements,
        Display,
        except [
            // TODO: DO NOT IMPLEMENT
            // There is no canonical unit. `to_sat_per_*` methods make it a caller's choice.
            fee_rate::FeeRate,
            // TODO: UNDECIDED
            result::NumOpResult<Amount>,
        ]
    );

    // C-GOOD-ERR: Every error type implements `Display`.
    // REQUIRED BY DEPENDENCY: std::error::Error
    units!(errors, assert_implements, Display);

    // TODO: DO NOT IMPLEMENT
    // Encoders and decoders return bytes and are not printed.
    units!(codecs, assert_does_not_implement, Display);
}

#[test]
fn partial_eq_trait() {
    // C-COMMON-TRAITS: Every value type and enum implements `PartialEq`.
    // POLICY: Value types use the standard derive set.
    // REQUIRED BY DEPENDENCY: Eq, PartialOrd, and the derives on `LockTime`.
    units!(
        public_types,
        assert_implements,
        PartialEq,
        except [
            // TODO: UNDECIDED
            amount::Display,
        ]
    );

    // POLICY: Every error type derives `PartialEq`.
    // REQUIRED BY DEPENDENCY: Eq, and the derives on `NumOpResult` and errors.
    units!(errors, assert_implements, PartialEq);

    // FORBIDDEN BY DEPENDENCY: consensus_encoding codecs derive only `Debug, Clone`.
    units!(codecs, assert_does_not_implement, PartialEq);
}

#[test]
fn eq_trait() {
    // C-COMMON-TRAITS: Every value type and enum implements `Eq`.
    // POLICY: Value types use the standard derive set.
    // REQUIRED BY DEPENDENCY: Ord, and the derives on `LockTime`.
    units!(
        public_types,
        assert_implements,
        Eq,
        except [
            // FORBIDDEN BY DEPENDENCY: PartialEq
            amount::Display,
        ]
    );

    // POLICY: Every error type derives `Eq`.
    // REQUIRED BY DEPENDENCY: Errors and `NumOpResult` derive `Eq` over inner errors.
    units!(errors, assert_implements, Eq);

    // FORBIDDEN BY DEPENDENCY: PartialEq
    units!(codecs, assert_does_not_implement, Eq);
}

#[test]
fn partial_ord_trait() {
    // C-COMMON-TRAITS: Every value type implements `PartialOrd`.
    // POLICY: Value types use the standard derive set.
    // REQUIRED BY DEPENDENCY: Ord
    units!(structs, assert_implements, PartialOrd);

    // FORBIDDEN BY DEPENDENCY: PartialEq
    units!(adapters, assert_does_not_implement, PartialOrd);

    // POLICY: Consider carefully before deriving, it bakes variant order into the public API.
    units!(enums, assert_does_not_implement, PartialOrd);

    // TODO: DO NOT IMPLEMENT
    // Errors are not ordered.
    units!(errors, assert_does_not_implement, PartialOrd);

    // FORBIDDEN BY DEPENDENCY: PartialEq
    units!(codecs, assert_does_not_implement, PartialOrd);
}

/// A struct that includes all public non-error enums.
struct Enums {
    a: amount::Denomination,
    b: absolute::LockTime,
    c: relative::LockTime,
    d: result::MathOp,
    e: result::NumOpResult<Amount>,
}

/// A struct that includes all public non-error structs.
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

/// A struct that includes all public non-error types.
struct Types {
    a: Enums,
    b: Structs,
}

/// A struct that includes all public non-error non-helper structs.
// C-COMMON-TRAITS excluding `Default` and `Display`. `Display` is done in `./str.rs`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// A struct that includes all public error types (excl. decode errors).
struct Errors {
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
    w: pow::CompactTargetDecoderError,
    x: result::NumOpError,
}

/// C-DEBUG-NONEMPTY: Tests that all public non-error types have non-empty Debug.
#[test]
fn c_debug_nonempty() {
    let debug = [
        format!("{:?}", amount::Denomination::Bitcoin),
        format!("{:?}", absolute::LockTime::Blocks(absolute::Height::MAX)),
        format!("{:?}", relative::LockTime::Blocks(relative::NumberOfBlocks::MAX)),
        format!("{:?}", result::MathOp::Add),
        format!("{:?}", result::NumOpResult::Valid(Amount::MAX)),
        format!("{:?}", Amount::MAX),
        format!("{:?}", Amount::MAX.display_in(amount::Denomination::Bitcoin)),
        format!("{:?}", SignedAmount::MAX),
        format!("{:?}", BlockHeight::MAX),
        format!("{:?}", BlockHeightInterval::MAX),
        format!("{:?}", BlockMtp::MAX),
        format!("{:?}", BlockMtpInterval::MAX),
        format!("{:?}", FeeRate::MAX),
        format!("{:?}", absolute::Height::MAX),
        format!("{:?}", absolute::MedianTimePast::MAX),
        format!("{:?}", relative::NumberOf512Seconds::MAX),
        format!("{:?}", relative::NumberOfBlocks::MAX),
        format!("{:?}", pow::CompactTarget::from_consensus(u32::MAX)),
        format!("{:?}", pow::Target::MAX),
        format!("{:?}", pow::Target::MAX.to_work()),
        format!("{:?}", Sequence::MAX),
        format!("{:?}", BlockTime::from_u32(u32::MAX)),
        format!("{:?}", Weight::MAX),
    ];
    for s in debug {
        assert!(!s.is_empty());
    }
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn c_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Types>();
    assert_sync::<Types>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
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
fn c_serde() {
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    assert_serde::<BlockHeight>();
    assert_serde::<BlockHeightInterval>();
    assert_serde::<BlockMtp>();
    assert_serde::<BlockMtpInterval>();
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
        Amount, AmountDecoder, AmountDecoderError, AmountEncoder, Denomination, Display,
        OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError, SignedAmount,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `amount::error` module.
#[test]
fn p_consistent_exports_amount_error() {
    use bitcoin_units::amount::error::{
        BadPositionError, InvalidCharacterError, MissingDenominationError, MissingDigitsError,
        OutOfRangeError, ParseAmountError, ParseDenominationError, ParseError,
        PossiblyConfusingDenominationError, TooPreciseError, UnknownDenominationError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `block` module.
#[test]
fn p_consistent_exports_block() {
    use bitcoin_units::block::{
        BlockHeight, BlockHeightDecoder, BlockHeightDecoderError, BlockHeightEncoder,
        BlockHeightInterval, BlockMtp, BlockMtpInterval, TooBigForRelativeHeightError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `sequence` module.
#[test]
fn p_consistent_exports_sequence() {
    use bitcoin_units::sequence::{
        Sequence, SequenceDecoder, SequenceDecoderError, SequenceEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `fee_rate` module.
#[test]
fn p_consistent_exports_fee_rate() {
    use bitcoin_units::fee_rate::serde::OverflowError;
    use bitcoin_units::fee_rate::FeeRate;
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::absolute` module.
#[test]
fn p_consistent_exports_locktime_absolute() {
    use bitcoin_units::locktime::absolute::error::{
        ConversionError as _, IncompatibleHeightError as _, IncompatibleTimeError as _,
        LockTimeDecoderError as _, ParseHeightError as _, ParseTimeError as _,
    };
    use bitcoin_units::locktime::absolute::{
        ConversionError, IncompatibleHeightError, IncompatibleTimeError, LockTimeDecoder,
        LockTimeDecoderError, LockTimeEncoder, ParseHeightError, ParseTimeError,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `locktime::relative` module.
#[test]
fn p_consistent_exports_locktime_relative() {
    use bitcoin_units::locktime::relative::error::{
        DisabledLockTimeError as _, InvalidHeightError as _, InvalidTimeError as _,
        IsSatisfiedByError as _, IsSatisfiedByHeightError as _, IsSatisfiedByTimeError as _,
        TimeOverflowError as _,
    };
    use bitcoin_units::locktime::relative::{
        DisabledLockTimeError, InvalidHeightError, InvalidTimeError, IsSatisfiedByError,
        IsSatisfiedByHeightError, IsSatisfiedByTimeError, NumberOf512Seconds, NumberOfBlocks,
        TimeOverflowError,
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
    use bitcoin_units::pow::{
        CompactTarget, CompactTargetDecoder, CompactTargetDecoderError, CompactTargetEncoder,
        ParseTargetError, ParseWorkError, Target, Work,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `time` module.
#[test]
fn p_consistent_exports_time() {
    use bitcoin_units::time::{
        BlockTime, BlockTimeDecoder, BlockTimeDecoderError, BlockTimeEncoder,
    };
}

/// P-CONSISTENT-EXPORTS: Tests that all types can be imported from the `weight` module.
#[test]
fn p_consistent_exports_weight() {
    use bitcoin_units::weight::Weight;
}

/// P-DEFAULT-CHANGE: Tests regression for Default implementation values.
#[test]
fn p_default_change() {
    assert_eq!(Amount::default(), Amount::ZERO);
    assert_eq!(SignedAmount::default(), SignedAmount::ZERO);
    assert_eq!(BlockHeightInterval::default(), BlockHeightInterval::ZERO);
    assert_eq!(BlockMtpInterval::default(), BlockMtpInterval::ZERO);
    assert_eq!(relative::NumberOf512Seconds::default(), relative::NumberOf512Seconds::ZERO);
    assert_eq!(relative::NumberOfBlocks::default(), relative::NumberOfBlocks::ZERO);
}

/// P-DECODERS: Tests that decoders implement a constructor method.
#[test]
fn p_decoders_implement_new() {
    let _ = amount::AmountDecoder::new();
    let _ = block::BlockHeightDecoder::new();
    let _ = locktime::absolute::LockTimeDecoder::new();
    let _ = pow::CompactTargetDecoder::new();
    let _ = sequence::SequenceDecoder::new();
    let _ = time::BlockTimeDecoder::new();
}

impl<'a> Arbitrary<'a> for Types {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Self { a: Enums::arbitrary(u)?, b: Structs::arbitrary(u)? };
        Ok(a)
    }
}

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
