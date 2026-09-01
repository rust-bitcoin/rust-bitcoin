// SPDX-License-Identifier: CC0-1.0

//! Test the API surface (not functionality) of `bitcoin-units`.
//!
//! See [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/about.html) and the [rust-bitcoin policies](../../docs/policy.md).

#![allow(dead_code)]
#![allow(unused_imports)]

// These imports test "typical" usage by user code.
use bitcoin_units::locktime::{absolute, relative}; // Typical usage is `absolute::LockTime`.
use bitcoin_units::{
    amount, block, fee_rate, locktime, parse_int, pow, result, sequence, time, weight, Amount,
    BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate, NumOpResult,
    Sequence, SignedAmount, Weight,
};

/// Detects whether a type implements or not a trait.
///
/// Both traits below declare `is_implemented`. Calling through `&&Probe` tries `&Probe` first, so
/// the `Specialized` impl answers first if the target trait is implemented, otherwise `Fallback` answers.
/// The traits that tests can check are listed in `probed_traits!`.
///
/// Based on [dtolnay's Autoref-based stable specialization](https://github.com/dtolnay/case-studies/blob/master/autoref-specialization/README.md).
mod trait_probe {
    use core::marker::PhantomData;

    pub struct Probe<T, M>(pub PhantomData<(T, M)>);

    pub trait Fallback {
        fn is_implemented(&self) -> bool { false }
    }

    impl<T, M> Fallback for Probe<T, M> {}

    pub trait Specialized {
        fn is_implemented(&self) -> bool;
    }

    /// Gives each trait a marker struct and an impl that detects it.
    macro_rules! probed_traits {
        ($($(#[$attr:meta])* $trait_name:ident => ($($bound:tt)+)),+ $(,)?) => {
            pub mod markers {
                $($(#[$attr])* pub struct $trait_name;)+
            }

            $($(#[$attr])* impl<T: $($bound)+> Specialized for &Probe<T, markers::$trait_name> {
                fn is_implemented(&self) -> bool { true }
            })+
        };
    }

    // Add a trait here to make it usable in the assertions
    probed_traits! {
        #[cfg(feature = "arbitrary")]
        Arbitrary => (for<'a> ::arbitrary::Arbitrary<'a>),
        Clone => (::core::clone::Clone),
        Copy => (::core::marker::Copy),
        Debug => (::core::fmt::Debug),
        Default => (::core::default::Default),
        #[cfg(feature = "serde")]
        Deserialize => (for<'de> ::serde::Deserialize<'de>),
        Display => (::core::fmt::Display),
        Eq => (::core::cmp::Eq),
        Hash => (::core::hash::Hash),
        Ord => (::core::cmp::Ord),
        PartialEq => (::core::cmp::PartialEq),
        PartialOrd => (::core::cmp::PartialOrd),
        Send => (::core::marker::Send),
        #[cfg(feature = "serde")]
        Serialize => (::serde::Serialize),
        Sync => (::core::marker::Sync),
    }
}

/// Asserts each of `$traits` is implemented for `$type`, or is not, according to `$want`.
macro_rules! assert_trait_impls {
    ($type:ty, [$($trait_name:ident),+ $(,)?], $want:expr) => {{
        #[allow(unused_imports)]
        use trait_probe::{Fallback as _, Specialized as _};
        $({
            let probe = trait_probe::Probe::<$type, trait_probe::markers::$trait_name>(
                core::marker::PhantomData,
            );
            // Call through `&&probe` so `&Probe` answers first IF the impl exists.
            let got = (&&probe).is_implemented();
            assert!(
                got == $want,
                "{} implements {}: got {}, want {}",
                stringify!($type),
                stringify!($trait_name),
                got,
                $want
            );
        })+
    }};
}

/// Asserts that each type implements every one of `$traits`.
macro_rules! assert_implements {
    ([$($type:ty),+ $(,)?], $traits:tt) => {
        $(assert_trait_impls!($type, $traits, true);)+
    };
    ($type:ty, $traits:tt) => {
        assert_trait_impls!($type, $traits, true)
    };
}

/// Asserts that each type implements none of `$traits`.
macro_rules! assert_does_not_implement {
    ([$($type:ty),+ $(,)?], $traits:tt) => {
        $(assert_trait_impls!($type, $traits, false);)+
    };
    ($type:ty, $traits:tt) => {
        assert_trait_impls!($type, $traits, false)
    };
}

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

/// Tests all public non-error non-helper structs implement the common traits.
// C-COMMON-TRAITS excluding `Default` and `Display`. `Display` is done in `./str.rs`.
#[test]
fn c_common_traits() {
    // Full path to show alphabetic sort order.
    assert_implements!(
        [
            amount::Amount,
            // amount::Display,
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
            time::BlockTime,
            weight::Weight,
        ],
        [Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash]
    );
}

/// Tests the traits implemented, and deliberately not implemented, by the public enums.
#[test]
fn c_common_traits_enums() {
    assert_implements!(
        [
            amount::Denomination,
            absolute::LockTime,
            relative::LockTime,
            result::MathOp,
            result::NumOpResult<Amount>,
        ],
        [Copy, Clone, Debug, PartialEq, Eq]
    );
    assert_implements!([amount::Denomination, absolute::LockTime, relative::LockTime], [Hash]);

    // None of these implement `PartialOrd` or `Ord`.
    assert_does_not_implement!(
        [
            amount::Denomination,
            absolute::LockTime,
            relative::LockTime,
            result::MathOp,
            result::NumOpResult<Amount>,
        ],
        [PartialOrd, Ord]
    );
    assert_does_not_implement!([result::MathOp, result::NumOpResult<Amount>], [Hash]);
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

/// Tests all public error types (excl. decode errors) implement the common traits.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[test]
fn c_common_traits_errors() {
    // All public types implement Debug (C-DEBUG).
    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_implements!(
        [
            amount::error::InputTooLargeError,
            amount::error::InvalidCharacterError,
            amount::error::MissingDenominationError,
            amount::error::MissingDigitsError,
            amount::error::OutOfRangeError,
            amount::error::ParseAmountError,
            amount::error::ParseDenominationError,
            amount::error::ParseError,
            amount::error::PossiblyConfusingDenominationError,
            amount::error::TooPreciseError,
            amount::error::UnknownDenominationError,
            block::TooBigForRelativeHeightError,
            locktime::absolute::ConversionError,
            locktime::absolute::ParseHeightError,
            locktime::absolute::ParseTimeError,
            locktime::relative::InvalidHeightError,
            locktime::relative::InvalidTimeError,
            locktime::relative::TimeOverflowError,
            parse_int::ParseIntError,
            parse_int::PrefixedHexError,
            parse_int::UnprefixedHexError,
            result::NumOpError,
        ],
        [Debug, Clone, PartialEq, Eq, Send, Sync]
    );
    #[cfg(feature = "serde")]
    assert_implements!(fee_rate::serde::OverflowError, [Debug, Clone, PartialEq, Eq, Send, Sync]);
    #[cfg(feature = "encoding")]
    assert_implements!(pow::CompactTargetDecoderError, [Debug, Clone, PartialEq, Eq, Send, Sync]);
}

/// Tests all public decoder types implement `Default`.
#[test]
#[cfg(feature = "encoding")]
fn p_decoders_implement_default() {
    // All decoders implement `Default` (P-DECODERS).
    assert_implements!(
        [
            amount::AmountDecoder,
            block::BlockHeightDecoder,
            locktime::absolute::LockTimeDecoder,
            pow::CompactTargetDecoder,
            sequence::SequenceDecoder,
            time::BlockTimeDecoder,
        ],
        [Default]
    );
}

/// Tests all public decoder error types implement the common traits.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[test]
#[cfg(feature = "encoding")]
fn c_common_traits_decoder_errors() {
    // All public types implement Debug (C-DEBUG).
    assert_implements!(
        [
            amount::error::AmountDecoderError,
            block::BlockHeightDecoderError,
            locktime::absolute::LockTimeDecoderError,
            sequence::SequenceDecoderError,
            time::BlockTimeDecoderError,
        ],
        [Debug, Clone, PartialEq, Eq]
    );
}

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn all_types_implement_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<Enums>();
    // Error types are covered in `c_common_traits_errors`.
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

/// C-SEND-SYNC: Tests that all public types implement `Send` + `Sync`.
#[test]
fn c_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Types>();
    assert_sync::<Types>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    // See `c_common_traits_errors`.
}

/// C-GOOD-ERR: Tests that all public error types implement Display.
#[test]
fn c_good_err_display() {
    assert_implements!(
        [
            amount::ParseError,
            amount::ParseAmountError,
            amount::OutOfRangeError,
            amount::TooPreciseError,
            amount::InputTooLargeError,
            amount::MissingDigitsError,
            amount::InvalidCharacterError,
            amount::BadPositionError,
            amount::MissingDenominationError,
            amount::UnknownDenominationError,
            amount::PossiblyConfusingDenominationError,
            amount::AmountDecoderError,
            block::TooBigForRelativeHeightError,
            block::BlockHeightDecoderError,
            locktime::absolute::LockTimeDecoderError,
            locktime::absolute::IncompatibleHeightError,
            locktime::absolute::IncompatibleTimeError,
            locktime::absolute::ParseHeightError,
            locktime::absolute::ParseTimeError,
            locktime::absolute::ConversionError,
            locktime::relative::DisabledLockTimeError,
            locktime::relative::IncompatibleHeightError,
            locktime::relative::IncompatibleTimeError,
            locktime::relative::TimeOverflowError,
            locktime::relative::InvalidHeightError,
            locktime::relative::InvalidTimeError,
            parse_int::ParseIntError,
            parse_int::PrefixedHexError,
            parse_int::UnprefixedHexError,
            pow::ParseWorkError,
            pow::ParseTargetError,
            result::NumOpError,
            sequence::SequenceDecoderError,
            time::BlockTimeDecoderError,
        ],
        [Display]
    );
    #[cfg(feature = "serde")]
    assert_implements!(fee_rate::serde::OverflowError, [Display]);
    #[cfg(feature = "encoding")]
    assert_implements!(pow::CompactTargetDecoderError, [Display]);
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
    assert_implements!(
        [
            absolute::LockTime,
            relative::LockTime,
            BlockHeight,
            BlockHeightInterval,
            BlockMtp,
            BlockMtpInterval,
            locktime::absolute::Height,
            locktime::absolute::MedianTimePast,
            locktime::relative::NumberOf512Seconds,
            locktime::relative::NumberOfBlocks,
            pow::CompactTarget,
            BlockTime,
            Weight,
            Sequence,
        ],
        [Serialize, Deserialize]
    );

    assert_does_not_implement!(
        [amount::Denomination, result::MathOp, result::NumOpResult<Amount>],
        [Serialize, Deserialize]
    );
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

#[test]
#[cfg(feature = "arbitrary")]
fn p_arbitrary() {
    assert_implements!(
        [
            amount::Denomination,
            absolute::LockTime,
            relative::LockTime,
            result::MathOp,
            result::NumOpResult<Amount>,
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
            sequence::Sequence,
            time::BlockTime,
            weight::Weight,
        ],
        [Arbitrary]
    );
}
