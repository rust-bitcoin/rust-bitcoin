// SPDX-License-Identifier: CC0-1.0

//! An unsigned bitcoin amount.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::str::FromStr;
use core::{default, fmt};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::const_casts;
use NumOpResult as R;

#[cfg(feature = "encoding")]
use super::error::AmountDecoderError;
use super::error::{ParseAmountErrorInner, ParseErrorInner};
use super::{
    parse_signed_to_satoshi, split_amount_and_denomination, Denomination, Display, DisplayStyle,
    OutOfRangeError, ParseAmountError, ParseError, SignedAmount,
};
use crate::result::{MathOp, NumOpError as E, NumOpResult};
use crate::{FeeRate, Weight};

mod encapsulate {
    use super::OutOfRangeError;

    /// An amount.
    ///
    /// The [`Amount`] type can be used to express Bitcoin amounts that support arithmetic and
    /// conversion to various denominations. The [`Amount`] type does not implement [`serde`] traits
    /// but we do provide modules for serializing as satoshis or bitcoin.
    ///
    /// **Warning!**
    ///
    /// This type implements several arithmetic operations from [`core::ops`].
    /// To prevent errors due to an overflow when using these operations,
    /// it is advised to instead use the checked arithmetic methods whose names
    /// start with `checked_`. The operations from [`core::ops`] that [`Amount`]
    /// implements will panic when an overflow occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "serde")] {
    /// use serde::{Serialize, Deserialize};
    /// use bitcoin_units::Amount;
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct Foo {
    ///     // If you are using `rust-bitcoin` then `bitcoin::amount::serde::as_sat` also works.
    ///     #[serde(with = "bitcoin_units::amount::serde::as_sat")]  // Also `serde::as_btc`.
    ///     amount: Amount,
    /// }
    /// # }
    /// ```
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Amount(u64);

    impl Amount {
        /// The maximum value of an amount.
        pub const MAX: Self = Self(21_000_000 * 100_000_000);
        /// The minimum value of an amount.
        pub const MIN: Self = Self(0);

        /// Gets the number of satoshis in this [`Amount`].
        ///
        /// # Examples
        ///
        /// ```
        /// # use bitcoin_units::Amount;
        /// assert_eq!(Amount::ONE_BTC.to_sat(), 100_000_000);
        /// ```
        pub const fn to_sat(self) -> u64 { self.0 }

        /// Constructs a new [`Amount`] from the given number of satoshis.
        ///
        /// # Errors
        ///
        /// If `satoshi` is outside of valid range (greater than [`Self::MAX_MONEY`]).
        ///
        /// # Examples
        ///
        /// ```
        /// # use bitcoin_units::{amount, Amount};
        /// # let sat = 100_000;
        /// let amount = Amount::from_sat(sat)?;
        /// assert_eq!(amount.to_sat(), sat);
        /// # Ok::<_, amount::OutOfRangeError>(())
        /// ```
        pub const fn from_sat(satoshi: u64) -> Result<Self, OutOfRangeError> {
            if satoshi > Self::MAX_MONEY.to_sat() {
                Err(OutOfRangeError { is_signed: false, is_greater_than_max: true })
            } else {
                Ok(Self(satoshi))
            }
        }
    }
}
#[doc(inline)]
pub use encapsulate::Amount;

impl Amount {
    /// The zero amount.
    pub const ZERO: Self = Self::from_sat_u32(0);
    /// Exactly one satoshi.
    pub const ONE_SAT: Self = Self::from_sat_u32(1);
    /// Exactly one bitcoin.
    pub const ONE_BTC: Self = Self::from_btc_u16(1);
    /// Exactly fifty bitcoin.
    pub const FIFTY_BTC: Self = Self::from_btc_u16(50);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: Self = Self::MAX;
    /// The number of bytes that an amount contributes to the size of a transaction.
    pub const SIZE: usize = 8; // Serialized length of a u64.

    /// Constructs a new [`Amount`] with satoshi precision and the given number of satoshis.
    ///
    /// Accepts an `u32` which is guaranteed to be in range for the type, but which can only
    /// represent roughly 0 to 42.95 BTC.
    #[allow(clippy::missing_panics_doc)]
    pub const fn from_sat_u32(satoshi: u32) -> Self {
        let sats = const_casts::u32_to_u64(satoshi);
        match Self::from_sat(sats) {
            Ok(amount) => amount,
            Err(_) =>
                panic!("unreachable - u32 input [0 to 4,294,967,295 satoshis] is within range"),
        }
    }

    /// Converts from a value expressing a decimal number of bitcoin to an [`Amount`].
    ///
    /// # Errors
    ///
    /// If the amount is too precise, negative, or greater than 21,000,000.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{amount, Amount};
    /// let amount = Amount::from_btc(0.01)?;
    /// assert_eq!(amount.to_sat(), 1_000_000);
    /// # Ok::<_, amount::ParseAmountError>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn from_btc(btc: f64) -> Result<Self, ParseAmountError> {
        Self::from_float_in(btc, Denomination::Bitcoin)
    }

    /// Converts from a value expressing a whole number of bitcoin to an [`Amount`].
    #[allow(clippy::missing_panics_doc)]
    pub fn from_int_btc<T: Into<u16>>(whole_bitcoin: T) -> Self {
        Self::from_btc_u16(whole_bitcoin.into())
    }

    /// Converts from a value expressing a whole number of bitcoin to an [`Amount`]
    /// in const context.
    #[allow(clippy::missing_panics_doc)]
    pub const fn from_btc_u16(whole_bitcoin: u16) -> Self {
        let btc = const_casts::u16_to_u64(whole_bitcoin);
        let sats = btc * 100_000_000;

        match Self::from_sat(sats) {
            Ok(amount) => amount,
            Err(_) => panic!("unreachable - 65,535 BTC is within range"),
        }
    }

    /// Parses a decimal string as a value in the given [`Denomination`].
    ///
    /// Note: This only parses the value string. If you want to parse a string
    /// containing the value with denomination, use [`FromStr`].
    ///
    /// # Errors
    ///
    /// If the amount is too precise, negative, or greater than 21,000,000.
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Self, ParseAmountError> {
        let (is_neg, amount) =
            parse_signed_to_satoshi(s, denom).map_err(|error| error.convert(false))?;
        if is_neg {
            return Err(ParseAmountError(ParseAmountErrorInner::OutOfRange(
                OutOfRangeError::negative(),
            )));
        }
        Self::try_from(amount).map_err(|e| ParseAmountError(ParseAmountErrorInner::OutOfRange(e)))
    }

    /// Parses amounts with denomination suffix as produced by [`Self::to_string_with_denomination`]
    /// or with [`fmt::Display`].
    ///
    /// If you want to parse only the amount without the denomination, use [`Self::from_str_in`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{amount, Amount};
    /// let amount = Amount::from_str_with_denomination("0.1 BTC")?;
    /// assert_eq!(amount, Amount::from_sat(10_000_000)?);
    /// # Ok::<_, amount::ParseError>(())
    /// ```
    pub fn from_str_with_denomination(s: &str) -> Result<Self, ParseError> {
        let (amt, denom) = split_amount_and_denomination(s)?;
        Self::from_str_in(amt, denom).map_err(Into::into)
    }

    /// Expresses this [`Amount`] as a floating-point value in the given [`Denomination`].
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{self, Amount, Denomination};
    /// let amount = Amount::from_sat(100_000)?;
    /// assert_eq!(amount.to_float_in(Denomination::Bitcoin), 0.001);
    /// # Ok::<_, amount::ParseError>(())
    /// ```
    #[cfg(feature = "alloc")]
    #[allow(clippy::missing_panics_doc)]
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        self.to_string_in(denom).parse::<f64>().unwrap()
    }

    /// Expresses this [`Amount`] as a floating-point value in Bitcoin.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{self, Amount, Denomination};
    /// let amount = Amount::from_sat(100_000)?;
    /// assert_eq!(amount.to_btc(), amount.to_float_in(Denomination::Bitcoin));
    /// # Ok::<_, amount::ParseError>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_btc(self) -> f64 { self.to_float_in(Denomination::Bitcoin) }

    /// Converts this [`Amount`] in floating-point notation in the given [`Denomination`].
    ///
    /// # Errors
    ///
    /// If the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    #[cfg(feature = "alloc")]
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Self, ParseAmountError> {
        if value < 0.0 {
            return Err(OutOfRangeError::negative().into());
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Self::from_str_in(&value.to_string(), denom)
    }

    /// Constructs a new object that implements [`fmt::Display`] in the given [`Denomination`].
    ///
    /// This function is useful if you do not wish to allocate. See also [`Self::to_string_in`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{self, Amount, Denomination};
    /// # use std::fmt::Write;
    /// let amount = Amount::from_sat(10_000_000)?;
    /// let mut output = String::new();
    /// let _ = write!(&mut output, "{}", amount.display_in(Denomination::Bitcoin));
    /// assert_eq!(output, "0.1");
    /// # Ok::<_, amount::OutOfRangeError>(())
    /// ```
    #[must_use]
    pub fn display_in(self, denomination: Denomination) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::FixedDenomination { denomination, show_denomination: false },
        }
    }

    /// Constructs a new object that implements [`fmt::Display`] dynamically selecting
    /// [`Denomination`].
    ///
    /// This will use BTC for values greater than or equal to 1 BTC and satoshis otherwise. To
    /// avoid confusion the denomination is always shown.
    #[must_use]
    pub fn display_dynamic(self) -> Display {
        Display {
            sats_abs: self.to_sat(),
            is_negative: false,
            style: DisplayStyle::DynamicDenomination,
        }
    }

    /// Returns a formatted string representing this [`Amount`] in the given [`Denomination`].
    ///
    /// Returned string does not include the denomination.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{self, Amount, Denomination};
    /// let amount = Amount::from_sat(10_000_000)?;
    /// assert_eq!(amount.to_string_in(Denomination::Bitcoin), "0.1");
    /// # Ok::<_, amount::OutOfRangeError>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_string_in(self, denom: Denomination) -> String { self.display_in(denom).to_string() }

    /// Returns a formatted string representing this [`Amount`] in the given [`Denomination`],
    /// suffixed with the abbreviation for the denomination.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::amount::{self, Amount, Denomination};
    /// let amount = Amount::from_sat(10_000_000)?;
    /// assert_eq!(amount.to_string_with_denomination(Denomination::Bitcoin), "0.1 BTC");
    /// # Ok::<_, amount::OutOfRangeError>(())
    /// ```
    #[cfg(feature = "alloc")]
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        self.display_in(denom).show_denomination().to_string()
    }

    /// Checked addition.
    ///
    /// Returns [`None`] if the sum is larger than [`Amount::MAX`].
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        // Unchecked add ok, adding two values less than `MAX_MONEY` cannot overflow an `i64`.
        match Self::from_sat(self.to_sat() + rhs.to_sat()) {
            Ok(amount) => Some(amount),
            Err(_) => None,
        }
    }

    /// Checked subtraction.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat().checked_sub(rhs.to_sat()) {
            Some(res) => match Self::from_sat(res) {
                Ok(amount) => Some(amount),
                Err(_) => None, // Unreachable because of checked_sub above.
            },
            None => None,
        }
    }

    /// Checked multiplication.
    ///
    /// Returns [`None`] if the product is larger than [`Amount::MAX`].
    #[must_use]
    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat().checked_mul(rhs) {
            Some(res) => match Self::from_sat(res) {
                Ok(amount) => Some(amount),
                Err(_) => None,
            },
            None => None,
        }
    }

    /// Checked integer division.
    ///
    /// Be aware that integer division loses the remainder if no exact division can be made.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat().checked_div(rhs) {
            Some(res) => match Self::from_sat(res) {
                Ok(amount) => Some(amount),
                Err(_) => None, // Unreachable because of checked_div above.
            },
            None => None,
        }
    }

    /// Checked remainder.
    ///
    /// Returns [`None`] if overflow occurred.
    #[must_use]
    pub const fn checked_rem(self, rhs: u64) -> Option<Self> {
        // No `map()` in const context.
        match self.to_sat().checked_rem(rhs) {
            Some(res) => match Self::from_sat(res) {
                Ok(amount) => Some(amount),
                Err(_) => None, // Unreachable because of checked_rem above.
            },
            None => None,
        }
    }

    /// Converts to a signed amount.
    #[rustfmt::skip] // Moves code comments to the wrong line.
    #[allow(clippy::missing_panics_doc)]
    pub fn to_signed(self) -> SignedAmount {
        SignedAmount::from_sat(self.to_sat() as i64) // Cast ok, signed amount and amount share positive range.
            .expect("range of Amount is within range of SignedAmount")
    }

    /// Infallibly subtracts one `Amount` from another returning a [`SignedAmount`].
    ///
    /// Since `SignedAmount::MIN` is equivalent to `-Amount::MAX` subtraction of two signed amounts
    /// can never overflow a `SignedAmount`.
    #[must_use]
    pub fn signed_sub(self, rhs: Self) -> SignedAmount {
        (self.to_signed() - rhs.to_signed())
            .expect("difference of two amounts is always within SignedAmount range")
    }

    /// Checked weight floor division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made. See also [`Self::div_by_weight_ceil`].
    pub const fn div_by_weight_floor(self, weight: Weight) -> NumOpResult<FeeRate> {
        let wu = weight.to_wu();

        // Mul by 1,000 because we use per/kwu.
        if let Some(sats) = self.to_sat().checked_mul(1_000) {
            match sats.checked_div(wu) {
                Some(fee_rate) =>
                    if let Ok(amount) = Self::from_sat(fee_rate) {
                        return FeeRate::from_per_kwu(amount);
                    },
                None => return R::Error(E::while_doing(MathOp::Div)),
            }
        }
        // Use `MathOp::Mul` because `Div` implies div by zero.
        R::Error(E::while_doing(MathOp::Mul))
    }

    /// Checked weight ceiling division.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made. This method rounds up ensuring the transaction fee rate is
    /// sufficient. See also [`Self::div_by_weight_floor`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin_units::{amount, Amount, FeeRate, Weight};
    /// let amount = Amount::from_sat(10)?;
    /// let weight = Weight::from_wu(300);
    /// let fee_rate = amount.div_by_weight_ceil(weight).expect("valid fee rate");
    /// assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(34));
    /// # Ok::<_, amount::OutOfRangeError>(())
    /// ```
    pub const fn div_by_weight_ceil(self, weight: Weight) -> NumOpResult<FeeRate> {
        let wu = weight.to_wu();
        if wu == 0 {
            return R::Error(E::while_doing(MathOp::Div));
        }

        // Mul by 1,000 because we use per/kwu.
        if let Some(sats) = self.to_sat().checked_mul(1_000) {
            // No need to use checked arithmetic because wu is non-zero.
            let fee_rate = sats.div_ceil(wu);
            if let Ok(amount) = Self::from_sat(fee_rate) {
                return FeeRate::from_per_kwu(amount);
            }
        }
        // Use `MathOp::Mul` because `Div` implies div by zero.
        R::Error(E::while_doing(MathOp::Mul))
    }

    /// Checked fee rate floor division.
    ///
    /// Computes the maximum weight that would result in a fee less than or equal to this amount
    /// at the given `fee_rate`. Uses floor division to ensure the resulting weight doesn't cause
    /// the fee to exceed the amount.
    pub const fn div_by_fee_rate_floor(self, fee_rate: FeeRate) -> NumOpResult<Weight> {
        debug_assert!(Self::MAX.to_sat().checked_mul(1_000).is_some());
        let msats = self.to_sat() * 1_000;
        match msats.checked_div(fee_rate.to_sat_per_kwu_ceil()) {
            Some(wu) => R::Valid(Weight::from_wu(wu)),
            None => R::Error(E::while_doing(MathOp::Div)),
        }
    }

    /// Checked fee rate ceiling division.
    ///
    /// Computes the minimum weight that would result in a fee greater than or equal to this amount
    /// at the given `fee_rate`. Uses ceiling division to ensure the resulting weight is sufficient.
    pub const fn div_by_fee_rate_ceil(self, fee_rate: FeeRate) -> NumOpResult<Weight> {
        // Use ceil because result is used as the divisor.
        let rate = fee_rate.to_sat_per_kwu_ceil();
        // Early return so we do not have to use checked arithmetic below.
        if rate == 0 {
            return R::Error(E::while_doing(MathOp::Div));
        }

        debug_assert!(Self::MAX.to_sat().checked_mul(1_000).is_some());
        let msats = self.to_sat() * 1_000;
        NumOpResult::Valid(Weight::from_wu(msats.div_ceil(rate)))
    }
}

impl default::Default for Amount {
    fn default() -> Self { Self::ZERO }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({} SAT)", self.to_sat())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.display_in(Denomination::Bitcoin).show_denomination(), f)
    }
}

impl FromStr for Amount {
    type Err = ParseError;

    /// Parses a string slice where the slice includes a denomination.
    ///
    /// If the returned value would be zero or negative zero, then no denomination is required.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = Self::from_str_with_denomination(s);

        match result {
            Err(ParseError(ParseErrorInner::MissingDenomination(_))) => {
                let d = Self::from_str_in(s, Denomination::Satoshi);

                if d == Ok(Self::ZERO) {
                    Ok(Self::ZERO)
                } else {
                    result
                }
            }
            _ => result,
        }
    }
}

impl TryFrom<SignedAmount> for Amount {
    type Error = OutOfRangeError;

    fn try_from(value: SignedAmount) -> Result<Self, Self::Error> { value.to_unsigned() }
}

#[cfg(feature = "encoding")]
encoding::encoder_newtype_exact! {
    /// The encoder for the [`Amount`] type.
    pub struct AmountEncoder<'e>(encoding::ArrayEncoder<8>);
}

#[cfg(feature = "encoding")]
impl encoding::Encodable for Amount {
    type Encoder<'e> = AmountEncoder<'e>;
    fn encoder(&self) -> Self::Encoder<'_> {
        AmountEncoder::new(encoding::ArrayEncoder::without_length_prefix(
            self.to_sat().to_le_bytes(),
        ))
    }
}

/// The decoder for the [`Amount`] type.
#[cfg(feature = "encoding")]
pub struct AmountDecoder(encoding::ArrayDecoder<8>);

#[cfg(feature = "encoding")]
impl AmountDecoder {
    /// Constructs a new [`Amount`] decoder.
    pub const fn new() -> Self { Self(encoding::ArrayDecoder::new()) }
}

#[cfg(feature = "encoding")]
impl Default for AmountDecoder {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "encoding")]
impl encoding::Decoder for AmountDecoder {
    type Output = Amount;
    type Error = AmountDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.0.push_bytes(bytes).map_err(AmountDecoderError::eof)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let a = u64::from_le_bytes(self.0.end().map_err(AmountDecoderError::eof)?);
        Amount::from_sat(a).map_err(AmountDecoderError::out_of_range)
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

#[cfg(feature = "encoding")]
impl encoding::Decodable for Amount {
    type Decoder = AmountDecoder;
    fn decoder() -> Self::Decoder { AmountDecoder(encoding::ArrayDecoder::<8>::new()) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Amount {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let sats = u.int_in_range(Self::MIN.to_sat()..=Self::MAX.to_sat())?;
        Ok(Self::from_sat(sats).expect("range is valid"))
    }
}
