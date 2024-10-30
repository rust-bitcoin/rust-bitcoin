// SPDX-License-Identifier: CC0-1.0

//! Bitcoin has value, and that value is denominated in sats - period.

use core::fmt;

#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

/// Abstraction over Bitcoin value - denominated in Satoshis.
///
/// Value can never be negative and has nothing to do with floats.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Value(u64);

/// Zero value.
pub const ZERO: Value = Value(0);
/// Exactly one satoshi.
pub const ONE_SAT: Value = Value(1);
/// Exactly one bitcoin.
pub const ONE_BTC: Value = Value(100_000_000);
/// Exactly fifty bitcoin.
pub const FIFTY_BTC: Value = Value(50 * 100_000_000);

impl Value {
    /// Zero value.
    pub const ZERO: Value = Value(0);
    /// The maximum value allowed as an amount. Useful for sanity checking.
    pub const MAX_MONEY: Value = Value(21_000_000 * ONE_BTC.0);
    /// The minimum possible value.
    pub const MIN: Value = Value(u64::MIN);
    /// The maximum possible value.
    pub const MAX: Value = Value(u64::MAX);
    /// The number of bytes that a value type contributes to the size of a transaction.
    pub const SIZE: usize = 8; // Serialized length of a u64.

    /// Creates a [`Value`] from a `u64` (you can also just use `from`).
    pub const fn from_sat(sat: u64) -> Value { Value(sat) }

    /// Gets the satoshi value as a `u64`.
    pub const fn to_sat(self) -> u64 { self.0 }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

macro_rules! impl_from_uint {
    ($($uint:ty),*) => {
        $(
            impl From<$uint> for Value {
                fn from(v: $uint) -> Self { Self(v.into())}
            }
        )*
    }
}
impl_from_uint!(u8, u16, u32, u64);

impl From<Value> for u64 {
    fn from(v: Value) -> u64 { v.0 }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Value {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = u64::arbitrary(u)?;
        Ok(Value(a))
    }
}
