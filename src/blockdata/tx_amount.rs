// The Rust Bitcoin Library - Written by the rust-bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! An amount that can represent the value of an unsigned transaction output (UTXO) or the total
//! value of a transaction. This implies there is an upper limit for this value. We use 21 million
//! as the upper bound because if a transaction gets included in the chain that spends more than
//! this Bitcoin is dead - long live Bitcoin.
//!

use core::fmt;
use core::convert::TryFrom;
use core::str::FromStr;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::internal_macros::write_err;
use crate::io;
use crate::parse::{self, ParseIntError};
use crate::prelude::*;
use crate::util::amount::Amount;

/// Upper bound on maximum sats in a single transaction (21_000_000 * 100_000_000).
const MAX_SATS: u64 = 2_100_000_000_000_000;

/// TODO: Document this.
const NULL_TX_OUT: u64 = 0xffffffffffffffff;

/// The `TXAmount` type can be used to express Bitcoin transaction amounts, it only supports checked
/// arithmetic because silently overflowing is never useful for bitcoin amounts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxAmount {
    value: u64,
    null: bool,
}

impl TxAmount {
    /// The minimum value for a transaction amount.
    ///
    /// A transaction amount is always greater than, or equal to, zero i.e., [`TxAmount`] is a
    /// signed integer type.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::Amount;
    /// assert_eq!(TxAmount::MIN, TxAmount::from_sats(0).expect("valid value"););
    /// assert_eq!(TXAmount::MIN, Amount::ZERO);
    /// ```
    pub const MIN: TxAmount = TxAmount { value: 0, null: false };
    /// The maximum amount value for a transaction amount.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::TxAmount;
    /// assert_eq!(Amount::MAX, Amount::from_sats(21_000_000).expect("21 million is valid"));
    /// ```
    pub const MAX: TxAmount = TxAmount { value: MAX_SATS, null: false };
    /// The zero amount.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::TxAmount;
    /// assert_eq!(TxAmount::ZERO, TxAmount::from_sats(0).expect("valid value"));
    /// ```
    pub const ZERO: TxAmount = TxAmount { value: 0, null: false };
    /// Exactly one satoshi.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::TxAmount;
    /// assert_eq!(TxAmount::ONE_SAT, TxAmount::from_sats(1).expect("valid value"));
    /// ```
    pub const ONE_SAT: TxAmount = TxAmount { value: 1, null: false };
    /// Exactly one bitcoin.
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::TxAmount;
    /// assert_eq!(TxAmount::ONE_BTC, TxAmount::from_sats(100_000_000).expect("valid value"));
    /// ```
    pub const ONE_BTC: TxAmount = TxAmount { value: 100_000_000, null: false };

    /// TODO: Document this with references from somewhere.
    ///
    /// The transaction amount with all bits set is used by consensus code to signal "null transaction".
    pub const NULL_TX_OUT: TxAmount = TxAmount{ value: NULL_TX_OUT, null: true };

    /// Returns the number of satoshis in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::Amount;
    /// let value = TxAmount::from_sat(100_000).expect("valid value");
    /// assert_eq!(value.to_sat(), 100_000);
    /// ```
    #[inline]
    pub const fn to_sat(self) -> u64 {
        self.value
    }

    /// Equivalent to [`TxAmount::to_sat`].
    #[inline]
    pub const fn to_sats(self) -> u64 {
        self.to_sat()
    }

    /// Converts self to an [`Amount`].
    ///
    /// TODO: Write example.
    #[inline]
    pub fn to_amount(self) -> Amount {
        if self.null {
            Amount::from_sat(NULL_TX_OUT)
        } else {
            Amount::from_sat(self.value)
        }
    }

    /// Creates a [`TxAmount`] from given number of satoshis.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::Amount;
    /// let value = Amount::from_sat(100_000).expect("valid value");;
    /// assert_eq!(value.to_sat(), 100_000);
    /// ```
    #[inline]
    pub fn from_sat(sat: u64) -> Result<TxAmount, Error> {
        if sat > MAX_SATS {
            Err(Error::Overflow(sat as u64)) // Can't use `into` because its not `const`.
        } else {
            Ok(TxAmount{ value: sat, null: false })
        }
    }

    /// Equivalent to [`TxAmount::from_sat`].
    #[inline]
    pub fn from_sats(sats: u64) -> Result<TxAmount, Error> {
        TxAmount::from_sat(sats)
    }

    /// Creates a [`TxAmount`] from a number of satoshis as a string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::Amount;
    /// let value = Amount::from_sats(100_000).expect("valid value");;
    /// assert_eq!(value.to_sat(), 100_000);
    /// ```
    #[inline]
    pub fn from_sat_str(s: &str) -> Result<TxAmount, Error> {
        let x = parse::int(s)?;
        TxAmount::from_sats(x)
    }

    /// Checked integer addition. Computes `self + rhs`, returning `None` if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::TxAmount;
    /// let a = TxAmount::from_sats(10_000_000);
    /// let b = TxAmount::from_sats(1_000_000);
    /// assert_eq!(a.checked_add(b), Some(TxAmount::from_sats(11_000_000)));
    /// assert_eq!(a.checked_add(TxAmount::MAX), None);
    /// ```
    #[inline]
    pub fn checked_add(self, rhs: TxAmount) -> Option<TxAmount> {
        let x = self.value + rhs.value;
        TxAmount::from_sats(x).ok()
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::TxAmount;
    /// let a = TxAmount::from_sats(10_000_000);
    /// let b = TxAmount::from_sats(1_000_000);
    /// assert_eq!(a.checked_sub(b), Some(TxAmount::from_sats(9_000_000)));
    /// assert_eq!(TxAmount::MIN.checked_sub(TxAmount::ONE_SAT), None);
    /// ```
    #[inline]
    pub fn checked_sub(self, rhs: TxAmount) -> Option<TxAmount> {
        let x = self.value.checked_sub(rhs.value)?;
        TxAmount::from_sats(x).ok()
    }

    /// Checked integer multiplication. Computes `self * rhs`, returning `None` if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::TxAmount;
    /// assert_eq!(TxAmount::ONE_SAT.checked_mul(1_000), Some(TxAmount::from_sats(1_000)));
    /// assert_eq!(TxAmount::max_value().checked_mul(2), None);
    /// ```
    #[inline]
    pub fn checked_mul(self, rhs: u64) -> Option<TxAmount> {
        let x = self.value.checked_mul(rhs)?;
        TxAmount::from_sats(x).ok()
    }

    /// Checked integer division. Computes `self / rhs`, returning `None` if `rhs == 0`.
    ///
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made (floor division).
    ///
    /// # Examples
    /// ```
    /// # use bitcoin::TxAmount;
    /// let a = TxAmount::from_sats(5);
    /// assert_eq!(a.checked_div(2), Some(TxAmount::from_sats(2)));
    /// assert_eq!(a.checked_div(0), None);
    /// ```
    #[inline]
    pub fn checked_div(self, rhs: u64) -> Option<TxAmount> {
        let x = self.value.checked_div(rhs)?;
        TxAmount::from_sats(x).ok()
    }

    /// Checked integer remainder. Computes `self % rhs`, returning None if `rhs == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::TxAmount;
    /// let a = TxAmount::from_sats(5);
    /// assert_eq!(a.checked_rem(2), Some(TxAmount::from_sat(1)));
    /// assert_eq!(a.checked_rem(0), None);
    /// ```
    #[inline]
    pub fn checked_rem(self, rhs: u64) -> Option<TxAmount> {
        let x = self.value.checked_rem(rhs)?;
        TxAmount::from_sats(x).ok()
    }
}

macro_rules! impl_try_from {
    ($ty:ident) => {
        impl TryFrom<$ty> for TxAmount {
            type Error = Error;

            #[inline]
            fn try_from(x: $ty) -> Result<Self, Self::Error> {
                TxAmount::from_sats(x.into())
            }
        }
    }
}
impl_try_from!(u64);
impl_try_from!(u32);
impl_try_from!(u16);
impl_try_from!(u8);

impl FromStr for TxAmount {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = parse::int(s)?;
        TxAmount::from_sats(x)
    }
}

impl TryFrom<&str> for TxAmount {
    type Error = Error;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let x = parse::int(s)?;
        TxAmount::from_sats(x)
    }
}

impl TryFrom<String> for TxAmount {
    type Error = Error;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let x = parse::int(s)?;
        TxAmount::from_sats(x)
    }
}

impl Encodable for TxAmount {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        if self.null {
            NULL_TX_OUT.consensus_encode(w)
        } else {
            self.value.consensus_encode(w)
        }
    }
}

impl Decodable for TxAmount {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let x = u64::consensus_decode(r)?;
        if x == u64::max_value() {
            Ok(TxAmount::NULL_TX_OUT)
        } else {
            TxAmount::from_sats(x).map_err(|_| encode::Error::ParseFailed("transaction amount is greater than 21 million"))
        }
    }
}

/// Errors encountered when working with [`TxAmount`].
#[derive(Debug)]
pub enum Error {
    /// Value overflowed i.e., is greater than 21 million.
    Overflow(u64),
    /// String parse error.
    Parse(ParseIntError),
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Overflow(ref x) => write!(f, "{} overflows tx amount (greater than 21 million)", x),
            Parse(ref e) => write_err!(f, "error while attempting to parse a tx amount from string"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            Overflow(_) => None,
            Parse(ref e) => Some(e),
        }
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::Parse(e)
    }
}
