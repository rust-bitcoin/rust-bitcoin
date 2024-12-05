// SPDX-License-Identifier: CC0-1.0

// methods are implementation of a standardized serde-specific signature
#![allow(missing_docs)]

//! This module adds serde serialization and deserialization support for Amounts.
//!
//! Since there is not a default way to serialize and deserialize Amounts, multiple
//! ways are supported and it's up to the user to decide which serialiation to use.
//! The provided modules can be used as follows:
//!
//! ```rust,ignore
//! use serde::{Serialize, Deserialize};
//! use bitcoin_units::Amount;
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct HasAmount {
//!     #[serde(with = "bitcoin_units::amount::serde::as_btc")]
//!     pub amount: Amount,
//! }
//! ```

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "alloc")] // This is because `to_float_in` uses `to_string`.
use super::Denomination;
use super::{Amount, ParseAmountError, SignedAmount};

/// This trait is used only to avoid code duplication and naming collisions
/// of the different serde serialization crates.
pub trait SerdeAmount: Copy + Sized {
    fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
    fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error>;
    #[cfg(feature = "alloc")]
    fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
    #[cfg(feature = "alloc")]
    fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error>;
}

mod private {
    /// Controls access to the trait methods.
    pub struct Token;
}

/// This trait is only for internal Amount type serialization/deserialization
pub trait SerdeAmountForOpt: Copy + Sized + SerdeAmount {
    fn type_prefix(_: private::Token) -> &'static str;
    fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
    #[cfg(feature = "alloc")]
    fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error>;
}

struct DisplayFullError(ParseAmountError);

#[cfg(feature = "std")]
impl fmt::Display for DisplayFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        fmt::Display::fmt(&self.0, f)?;
        let mut source_opt = self.0.source();
        while let Some(source) = source_opt {
            write!(f, ": {}", source)?;
            source_opt = source.source();
        }
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl fmt::Display for DisplayFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl SerdeAmount for Amount {
    fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        u64::serialize(&self.to_sat(), s)
    }
    fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
        use serde::de::Error;
        let des = u64::deserialize(d)?;
        Amount::from_sat(des).ok_or(<D as Deserializer>::Error::custom("exceeds MAX_MONEY"))
    }
    #[cfg(feature = "alloc")]
    fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
    }
    #[cfg(feature = "alloc")]
    fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
        use serde::de::Error;
        Amount::from_btc(f64::deserialize(d)?).map_err(DisplayFullError).map_err(D::Error::custom)
    }
}

impl SerdeAmountForOpt for Amount {
    fn type_prefix(_: private::Token) -> &'static str { "u" }
    fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        s.serialize_some(&self.to_sat())
    }
    #[cfg(feature = "alloc")]
    fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        s.serialize_some(&self.to_btc())
    }
}

impl SerdeAmount for SignedAmount {
    fn ser_sat<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        i64::serialize(&self.to_sat(), s)
    }
    fn des_sat<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
        Ok(SignedAmount::from_sat(i64::deserialize(d)?))
    }
    #[cfg(feature = "alloc")]
    fn ser_btc<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        f64::serialize(&self.to_float_in(Denomination::Bitcoin), s)
    }
    #[cfg(feature = "alloc")]
    fn des_btc<'d, D: Deserializer<'d>>(d: D, _: private::Token) -> Result<Self, D::Error> {
        use serde::de::Error;
        SignedAmount::from_btc(f64::deserialize(d)?)
            .map_err(DisplayFullError)
            .map_err(D::Error::custom)
    }
}

impl SerdeAmountForOpt for SignedAmount {
    fn type_prefix(_: private::Token) -> &'static str { "i" }
    fn ser_sat_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        s.serialize_some(&self.to_sat())
    }
    #[cfg(feature = "alloc")]
    fn ser_btc_opt<S: Serializer>(self, s: S, _: private::Token) -> Result<S::Ok, S::Error> {
        s.serialize_some(&self.to_btc())
    }
}

pub mod as_sat {
    //! Serialize and deserialize [`Amount`](crate::Amount) as real numbers denominated in satoshi.
    //! Use with `#[serde(with = "amount::serde::as_sat")]`.

    use serde::{Deserializer, Serializer};

    use super::private;
    use crate::amount::serde::SerdeAmount;

    pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
        a.ser_sat(s, private::Token)
    }

    pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
        A::des_sat(d, private::Token)
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<Amount>`](crate::Amount) as real numbers denominated in satoshi.
        //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use serde::{de, Deserializer, Serializer};

        use super::private;
        use crate::amount::serde::SerdeAmountForOpt;

        pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
            a: &Option<A>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match *a {
                Some(a) => a.ser_sat_opt(s, private::Token),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
            d: D,
        ) -> Result<Option<A>, D::Error> {
            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "An Option<{}64>", X::type_prefix(private::Token))
                }

                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(None)
                }
                fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    Ok(Some(X::des_sat(d, private::Token)?))
                }
            }
            d.deserialize_option(VisitOptAmt::<A>(PhantomData))
        }
    }
}

#[cfg(feature = "alloc")]
pub mod as_btc {
    //! Serialize and deserialize [`Amount`](crate::Amount) as JSON numbers denominated in BTC.
    //! Use with `#[serde(with = "amount::serde::as_btc")]`.

    use serde::{Deserializer, Serializer};

    use super::private;
    use crate::amount::serde::SerdeAmount;

    pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
        a.ser_btc(s, private::Token)
    }

    pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
        A::des_btc(d, private::Token)
    }

    pub mod opt {
        //! Serialize and deserialize `Option<Amount>` as JSON numbers denominated in BTC.
        //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use serde::{de, Deserializer, Serializer};

        use super::private;
        use crate::amount::serde::SerdeAmountForOpt;

        pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
            a: &Option<A>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            match *a {
                Some(a) => a.ser_btc_opt(s, private::Token),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
            d: D,
        ) -> Result<Option<A>, D::Error> {
            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "An Option<f64>")
                }

                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(None)
                }
                fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    Ok(Some(X::des_btc(d, private::Token)?))
                }
            }
            d.deserialize_option(VisitOptAmt::<A>(PhantomData))
        }
    }
}
