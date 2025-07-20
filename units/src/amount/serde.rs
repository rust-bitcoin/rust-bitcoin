// SPDX-License-Identifier: CC0-1.0

// methods are implementation of a standardized serde-specific signature
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

//! This module adds serde serialization and deserialization support for amounts.
//!
//! Since there is not a default way to serialize and deserialize amounts, multiple
//! ways are supported and it's up to the user to decide which serialization to use.
//!
//! # Examples
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use bitcoin_units::{amount, Amount};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct HasAmount {
//!     #[serde(with = "amount::serde::as_sat")]
//!     pub amount: Amount,
//! }
//! ```

#[cfg(feature = "alloc")]
use core::fmt;

#[cfg(feature = "alloc")]
use super::ParseAmountError;

#[cfg(feature = "alloc")]
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
#[cfg(feature = "alloc")]
impl fmt::Display for DisplayFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

pub mod as_sat {
    //! Serialize and deserialize [`Amount`] and [`SignedAmount`] as real numbers denominated in satoshi.
    //!
    //! Use with `#[serde(with = "amount::serde::as_sat")]`.
    //!
    //! [`Amount`]: crate::Amount
    //! [`SignedAmount`]: crate::SignedAmount

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::SignedAmount;

    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        i64::serialize(&amount.to_sat(), s)
    }

    pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<A, D::Error>
    where
        A: TryFrom<SignedAmount>,
        <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
    {
        let sat = i64::deserialize(d)?;
        let amount = SignedAmount::from_sat(sat).map_err(serde::de::Error::custom)?;

        A::try_from(amount).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        //! Serialize and deserialize `Option<Amount>` and `Option<SignedAmount>` as real numbers
        //! denominated in satoshi.
        //!
        //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use serde::{de, Deserializer, Serializer};

        use crate::SignedAmount;

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<A, S: Serializer>(a: &Option<A>, s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            match *a {
                Some(a) => {
                    let amount: SignedAmount = a.into();
                    s.serialize_some(&amount.to_sat())
                }
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Option<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitOptAmt<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "an Option<i64>")
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
                    Ok(Some(super::deserialize(d)?))
                }
            }
            d.deserialize_option(VisitOptAmt::<A>(PhantomData))
        }
    }
}

#[cfg(feature = "alloc")]
pub mod as_btc {
    //! Serialize and deserialize [`Amount`] and [`SignedAmount`] as JSON numbers denominated in BTC.
    //!
    //! Use with `#[serde(with = "amount::serde::as_btc")]`.
    //!
    //! [`Amount`]: crate::Amount
    //! [`SignedAmount`]: crate::SignedAmount

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::DisplayFullError;
    use crate::amount::{Denomination, SignedAmount};

    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        f64::serialize(&amount.to_float_in(Denomination::Bitcoin), s)
    }

    pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<A, D::Error>
    where
        A: TryFrom<SignedAmount>,
        <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
    {
        let btc = f64::deserialize(d)?;
        let amount = SignedAmount::from_btc(btc)
            .map_err(DisplayFullError)
            .map_err(serde::de::Error::custom)?;

        A::try_from(amount).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        //! Serialize and deserialize `Option<Amount>` and `Option<SignedAmount>` as JSON numbers
        //! denominated in BTC.
        //!
        //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use serde::{de, Deserializer, Serialize, Serializer};

        use crate::amount::{Denomination, SignedAmount};

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<A, S: Serializer>(a: &Option<A>, s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            match *a {
                Some(a) => {
                    let amount: SignedAmount = a.into();
                    f64::serialize(&amount.to_float_in(Denomination::Bitcoin), s)
                }
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Option<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitOptAmt<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "an Option<f64>")
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
                    Ok(Some(super::deserialize(d)?))
                }
            }
            d.deserialize_option(VisitOptAmt::<A>(PhantomData))
        }
    }
}

#[cfg(feature = "alloc")]
pub mod as_str {
    //! Serialize and deserialize [`Amount`] and [`SignedAmount`] as a JSON string denominated in BTC.
    //!
    //! Use with `#[serde(with = "amount::serde::as_str")]`.
    //!
    //! [`Amount`]: crate::Amount
    //! [`SignedAmount`]: crate::SignedAmount

    use alloc::string::String;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::DisplayFullError;
    use crate::amount::{Denomination, SignedAmount};

    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        str::serialize(&amount.to_string_in(Denomination::Bitcoin), s)
    }

    pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<A, D::Error>
    where
        A: TryFrom<SignedAmount>,
        <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
    {
        let btc = String::deserialize(d)?;
        let amount = SignedAmount::from_str_in(&btc, Denomination::Bitcoin)
            .map_err(DisplayFullError)
            .map_err(serde::de::Error::custom)?;

        A::try_from(amount).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        //! Serialize and deserialize `Option<Amount>` and `Option<SignedAmount>` as a JSON string
        //! denominated in BTC.
        //!
        //! Use with `#[serde(default, with = "amount::serde::as_str::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use serde::{de, Deserializer, Serialize, Serializer};

        use crate::amount::{Denomination, SignedAmount};

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<A, S: Serializer>(a: &Option<A>, s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            match *a {
                Some(a) => {
                    let amount: SignedAmount = a.into();
                    str::serialize(&amount.to_string_in(Denomination::Bitcoin), s)
                }
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Option<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitOptAmt<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "an Option<String>")
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
                    Ok(Some(super::deserialize(d)?))
                }
            }
            d.deserialize_option(VisitOptAmt::<A>(PhantomData))
        }
    }
}

#[cfg(test)]
mod tests {

    use serde::{Deserialize, Serialize};

    use crate::amount::{self, Amount, SignedAmount};

    #[test]
    fn can_serde_as_sat() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct HasAmount {
            #[serde(with = "amount::serde::as_sat")]
            pub amount: Amount,
            #[serde(with = "amount::serde::as_sat")]
            pub signed_amount: SignedAmount,
        }

        let orig = HasAmount { amount: Amount::ONE_BTC, signed_amount: SignedAmount::ONE_BTC };

        let json = serde_json::to_string(&orig).expect("failed to ser");
        let want = "{\"amount\":100000000,\"signed_amount\":100000000}";
        assert_eq!(json, want);

        let rinsed: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(rinsed, orig);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn can_serde_as_btc() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct HasAmount {
            #[serde(with = "amount::serde::as_btc")]
            pub amount: Amount,
            #[serde(with = "amount::serde::as_btc")]
            pub signed_amount: SignedAmount,
        }

        let orig = HasAmount { amount: Amount::ONE_BTC, signed_amount: SignedAmount::ONE_BTC };

        let json = serde_json::to_string(&orig).expect("failed to ser");
        let want = "{\"amount\":1.0,\"signed_amount\":1.0}";
        assert_eq!(json, want);

        let rinsed: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(rinsed, orig);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn can_serde_as_str() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct HasAmount {
            #[serde(with = "amount::serde::as_str")]
            pub amount: Amount,
            #[serde(with = "amount::serde::as_str")]
            pub signed_amount: SignedAmount,
        }

        let orig = HasAmount { amount: Amount::ONE_BTC, signed_amount: SignedAmount::ONE_BTC };

        let json = serde_json::to_string(&orig).expect("failed to ser");
        let want = "{\"amount\":\"1\",\"signed_amount\":\"1\"}";
        assert_eq!(json, want);

        let rinsed: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(rinsed, orig);
    }
}
