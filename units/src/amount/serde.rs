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

#[cfg(feature = "alloc")]
#[cfg(not(feature = "std"))]
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

    use core::fmt;
    use core::marker::PhantomData;
    use serde::{Deserializer, Serialize, Serializer};

    use crate::SignedAmount;

    fn is_signed<T: TryFrom<SignedAmount>>() -> bool {
        T::try_from(-SignedAmount::from(crate::amt!(1 sat))).is_ok()
    }

    #[test]
    fn is_signed_correct() {
        assert!(!is_signed::<crate::Amount>());
        assert!(is_signed::<crate::SignedAmount>());
    }

    #[inline]
    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        i64::serialize(&amount.to_sat(), s)
    }

    #[inline]
    pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<A, D::Error>
    where
        A: TryFrom<SignedAmount>,
        <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
    {
        fn expecting<T: TryFrom<SignedAmount>>() -> &'static str {
            if is_signed::<T>() {
                "an integer between -2100000000000000 and 2100000000000000 inclusive"
            } else {
                "an integer between 0 and 2100000000000000 inclusive"
            }
        }

        // We use custom visitor to have better control over error messages
        struct Visitor<T>(PhantomData<fn() -> T>);

        impl<'de, T> serde::de::Visitor<'de> for Visitor<T> where T: TryFrom<SignedAmount> {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(expecting::<T>())
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                fn range_error<T, E1, E2: serde::de::Error>(value: i64) -> impl FnOnce(E1) -> E2
                    where T: TryFrom<SignedAmount>
                {
                    move |_| {
                        let unexpected = serde::de::Unexpected::Signed(value);
                        E2::invalid_value(unexpected, &expecting::<T>())
                    }
                }

                SignedAmount::from_sat(value)
                    .map_err(range_error::<T, _, _>(value))?
                    .try_into()
                    .map_err(range_error::<T, _, _>(value))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                fn range_error<T, E1, E2: serde::de::Error>(value: u64) -> impl FnOnce(E1) -> E2
                    where T: TryFrom<SignedAmount>
                {
                    move |_| {
                        let unexpected = serde::de::Unexpected::Unsigned(value);
                        E2::invalid_value(unexpected, &expecting::<T>())
                    }
                }

                let signed = i64::try_from(value).map_err(range_error::<T, _, _>(value))?;
                SignedAmount::from_sat(signed)
                    .map_err(range_error::<T, _, _>(value))?
                    .try_into()
                    .map_err(range_error::<T, _, _>(value))
            }
        }
        if is_signed::<A>() {
            d.deserialize_i64(Visitor(PhantomData))
        } else {
            d.deserialize_u64(Visitor(PhantomData))
        }
    }

    pub mod opt {
        //! Serialize and deserialize `Option<Amount>` and `Option<SignedAmount>` as real numbers
        //! denominated in satoshi.
        //!
        //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

        use core::fmt;
        use core::marker::PhantomData;

        use super::is_signed;
        use serde::{de, Deserializer, Serializer};

        use crate::SignedAmount;

        #[inline]
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
            fn expecting<T: TryFrom<SignedAmount>>() -> &'static str {
                if is_signed::<T>() {
                    "an optional integer between -2100000000000000 and 2100000000000000 inclusive"
                } else {
                    "an optional integer between 0 and 2100000000000000 inclusive"
                }
            }

            struct VisitOptAmt<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitOptAmt<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Option<X>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str(expecting::<X>())
                }

                #[inline]
                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(None)
                }

                #[inline]
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

    #[cfg(feature = "alloc")]
    pub mod vec {
        //! Serialize and deserialize `Vec<Amount>` and `Vec<SignedAmount>` as real numbers
        //! denominated in satoshi.
        //!
        //! Use with `#[serde(with = "amount::serde::as_sat::vec")]`.

        use alloc::vec::Vec;
        use core::fmt;
        use core::marker::PhantomData;
        use super::is_signed;

        use serde::de::{self, SeqAccess};
        use serde::ser::SerializeSeq;
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::SignedAmount;

        pub fn serialize<A, S: Serializer>(a: &[A], s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            let mut seq = s.serialize_seq(Some(a.len()))?;
            for amount in a {
                let signed_amount: SignedAmount = (*amount).into();
                seq.serialize_element(&signed_amount.to_sat())?;
            }
            seq.end()
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Vec<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            fn expecting<T: TryFrom<SignedAmount>>() -> &'static str {
                if is_signed::<T>() {
                    "an sequence of integers between -2100000000000000 and 2100000000000000 inclusive"
                } else {
                    "an sequence of integers between 0 and 2100000000000000 inclusive"
                }
            }

            struct VisitVec<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitVec<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Vec<X>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str(expecting::<X>())
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    #[derive(Deserialize)]
                    #[serde(transparent)]
                    struct Wrapper<T: TryFrom<SignedAmount>>(#[serde(with = "super")] T) where T::Error: core::fmt::Display;

                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(wrapped) = seq.next_element::<Wrapper<X>>()? {
                        out.push(wrapped.0);
                    }
                    Ok(out)
                }
            }

            d.deserialize_seq(VisitVec::<A>(PhantomData))
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

    #[inline]
    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        f64::serialize(&amount.to_float_in(Denomination::Bitcoin), s)
    }

    #[inline]
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

        #[inline]
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

                #[inline]
                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(None)
                }

                #[inline]
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

    pub mod vec {
        //! Serialize and deserialize `Vec<Amount>` and `Vec<SignedAmount>` as JSON numbers
        //! denominated in BTC.
        //!
        //! Use with `#[serde(with = "amount::serde::as_btc::vec")]`.

        use alloc::vec::Vec;
        use core::fmt;
        use core::marker::PhantomData;

        use serde::de::{self, SeqAccess};
        use serde::ser::SerializeSeq;
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::amount::{Denomination, SignedAmount};

        pub fn serialize<A, S: Serializer>(a: &[A], s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            let mut seq = s.serialize_seq(Some(a.len()))?;
            for amount in a {
                let signed_amount: SignedAmount = (*amount).into();
                seq.serialize_element(&signed_amount.to_float_in(Denomination::Bitcoin))?;
            }
            seq.end()
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Vec<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            struct VisitVec<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitVec<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Vec<X>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a sequence of f64")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    #[derive(Deserialize)]
                    #[serde(transparent)]
                    struct Wrapper(#[serde(with = "super")] SignedAmount);

                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(wrapped) = seq.next_element::<Wrapper>()? {
                        out.push(X::try_from(wrapped.0).map_err(de::Error::custom)?);
                    }
                    Ok(out)
                }
            }

            d.deserialize_seq(VisitVec::<A>(PhantomData))
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

    #[inline]
    pub fn serialize<A, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        A: Into<SignedAmount> + Copy,
    {
        let amount: SignedAmount = (*a).into();
        str::serialize(&amount.to_string_in(Denomination::Bitcoin), s)
    }

    #[inline]
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

        #[inline]
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

                #[inline]
                fn visit_none<E>(self) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(None)
                }

                #[inline]
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

    pub mod vec {
        //! Serialize and deserialize `Vec<Amount>` and `Vec<SignedAmount>` as JSON strings
        //! denominated in BTC.
        //!
        //! Use with `#[serde(with = "amount::serde::as_str::vec")]`.

        use alloc::vec::Vec;
        use core::fmt;
        use core::marker::PhantomData;

        use serde::de::{self, SeqAccess};
        use serde::ser::SerializeSeq;
        use serde::{Deserialize, Deserializer, Serializer};

        use crate::amount::{Denomination, SignedAmount};

        pub fn serialize<A, S: Serializer>(a: &[A], s: S) -> Result<S::Ok, S::Error>
        where
            A: Into<SignedAmount> + Copy,
        {
            let mut seq = s.serialize_seq(Some(a.len()))?;
            for amount in a {
                let signed_amount: SignedAmount = (*amount).into();
                seq.serialize_element(&signed_amount.to_string_in(Denomination::Bitcoin))?;
            }
            seq.end()
        }

        pub fn deserialize<'d, A, D: Deserializer<'d>>(d: D) -> Result<Vec<A>, D::Error>
        where
            A: TryFrom<SignedAmount>,
            <A as TryFrom<SignedAmount>>::Error: core::fmt::Display,
        {
            struct VisitVec<X>(PhantomData<X>);

            impl<'de, X> de::Visitor<'de> for VisitVec<X>
            where
                X: TryFrom<SignedAmount>,
                <X as TryFrom<SignedAmount>>::Error: core::fmt::Display,
            {
                type Value = Vec<X>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a sequence of String")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    #[derive(Deserialize)]
                    #[serde(transparent)]
                    struct Wrapper(#[serde(with = "super")] SignedAmount);

                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(wrapped) = seq.next_element::<Wrapper>()? {
                        out.push(X::try_from(wrapped.0).map_err(de::Error::custom)?);
                    }
                    Ok(out)
                }
            }

            d.deserialize_seq(VisitVec::<A>(PhantomData))
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

        let roundtrip: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(roundtrip, orig);
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

        let roundtrip: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(roundtrip, orig);
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

        let roundtrip: HasAmount = serde_json::from_str(&json).expect("failed to deser");
        assert_eq!(roundtrip, orig);
    }
}
