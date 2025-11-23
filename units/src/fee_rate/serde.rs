// SPDX-License-Identifier: CC0-1.0

// Module implements standardized serde-specific trait methods.
#![allow(missing_docs)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::missing_errors_doc)]

//! This module adds serde serialization and deserialization support for fee rates.
//!
//! Since there is not a default way to serialize and deserialize fee rates, multiple
//! ways are supported and it's up to the user to decide which serialization to use.
//!
//! The provided modules can be used as follows:
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use bitcoin_units::{fee_rate, FeeRate};
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct Foo {
//!     #[serde(with = "fee_rate::serde::as_sat_per_kwu_floor")]
//!     pub fee_rate: FeeRate,
//! }
//! ```

use core::convert::Infallible;
use core::fmt;

pub mod as_sat_per_kwu_floor {
    //! Serialize and deserialize [`FeeRate`] denominated in satoshis per 1000 weight units.
    //!
    //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_kwu_floor")]`.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Amount, FeeRate};

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_kwu_floor(), s)
    }

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        let sat = u64::deserialize(d)?;
        FeeRate::from_per_kwu(
            Amount::from_sat(sat).map_err(|_| serde::de::Error::custom("amount out of range"))?,
        )
        .into_result()
        .map_err(|_| serde::de::Error::custom("fee rate too big for sats/kwu"))
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per 1000 weight units.
        //!
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_kwu_floor::opt")]`.

        use core::fmt;

        use serde::{de, Deserializer, Serializer};

        use crate::FeeRate;

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<S: Serializer>(f: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
            match *f {
                Some(f) => s.serialize_some(&f.to_sat_per_kwu_floor()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<FeeRate>, D::Error> {
            struct VisitOpt;

            impl<'de> de::Visitor<'de> for VisitOpt {
                type Value = Option<FeeRate>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "an Option<u64>")
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
            d.deserialize_option(VisitOpt)
        }
    }
}

pub mod as_sat_per_vb_floor {
    //! Serialize and deserialize [`FeeRate`] denominated in satoshis per virtual byte.
    //!
    //! When serializing use floor division to convert per kwu to per virtual byte.
    //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_floor")]`.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Amount, FeeRate};

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_vb_floor(), s)
    }

    // Errors on overflow.
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        let sat = u64::deserialize(d)?;
        FeeRate::from_per_vb(
            Amount::from_sat(sat).map_err(|_| serde::de::Error::custom("amount out of range"))?,
        )
        .into_result()
        .map_err(|_| serde::de::Error::custom("fee rate too big for sats/vb"))
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per virtual byte.
        //!
        //! When serializing use floor division to convert per kwu to per virtual byte.
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_floor::opt")]`.

        use core::fmt;

        use serde::{de, Deserializer, Serializer};

        use crate::fee_rate::FeeRate;

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<S: Serializer>(f: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
            match *f {
                Some(f) => s.serialize_some(&f.to_sat_per_vb_floor()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<FeeRate>, D::Error> {
            struct VisitOpt;

            impl<'de> de::Visitor<'de> for VisitOpt {
                type Value = Option<FeeRate>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "an Option<u64>")
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
            d.deserialize_option(VisitOpt)
        }
    }
}

pub mod as_sat_per_vb_ceil {
    //! Serialize and deserialize [`FeeRate`] denominated in satoshis per virtual byte.
    //!
    //! When serializing use ceil division to convert per kwu to per virtual byte.
    //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_ceil")]`.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Amount, FeeRate};

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_vb_ceil(), s)
    }

    // Errors on overflow.
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        let sat = u64::deserialize(d)?;
        FeeRate::from_per_vb(
            Amount::from_sat(sat).map_err(|_| serde::de::Error::custom("amount out of range"))?,
        )
        .into_result()
        .map_err(|_| serde::de::Error::custom("fee rate too big for sats/vb"))
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per virtual byte.
        //!
        //! When serializing use ceil division to convert per kwu to per virtual byte.
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_ceil::opt")]`.

        use core::fmt;

        use serde::{de, Deserializer, Serializer};

        use crate::fee_rate::FeeRate;

        #[allow(clippy::ref_option)] // API forced by serde.
        pub fn serialize<S: Serializer>(f: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
            match *f {
                Some(f) => s.serialize_some(&f.to_sat_per_vb_ceil()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<FeeRate>, D::Error> {
            struct VisitOpt;

            impl<'de> de::Visitor<'de> for VisitOpt {
                type Value = Option<FeeRate>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "an Option<u64>")
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
            d.deserialize_option(VisitOpt)
        }
    }
}

/// Overflow occurred while deserializing fee rate per virtual byte.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OverflowError;

impl From<Infallible> for OverflowError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "overflow occurred while deserializing fee rate per virtual byte")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OverflowError {}
