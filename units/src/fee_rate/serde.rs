// SPDX-License-Identifier: CC0-1.0

// Module implements standardized serde-specific trait methods.
#![allow(missing_docs)]
#![allow(clippy::trivially_copy_pass_by_ref)]

//! This module adds serde serialization and deserialization support for amounts.
//!
//! Since there is not a default way to serialize and deserialize Amounts, multiple
//! ways are supported and it's up to the user to decide which serialiation to use.
//!
//! The provided modules can be used as follows:
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use bitcoin_units::FeeRate;
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct Foo {
//!     #[serde(with = "bitcoin_units::fee_rate::serde::as_sat_per_kwu")]
//!     pub fee_rate: FeeRate,
//! }
//! ```

use core::convert::Infallible;
use core::fmt;

pub mod as_sat_per_kwu {
    //! Serialize and deserialize [`FeeRate`] denominated in satoshis per 1000 weight units.
    //!
    //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_kwu")]`.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::FeeRate;

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_kwu(), s)
    }

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        Ok(FeeRate::from_sat_per_kwu(u64::deserialize(d)?))
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per 1000 weight units.
        //!
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_kwu::opt")]`.

        use core::fmt;

        use serde::{de, Deserialize, Deserializer, Serializer};

        use crate::FeeRate;

        pub fn serialize<S: Serializer>(f: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error> {
            match *f {
                Some(f) => s.serialize_some(&f.to_sat_per_kwu()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<FeeRate>, D::Error> {
            struct VisitOpt;

            impl<'de> de::Visitor<'de> for VisitOpt {
                type Value = Option<FeeRate>;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "An Option<FeeRate>")
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
                    Ok(Some(FeeRate::from_sat_per_kwu(u64::deserialize(d)?)))
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

    use crate::fee_rate::serde::OverflowError;
    use crate::fee_rate::FeeRate;

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_vb_floor(), s)
    }

    // Errors on overflow.
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        Ok(FeeRate::from_sat_per_vb(u64::deserialize(d)?)
            .ok_or(OverflowError)
            .map_err(serde::de::Error::custom)?)
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per virtual byte.
        //!
        //! When serializing use floor division to convert per kwu to per virtual byte.
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_floor::opt")]`.

        use core::fmt;

        use serde::{de, Deserialize, Deserializer, Serializer};

        use crate::fee_rate::serde::OverflowError;
        use crate::fee_rate::FeeRate;

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
                    write!(f, "An Option<FeeRate>")
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
                    Ok(Some(
                        FeeRate::from_sat_per_vb(u64::deserialize(d)?)
                            .ok_or(OverflowError)
                            .map_err(serde::de::Error::custom)?,
                    ))
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
    //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb")]`.

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::fee_rate::serde::OverflowError;
    use crate::fee_rate::FeeRate;

    pub fn serialize<S: Serializer>(f: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
        u64::serialize(&f.to_sat_per_vb_ceil(), s)
    }

    // Errors on overflow.
    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<FeeRate, D::Error> {
        Ok(FeeRate::from_sat_per_vb(u64::deserialize(d)?)
            .ok_or(OverflowError)
            .map_err(serde::de::Error::custom)?)
    }

    pub mod opt {
        //! Serialize and deserialize [`Option<FeeRate>`] denominated in satoshis per virtual byte.
        //!
        //! When serializing use ceil division to convert per kwu to per virtual byte.
        //! Use with `#[serde(with = "fee_rate::serde::as_sat_per_vb_ceil::opt")]`.

        use core::fmt;

        use serde::{de, Deserialize, Deserializer, Serializer};

        use crate::fee_rate::serde::OverflowError;
        use crate::fee_rate::FeeRate;

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
                    write!(f, "An Option<FeeRate>")
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
                    Ok(Some(
                        FeeRate::from_sat_per_vb(u64::deserialize(d)?)
                            .ok_or(OverflowError)
                            .map_err(serde::de::Error::custom)?,
                    ))
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
