// SPDX-License-Identifier: CC0-1.0

//! Bitcoin serde utilities.
//!
//! This module is for special serde serializations.

macro_rules! serde_string_deserialize_impl {
    ($name:ty, $expecting:literal) => {
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> core::result::Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use core::fmt::Formatter;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        v.parse::<$name>().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}
pub(crate) use serde_string_deserialize_impl;
