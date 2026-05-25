//! Contains extensions of `serde` and internal reexports.

#[doc(hidden)]
pub use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

/// Implements `serde::Serialize` by way of `Display`.
///
/// `$name` is required to implement `core::fmt::Display`.
#[macro_export]
macro_rules! serde_string_serialize_impl {
    ($name:ty, $expecting:literal) => {
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

/// Implements `serde::Deserialize` by way of `FromStr`.
///
/// `$name` is required to implement `core::str::FromStr`.
#[macro_export]
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

/// Implements `serde::Serialize` and `Deserialize` by way of `Display` and `FromStr` respectively.
///
/// `$name` is required to implement `core::fmt::Display` and `core::str::FromStr`.
#[macro_export]
macro_rules! serde_string_impl {
    ($name:ty, $expecting:literal) => {
        $crate::serde_string_deserialize_impl!($name, $expecting);
        $crate::serde_string_serialize_impl!($name, $expecting);
    };
}
