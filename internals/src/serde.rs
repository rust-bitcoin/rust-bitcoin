//! Contains extensions of `serde` and internal reexports.

#[doc(hidden)]
pub use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

/// Converts given error type to a type implementing [`de::Error`].
///
/// This is used in [`Deserialize`] implementations to convert specialized errors into serde
/// errors.
pub trait IntoDeError: Sized {
    /// Converts to deserializer error possibly outputting vague message.
    ///
    /// This method is allowed to return a vague error message if the error type doesn't contain
    /// enough information to explain the error precisely.
    fn into_de_error<E: de::Error>(self, expected: Option<&dyn de::Expected>) -> E;

    /// Converts to deserializer error without outputting vague message.
    ///
    /// If the error type doesn't contain enough information to explain the error precisely this
    /// should return `Err(self)` allowing the caller to use its information instead.
    fn try_into_de_error<E>(self, expected: Option<&dyn de::Expected>) -> Result<E, Self>
    where
        E: de::Error,
    {
        Ok(self.into_de_error(expected))
    }
}

mod impls {
    use super::*;

    impl IntoDeError for core::convert::Infallible {
        fn into_de_error<E: de::Error>(self, _expected: Option<&dyn de::Expected>) -> E {
            match self {}
        }
    }

    impl IntoDeError for core::num::ParseIntError {
        fn into_de_error<E: de::Error>(self, expected: Option<&dyn de::Expected>) -> E {
            self.try_into_de_error(expected).unwrap_or_else(|_| {
                let expected = expected.unwrap_or(&"an integer");

                E::custom(format_args!("invalid string, expected {}", expected))
            })
        }

        fn try_into_de_error<E>(self, expected: Option<&dyn de::Expected>) -> Result<E, Self>
        where
            E: de::Error,
        {
            use core::num::IntErrorKind::Empty;

            let expected = expected.unwrap_or(&"an integer");

            match self.kind() {
                Empty => Ok(E::invalid_value(de::Unexpected::Str(""), expected)),
                _ => Err(self),
            }
        }
    }
}

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

/// A combination macro where the human-readable serialization is done like
/// serde_string_impl and the non-human-readable impl is done as a struct.
#[macro_export]
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:literal, $($fe:ident),*) => (
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> core::result::Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
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
                } else {
                    use core::fmt::Formatter;
                    use $crate::serde::de::IgnoredAny;

                    #[allow(non_camel_case_types)]
                    enum Enum { Unknown__Field, $($fe),* }

                    struct EnumVisitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                        type Value = Enum;

                        fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                            f.write_str("a field name")
                        }

                        fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            match v {
                                $(
                                stringify!($fe) => Ok(Enum::$fe)
                                ),*,
                                _ => Ok(Enum::Unknown__Field)
                            }
                        }
                    }

                    impl<'de> $crate::serde::Deserialize<'de> for Enum {
                        fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
                        where
                            D: $crate::serde::de::Deserializer<'de>,
                        {
                            deserializer.deserialize_str(EnumVisitor)
                        }
                    }

                    struct Visitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                            f.write_str("a struct")
                        }

                        fn visit_seq<V>(self, mut seq: V) -> core::result::Result<Self::Value, V::Error>
                        where
                            V: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            let length = 0;
                            $(
                                let $fe = seq.next_element()?.ok_or_else(|| {
                                    Error::invalid_length(length, &self)
                                })?;
                                #[allow(unused_variables)]
                                let length = length + 1;
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }

                        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
                        where
                            A: $crate::serde::de::MapAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            $(let mut $fe = None;)*

                            loop {
                                match map.next_key::<Enum>()? {
                                    Some(Enum::Unknown__Field) => {
                                        map.next_value::<IgnoredAny>()?;
                                    }
                                    $(
                                        Some(Enum::$fe) => {
                                            $fe = Some(map.next_value()?);
                                        }
                                    )*
                                    None => { break; }
                                }
                            }

                            $(
                                let $fe = match $fe {
                                    Some(x) => x,
                                    None => return Err(A::Error::missing_field(stringify!($fe))),
                                };
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }
                    }
                    // end type defs

                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
                }
            }
        }

        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
                    use $crate::serde::ser::SerializeStruct;

                    // Only used to get the struct length.
                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                    $(
                        st.serialize_field(stringify!($fe), &self.$fe)?;
                    )*

                    st.end()
                }
            }
        }
    )
}

/// Does round trip test to/from serde value.
#[cfg(feature = "test-serde")]
#[macro_export]
macro_rules! serde_round_trip (
    ($var:expr) => ({
        use serde_json;

        let encoded = $crate::serde_json::to_value(&$var).expect("serde_json failed to encode");
        let decoded = $crate::serde_json::from_value(encoded).expect("serde_json failed to decode");
        assert_eq!($var, decoded);

        let encoded = $crate::bincode::serialize(&$var).expect("bincode failed to encode");
        let decoded = $crate::bincode::deserialize(&encoded).expect("bincode failed to decode");
        assert_eq!($var, decoded);
    })
);
