// SPDX-License-Identifier: CC0-1.0

//! Bitcoin serde utilities.
//!
//! This module is for special serde serializations.

#![allow(unused_imports)] // TODO: Remove this.

pub(crate) struct SerializeBytesAsHex<'a>(pub(crate) &'a [u8]);

impl<'a> serde::Serialize for SerializeBytesAsHex<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use hex::DisplayHex;

        serializer.collect_str(&format_args!("{:x}", self.0.as_hex()))
    }
}

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

macro_rules! serde_string_impl {
    ($name:ty, $expecting:literal) => {
        $crate::serde_utils::serde_string_deserialize_impl!($name, $expecting);
        $crate::serde_utils::serde_string_serialize_impl!($name, $expecting);
    };
}
pub(crate) use {serde_string_deserialize_impl, serde_string_impl, serde_string_serialize_impl};

/// A combination macro where the human-readable serialization is done like
/// serde_string_impl and the non-human-readable impl is done as a struct.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:literal, $($fe:ident),*) => (
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> core::result::Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    use core::fmt::Formatter;
                    use core::str::FromStr;

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
                            $name::from_str(v).map_err(E::custom)
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
pub(crate) use serde_struct_human_string_impl;
