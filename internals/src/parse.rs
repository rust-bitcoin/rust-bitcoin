/// Support for parsing strings.

// Impls a single TryFrom conversion
#[doc(hidden)]
#[macro_export]
macro_rules! impl_try_from_stringly {
    ($from:ty, $to:ty, $error:ty, $func:expr) => {
        $(#[$attr])?
        impl core::convert::TryFrom<$from> for $to {
            type Error = $error;

            fn try_from(s: $from) -> Result<Self, Self::Error> {
                $func(AsRef::<str>::as_ref(s)).map_err(|source| <$error>::new(s, source))
            }
        }

    }
}

/// Implements conversions from various string types.
///
/// This macro implements `FromStr` as well as `TryFrom<{stringly}` where `{stringly}` is one of
/// these types:
///
/// * `&str`
/// * `String`
/// * `Box<str>`
/// * `Cow<'_, str>`
///
/// The last three are only available with `alloc` feature turned on.
#[macro_export]
macro_rules! impl_parse {
    ($type:ty, $descr:expr, $func:expr, $vis:vis $error:ident, $error_source:ty $(, $error_derive:path)*) => {
        $crate::parse_error_type!($vis $error, $error_source, $descr $(, $error_derive)*);

        impl core::str::FromStr for $type {
            type Err = $error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $func(s).map_err(|source| <$error>::new(s, source))
            }
        }

        impl_try_from_stringly!(&str);

        #[cfg(feature = "alloc")]
        impl_try_from_stringly!(alloc::string::String, $type, $error, $func);
        #[cfg(feature = "alloc")]
        impl_try_from_stringly!(alloc::borrow::Cow<'_, str>, $type, $error, $func);
        #[cfg(feature = "alloc")]
        impl_try_from_stringly!(alloc::boxed::Box<str>, $type, $error, $func);
    }
}

/// Implements conversions from various string types as well as `serde` (de)serialization.
///
/// This calls `impl_parse` macro and implements serde deserialization by expecting and parsing a
/// string and serialization by outputting a string.
#[macro_export]
macro_rules! impl_parse_and_serde {
    ($type:ty, $descr:expr, $func:expr, $error:ident, $error_source:ty $(, $error_derive:path)*) => {
        impl_parse!($type, $descr, $func, $error, $error_source $(, $error_derive)*);

        // We don't use `serde_string_impl` because we want to avoid allocating input.
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use core::fmt::{self, Formatter};
                use core::str::FromStr;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                        f.write_str($descr)
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        s.parse().map_err(|error| {
                            $crate::serde::IntoDeError::try_into_de_error(error)
                                .unwrap_or_else(|_| E::invalid_value(Unexpected::Str(s), &self))
                        })
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    }
}
