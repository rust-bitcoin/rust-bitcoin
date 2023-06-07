//! Contains extensions of `serde` and internal reexports.

#[cfg(feature = "serde")]
#[doc(hidden)]
pub use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

/// Converts given error type to a type implementing [`de::Error`].
///
/// This is used in [`Deserialize`] implementations to convert specialized errors into serde
/// errors.
#[cfg(feature = "serde")]
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

#[cfg(feature = "serde")]
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

        #[cfg(rust_v_1_55)]
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

        #[cfg(not(rust_v_1_55))]
        fn try_into_de_error<E>(self, _expected: Option<&dyn de::Expected>) -> Result<E, Self>
        where
            E: de::Error,
        {
            Err(self)
        }
    }
}
