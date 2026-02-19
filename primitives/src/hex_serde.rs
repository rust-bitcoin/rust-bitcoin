// SPDX-License-Identifier: CC0-1.0

// methods are implementation of a standardized serde-specific signature
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

//! Generic serde serialization and deserialization support for types implementing
//! [`Encodable`] and [`Decodable`].
//!
//! # Examples
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use bitcoin_primitives::block::Header;
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct MyStruct {
//!     // Serialize as hex when using human-readable formats (JSON, etc.)
//!     #[serde(with = "bitcoin_primitives::hex_serde::as_consensus")]
//!     pub header: Header,
//! }
//! ```

use core::fmt;

use encoding::{Decodable, Encodable};

/// Serialize and deserialize types as consensus-encoded hex strings.
///
/// Use with `#[serde(with = "bitcoin_primitives::hex_serde::as_consensus")]`.
///
/// This module works with any type `T` that implements both [`Encodable`] and [`Decodable`].
/// In human-readable formats (like JSON), the value is serialized as a hex string.
/// In non-human-readable formats (like bincode), raw bytes are used.
pub mod as_consensus {
    use core::marker::PhantomData;

    use serde::{Deserializer, Serialize, Serializer};

    use super::*;

    /// Serializes a type as a consensus-encoded hex string.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to serialize, must implement [`Encodable`] and [`Decodable`]
    /// * `S` - The serializer type
    pub fn serialize<T, S>(value: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: Encodable + Decodable,
        S: Serializer,
    {
        if s.is_human_readable() {
            // TODO: Try to do this without allocation.
            let hex = alloc::format!("{}", crate::hex_codec::HexPrimitive(value));
            str::serialize(&hex, s)
        } else {
            // For non-human-readable formats, serialize as bytes.
            let bytes = encoding::encode_to_vec(value);
            s.serialize_bytes(&bytes)
        }
    }

    /// Deserializes a type from a consensus-encoded hex string.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize, must implement [`Encodable`] and [`Decodable`]
    /// * `D` - The deserializer type
    pub fn deserialize<'d, T, D>(d: D) -> Result<T, D::Error>
    where
        T: Encodable + Decodable + core::str::FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'d>,
    {
        if d.is_human_readable() {
            use alloc::string::String;
            use serde::Deserialize;

            // TODO: Try to do this without allocation.
            let hex_str = String::deserialize(d)?;
            T::from_str(&hex_str).map_err(serde::de::Error::custom)
        } else {
            // For non-human-readable formats, deserialize from bytes
            struct BytesVisitor<T>(PhantomData<T>);

            impl<'de, T> serde::de::Visitor<'de> for BytesVisitor<T>
            where
                T: Encodable + Decodable,
            {
                type Value = T;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a byte array")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    encoding::decode_from_slice(v)
                        .map_err(|_| serde::de::Error::custom("failed to decode from bytes"))
                }

                fn visit_byte_buf<E>(self, v: alloc::vec::Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    encoding::decode_from_slice(&v)
                        .map_err(|_| serde::de::Error::custom("failed to decode from bytes"))
                }
            }

            d.deserialize_bytes(BytesVisitor(PhantomData))
        }
    }
}
