// SPDX-License-Identifier: CC0-1.0

// Methods are an implementation of a standardized serde-specific signature.
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

//! `serde` serialize and deserialize types using consensus encoding.
//!
//! Use with `#[serde(with = "bitcoin_primitives::serde_as_consensus")]`.
//!
//! This module works with any type `T` that implements both [`Encode`] and [`Decode`].
//! In human-readable formats (like JSON), the value is serialized as a hex string.
//! In non-human-readable formats (like bincode), raw bytes are used.
//!
//! # Examples
//!
//! ```
//! use serde::{Serialize, Deserialize};
//! use bitcoin_primitives::block::{Block, Header, Unchecked};
//! use bitcoin_primitives::TxOut;
//!
//! #[derive(Serialize, Deserialize)]
//! pub struct MyStruct {
//!     // Serialize as hex when using human-readable formats (JSON, etc.)
//!     #[serde(with = "bitcoin_primitives::serde_as_consensus")]
//!     pub header: Header,
//!     // We support options too.
//!     #[serde(with = "bitcoin_primitives::serde_as_consensus::opt")]
//!     pub block: Option<Block<Unchecked>>,
//!     // And we support vectors.
//!     #[serde(with = "bitcoin_primitives::serde_as_consensus::vec")]
//!     pub tx_outs: Vec<TxOut>,
//! }
//! ```

use core::fmt;
use core::marker::PhantomData;

use encoding::{Decode, Encode};
use serde::{de, Deserializer, Serializer};

use crate::hex_codec::HexPrimitive;

/// Serializes a type as a consensus-encoded hex string.
///
/// # Type Parameters
///
/// * `T` - The type to serialize, must implement [`Encode`] and [`Decode`]
/// * `S` - The serializer type
pub fn serialize<T, S>(value: &T, s: S) -> Result<S::Ok, S::Error>
where
    T: Encode + Decode,
    S: Serializer,
{
    if s.is_human_readable() {
        // `HexPrimitive` uses `LowerHex` for `Display`.
        s.collect_str(&crate::hex_codec::HexPrimitive(value))
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
/// * `T` - The type to deserialize, must implement [`Encode`] and [`Decode`]
/// * `D` - The deserializer type
pub fn deserialize<'d, T, D>(d: D) -> Result<T, D::Error>
where
    T: Encode + Decode,
    D: Deserializer<'d>,
{
    if d.is_human_readable() {
        use alloc::string::String;

        use serde::Deserialize;

        let hex_str = String::deserialize(d)?;
        HexPrimitive::<T>::from_str(&hex_str).map_err(de::Error::custom)
    } else {
        // For non-human-readable formats, deserialize from bytes
        struct BytesVisitor<T>(PhantomData<T>);

        impl<'de, T> serde::de::Visitor<'de> for BytesVisitor<T>
        where
            T: Encode + Decode,
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

pub mod opt {
    //! `serde` serialize and deserialize `Option<T>`.
    //!
    //! **WARNING:**
    //!
    //! This module is specifically for using `serde` to be able to serialize any object that is
    //! `Encode`/`Decode` if said object is in an `Option`.
    //!
    //! Use with `#[serde(with = "bitcoin_primitives::serde_as_consensus::opt")]`.

    use core::fmt;
    use core::marker::PhantomData;

    use encoding::{Decode, Encode};
    use serde::{de, Deserializer, Serializer};

    #[allow(clippy::ref_option)] // API forced by serde.
    pub fn serialize<T, S>(t: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        T: Encode + Decode,
        S: Serializer,
    {
        struct AsConsensus<'a, T>(&'a T);

        impl<T: Encode + Decode> serde::Serialize for AsConsensus<'_, T> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                super::serialize(self.0, s)
            }
        }

        match *t {
            Some(ref t) => s.serialize_some(&AsConsensus(t)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'d, T, D>(d: D) -> Result<Option<T>, D::Error>
    where
        T: Encode + Decode,
        D: Deserializer<'d>,
    {
        struct OptVisitor<X>(PhantomData<X>);

        impl<'de, X> de::Visitor<'de> for OptVisitor<X>
        where
            X: Encode + Decode,
        {
            type Value = Option<X>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an Option<T> where T: encoding::Decode")
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
        d.deserialize_option(OptVisitor::<T>(PhantomData))
    }
}

pub mod vec {
    //! `serde` serialize and deserialize `Vec<T>`.
    //!
    //! **WARNING:**
    //!
    //! This is not a consensus encoded vector (i.e, with length prefix). This module is
    //! specifically for using `serde` to be able to serialize any object that is
    //! `Encode`/`Decode` if said object is in a `Vec`.
    //!
    //! Use with `#[serde(with = "bitcoin_primitives::serde_as_consensus::vec")]`.

    use alloc::vec::Vec;
    use core::fmt;
    use core::marker::PhantomData;

    use encoding::{Decode, Encode};
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<T, S>(v: &[T], s: S) -> Result<S::Ok, S::Error>
    where
        T: Encode + Decode,
        S: Serializer,
    {
        struct AsConsensus<'a, T>(&'a T);

        impl<T: Encode + Decode> serde::Serialize for AsConsensus<'_, T> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                super::serialize(self.0, s)
            }
        }

        s.collect_seq(v.iter().map(|item| AsConsensus(item)))
    }

    pub fn deserialize<'d, T, D>(d: D) -> Result<Vec<T>, D::Error>
    where
        T: Encode + Decode,
        D: Deserializer<'d>,
    {
        struct VecVisitor<X>(PhantomData<X>);

        impl<'de, X> de::Visitor<'de> for VecVisitor<X>
        where
            X: Encode + Decode,
        {
            type Value = Vec<X>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a sequence of consensus-encodable items")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                struct Wrap<X>(X);

                impl<'de, X> de::Deserialize<'de> for Wrap<X>
                where
                    X: Encode + Decode,
                {
                    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                        super::deserialize::<X, D>(d).map(Wrap)
                    }
                }

                let mut out = Vec::new();
                while let Some(Wrap(item)) = seq.next_element::<Wrap<X>>()? {
                    out.push(item);
                }
                Ok(out)
            }
        }

        d.deserialize_seq(VecVisitor::<T>(PhantomData))
    }
}
