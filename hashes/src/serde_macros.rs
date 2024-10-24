// SPDX-License-Identifier: CC0-1.0

//! Macros for serde trait implementations, and supporting code.

/// Functions used by serde impls of all hashes.
#[cfg(feature = "serde")]
pub mod serde_details {
    use core::marker::PhantomData;
    use core::str::FromStr;
    use core::{fmt, str};

    use serde::de;

    /// Type used to implement serde traits for hashes as hex strings.
    pub struct HexVisitor<ValueT>(PhantomData<ValueT>);

    impl<ValueT> Default for HexVisitor<ValueT> {
        fn default() -> Self { Self(PhantomData) }
    }

    impl<ValueT> de::Visitor<'_> for HexVisitor<ValueT>
    where
        ValueT: FromStr,
        <ValueT as FromStr>::Err: fmt::Display,
    {
        type Value = ValueT;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an ASCII hex string")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            if let Ok(hex) = str::from_utf8(v) {
                hex.parse::<Self::Value>().map_err(E::custom)
            } else {
                Err(E::invalid_value(de::Unexpected::Bytes(v), &self))
            }
        }

        fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<Self::Value>().map_err(E::custom)
        }
    }

    /// Type used to implement serde traits for hashes as bytes.
    pub struct BytesVisitor<ValueT, const N: usize>(PhantomData<ValueT>);

    impl<ValueT, const N: usize> Default for BytesVisitor<ValueT, N> {
        fn default() -> Self { Self(PhantomData) }
    }

    impl<ValueT, const N: usize> de::Visitor<'_> for BytesVisitor<ValueT, N>
    where
        ValueT: crate::Hash,
        ValueT: crate::Hash<Bytes = [u8; N]>,
    {
        type Value = ValueT;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a bytestring")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = <[u8; N]>::try_from(v).map_err(|_| {
                // from_slice only errors on incorrect length
                E::invalid_length(v.len(), &stringify!(N))
            })?;

            Ok(<Self::Value as crate::Hash>::from_byte_array(bytes))
        }
    }
}

/// Implements `Serialize` and `Deserialize` for a type `$t` which
/// represents a newtype over a byte-slice over length `$len`.
#[macro_export]
#[cfg(feature = "serde")]
macro_rules! serde_impl(
    ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => (
        impl<$($gen: $gent),*> $crate::serde::Serialize for $t<$($gen),*> {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(<Self as $crate::Hash>::as_byte_array(self))
                }
            }
        }

        impl<'de $(, $gen: $gent)*> $crate::serde::Deserialize<'de> for $t<$($gen),*> {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> core::result::Result<$t<$($gen),*>, D::Error> {
                use $crate::serde_macros::serde_details::{BytesVisitor, HexVisitor};

                if d.is_human_readable() {
                    d.deserialize_str(HexVisitor::<Self>::default())
                } else {
                    d.deserialize_bytes(BytesVisitor::<Self, $len>::default())
                }
            }
        }
));

/// Does an "empty" serde implementation for the configuration without serde feature.
#[macro_export]
#[cfg(not(feature = "serde"))]
macro_rules! serde_impl(
        ($t:ident, $len:expr $(, $gen:ident: $gent:ident)*) => ()
);
