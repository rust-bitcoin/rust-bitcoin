// SPDX-License-Identifier: CC0-1.0

//! Primitive hash wrapper types.
//!
//! Note: To print and parse these hash types enable the "hex" feature.

mod block_hash;
mod ntxid;
#[cfg(feature = "alloc")]
mod script_hash;
mod transaction_merkle_node;
mod txid;
mod witness_commitment;
mod witness_merkle_node;
#[cfg(feature = "alloc")]
mod witness_script_hash;
mod wtxid;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    block_hash::{BlockHash, BlockHashDecoder, BlockHashDecoderError, BlockHashEncoder},
    ntxid::Ntxid,
    transaction_merkle_node::{TxMerkleNode, TxMerkleNodeEncoder, TxMerkleNodeDecoder, TxMerkleNodeDecoderError},
    txid::{Txid},
    wtxid::Wtxid,
    witness_commitment::WitnessCommitment,
    witness_merkle_node::WitnessMerkleNode,
};
#[cfg(feature = "alloc")]
#[doc(inline)]
pub use self::{
    script_hash::{RedeemScriptSizeError, ScriptHash},
    witness_script_hash::{WScriptHash, WitnessScriptSizeError},
};

/// Adds trait impls to a bytelike type.
///
/// Implements:
///
/// * `AsRef[u8; $len]`
/// * `AsRef[u8]`
/// * `Borrow<[u8; $len]>`
/// * `Borrow<[u8]>`
///
/// # Parameters
///
/// * `ty` - the bytelike type to implement the traits on.
/// * `$len` - the number of bytes this type has.
/// * `$gen: $gent` - the generic type(s) and trait bound(s).
macro_rules! impl_bytelike_traits {
    ($ty:ident, $len:expr $(, $gen:ident: $gent:ident)*) => {
        impl $crate::_export::_core::convert::AsRef<[u8; { $len }]> for $ty {
            #[inline]
            fn as_ref(&self) -> &[u8; { $len }] { self.as_byte_array() }
        }

        impl $crate::_export::_core::convert::AsRef<[u8]> for $ty {
            #[inline]
            fn as_ref(&self) -> &[u8] { self.as_byte_array() }
        }

        impl $crate::_export::_core::borrow::Borrow<[u8; { $len }]> for $ty {
            fn borrow(&self) -> &[u8; { $len }] { self.as_byte_array() }
        }

        impl $crate::_export::_core::borrow::Borrow<[u8]> for $ty {
            fn borrow(&self) -> &[u8] { self.as_byte_array() }
        }
    };
}
pub(in crate::hash_types) use impl_bytelike_traits;

/// Implements `Serialize` and `Deserialize` for a hash wrapper type `$t`.
///
/// This is equivalent to `hashes::impl_serde_for_newtype` but does not rely on the wrapper type
/// implementing the `Hash` trait.
///
/// Requires `$t` to implement:
/// * `from_byte_array()`
/// * `as_byte_array()`
/// * `str::FromStr`
/// * `fmt::Display`
#[cfg(feature = "serde")]
macro_rules! impl_serde(
    ($t:ident, $len:expr) => (
        impl $crate::serde::Serialize for $t {
            fn serialize<S: $crate::serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    s.collect_str(self)
                } else {
                    s.serialize_bytes(self.as_byte_array())
                }
            }
        }

        impl<'de> $crate::serde::Deserialize<'de> for $t {
            fn deserialize<D: $crate::serde::Deserializer<'de>>(d: D) -> core::result::Result<$t, D::Error> {
                use $crate::hash_types::serde_details::{BytesVisitor, HexVisitor};

                if d.is_human_readable() {
                    d.deserialize_str(HexVisitor::<Self>::default())
                } else {
                    let bytes = d.deserialize_bytes(BytesVisitor::<$len>::default())?;
                    Ok(Self::from_byte_array(bytes))
                }
            }
        }
));
#[cfg(feature = "serde")]
pub(in crate::hash_types) use impl_serde;

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
    pub struct BytesVisitor<const N: usize>();

    impl<const N: usize> Default for BytesVisitor<N> {
        fn default() -> Self { Self() }
    }

    impl<const N: usize> de::Visitor<'_> for BytesVisitor<N> {
        type Value = [u8; N];

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

            Ok(bytes)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    const DUMMY_TXID_HEX_STR: &str =
        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389";

    // Creates an arbitrary dummy hash type object.
    #[cfg(feature = "serde")]
    fn dummy_test_case() -> Txid { DUMMY_TXID_HEX_STR.parse::<Txid>().unwrap() }

    #[cfg(feature = "alloc")]
    fn ab_test_case() -> (Txid, &'static str) {
        let mut a = [0xab; 32];
        a[0] = 0xff; // Just so we can see which way the array is printing.
        let tc = Txid::from_byte_array(a);
        let want = "abababababababababababababababababababababababababababababababff";

        (tc, want)
    }

    #[test]
    #[cfg(feature = "serde")] // Implies alloc and hex
    fn serde_human_readable_roundtrips() {
        let tc = dummy_test_case();
        let ser = serde_json::to_string(&tc).unwrap();
        let got = serde_json::from_str::<Txid>(&ser).unwrap();
        assert_eq!(got, tc);
    }

    #[test]
    #[cfg(feature = "serde")] // Implies alloc and hex
    fn serde_non_human_readable_roundtrips() {
        let tc = dummy_test_case();
        let ser = bincode::serialize(&tc).unwrap();
        let got = bincode::deserialize::<Txid>(&ser).unwrap();
        assert_eq!(got, tc);
    }

    #[test]
    // This is solely to test that we can debug print WITH and WITHOUT "hex" so its ok to require "alloc".
    #[cfg(feature = "alloc")]
    fn debug() {
        let (tc, want) = ab_test_case();
        let got = alloc::format!("{:?}", tc);
        assert_eq!(got, want);
    }

    #[test]
    fn as_ref_and_borrow_match_as_byte_array() {
        let tc = Txid::from_byte_array([0x11; 32]);

        let as_array: &[u8; 32] = tc.as_ref();
        let as_slice: &[u8] = tc.as_ref();
        let borrowed: &[u8; 32] = core::borrow::Borrow::<[u8; 32]>::borrow(&tc);

        assert_eq!(as_array, tc.as_byte_array());
        assert_eq!(borrowed, tc.as_byte_array());
        assert_eq!(as_slice, tc.as_byte_array());
    }
}
