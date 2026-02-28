// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.

mod borrowed;
mod owned;
mod tag;
#[cfg(test)]
mod tests;

use core::cmp::Ordering;
use core::fmt;
#[cfg(feature = "serde")]
use core::marker::PhantomData;

#[cfg(feature = "hex")]
use hex_unstable::DisplayHex;
use internals::script::{self, PushDataLenLen};

use crate::prelude::rc::Rc;
#[cfg(target_has_atomic = "ptr")]
use crate::prelude::sync::Arc;
use crate::prelude::{Borrow, BorrowMut, Box, Cow, ToOwned, Vec};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::{Script, ScriptEncoder},
    owned::{ScriptBuf, ScriptBufDecoder, ScriptBufDecoderError},
    tag::{Tag, RedeemScriptTag, ScriptPubKeyTag, ScriptSigTag, TapScriptTag, WitnessScriptTag},
};
#[doc(inline)]
pub use crate::hash_types::{
    RedeemScriptSizeError, ScriptHash, WScriptHash, WitnessScriptSizeError,
};

/// A P2SH redeem script.
pub type RedeemScriptBuf = ScriptBuf<RedeemScriptTag>;

/// A reference to a P2SH redeem script.
pub type RedeemScript = Script<RedeemScriptTag>;

/// A reference to a `scriptPubKey` (locking script).
pub type ScriptPubKey = Script<ScriptPubKeyTag>;

/// A reference to a script signature (scriptSig).
pub type ScriptSig = Script<ScriptSigTag>;

/// A `scriptPubKey` (locking script).
pub type ScriptPubKeyBuf = ScriptBuf<ScriptPubKeyTag>;

/// A `scriptPubKey` decoder.
pub type ScriptPubKeyBufDecoder = ScriptBufDecoder<ScriptPubKeyTag>;

/// A script signature (scriptSig).
pub type ScriptSigBuf = ScriptBuf<ScriptSigTag>;

/// A `scriptSig` decoder.
pub type ScriptSigBufDecoder = ScriptBufDecoder<ScriptSigTag>;

/// A Segwit v1 Taproot script.
pub type TapScriptBuf = ScriptBuf<TapScriptTag>;

/// A reference to a Segwit v1 Taproot script.
pub type TapScript = Script<TapScriptTag>;

/// A Segwit v0 witness script.
pub type WitnessScriptBuf = ScriptBuf<WitnessScriptTag>;

/// A reference to a Segwit v0 witness script.
pub type WitnessScript = Script<WitnessScriptTag>;

/// The maximum allowed redeem script size for a P2SH output.
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;
/// The maximum allowed redeem script size of the witness script.
pub const MAX_WITNESS_SCRIPT_SIZE: usize = 10_000;

/// Either a redeem script or a Segwit version 0 scriptpubkey.
///
/// In the case of P2SH-wrapped Segwit version outputs, we take a Segwit scriptPubKey
/// and put it in a redeem script slot. The Bitcoin script interpreter has special
/// logic to handle this case, which is reflected in our API in several methods
/// relating to P2SH and signature hashing. These methods take either a normal
/// P2SH redeem script, or a Segwit version 0 scriptpubkey.
///
/// Segwit version 1 (Taproot) and higher do **not** support P2SH-wrapping, and such
/// scriptPubKeys should not be used with this trait.
pub trait ScriptHashableTag: sealed::Sealed {}

impl ScriptHashableTag for RedeemScriptTag {}
impl ScriptHashableTag for ScriptPubKeyTag {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RedeemScriptTag {}
    impl Sealed for super::ScriptPubKeyTag {}
}

impl<T: ScriptHashableTag> TryFrom<ScriptBuf<T>> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: ScriptBuf<T>) -> Result<Self, Self::Error> {
        Self::from_script(&redeem_script)
    }
}

impl<T: ScriptHashableTag> TryFrom<&ScriptBuf<T>> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: &ScriptBuf<T>) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl<T: ScriptHashableTag> TryFrom<&Script<T>> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: &Script<T>) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl TryFrom<WitnessScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: WitnessScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&witness_script)
    }
}

impl TryFrom<&WitnessScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: &WitnessScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

impl TryFrom<&WitnessScript> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: &WitnessScript) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

// We keep all the `Script` and `ScriptBuf` impls together since it's easier to see side-by-side.

impl<T> From<ScriptBuf<T>> for Box<Script<T>> {
    #[inline]
    fn from(v: ScriptBuf<T>) -> Self { v.into_boxed_script() }
}

impl<T> From<ScriptBuf<T>> for Cow<'_, Script<T>> {
    #[inline]
    fn from(value: ScriptBuf<T>) -> Self { Cow::Owned(value) }
}

impl<'a, T> From<Cow<'a, Script<T>>> for ScriptBuf<T> {
    #[inline]
    fn from(value: Cow<'a, Script<T>>) -> Self {
        match value {
            Cow::Owned(owned) => owned,
            Cow::Borrowed(borrowed) => borrowed.into(),
        }
    }
}

impl<'a, T> From<Cow<'a, Script<T>>> for Box<Script<T>> {
    #[inline]
    fn from(value: Cow<'a, Script<T>>) -> Self {
        match value {
            Cow::Owned(owned) => owned.into(),
            Cow::Borrowed(borrowed) => borrowed.into(),
        }
    }
}

impl<'a, T> From<&'a Script<T>> for Box<Script<T>> {
    #[inline]
    fn from(value: &'a Script<T>) -> Self { value.to_owned().into() }
}

impl<'a, T> From<&'a Script<T>> for ScriptBuf<T> {
    #[inline]
    fn from(value: &'a Script<T>) -> Self { value.to_owned() }
}

impl<'a, T> From<&'a Script<T>> for Cow<'a, Script<T>> {
    #[inline]
    fn from(value: &'a Script<T>) -> Self { Cow::Borrowed(value) }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(target_has_atomic = "ptr")]
impl<'a, T> From<&'a Script<T>> for Arc<Script<T>> {
    #[inline]
    fn from(value: &'a Script<T>) -> Self { Script::from_arc_bytes(Arc::from(value.as_bytes())) }
}

impl<'a, T> From<&'a Script<T>> for Rc<Script<T>> {
    #[inline]
    fn from(value: &'a Script<T>) -> Self { Script::from_rc_bytes(Rc::from(value.as_bytes())) }
}

impl<T> From<Vec<u8>> for ScriptBuf<T> {
    #[inline]
    fn from(v: Vec<u8>) -> Self { Self::from_bytes(v) }
}

impl<T> From<ScriptBuf<T>> for Vec<u8> {
    #[inline]
    fn from(v: ScriptBuf<T>) -> Self { v.into_bytes() }
}

impl<T> AsRef<Self> for Script<T> {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}

impl<T> AsRef<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn as_ref(&self) -> &Script<T> { self }
}

impl<T> AsRef<[u8]> for Script<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl<T> AsRef<[u8]> for ScriptBuf<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl<T> AsMut<Self> for Script<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut Self { self }
}

impl<T> AsMut<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut Script<T> { self }
}

impl<T> AsMut<[u8]> for Script<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl<T> AsMut<[u8]> for ScriptBuf<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl<T> fmt::Debug for Script<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl<T> fmt::Debug for ScriptBuf<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(self.as_script(), f) }
}

impl<T> fmt::Display for Script<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // This has to be a macro because it needs to break the loop
        macro_rules! read_push_data_len {
            ($iter:expr, $size:path, $formatter:expr) => {
                match script::read_push_data_len($iter, $size) {
                    Ok(n) => n,
                    Err(_) => {
                        $formatter.write_str("<unexpected end>")?;
                        break;
                    }
                }
            };
        }

        let mut iter = self.as_bytes().iter();
        // Was at least one opcode emitted?
        let mut at_least_one = false;
        // `iter` needs to be borrowed in `read_push_data_len`, so we have to use `while let` instead
        // of `for`.
        while let Some(byte) = iter.next().copied() {
            use crate::opcodes::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};

            let data_len = if byte <= 75 {
                usize::from(byte)
            } else {
                match byte {
                    OP_PUSHDATA1 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::One, f)
                    }
                    OP_PUSHDATA2 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::Two, f)
                    }
                    OP_PUSHDATA4 => {
                        // side effects: may write and break from the loop
                        read_push_data_len!(&mut iter, PushDataLenLen::Four, f)
                    }
                    _ => 0,
                }
            };

            if at_least_one {
                f.write_str(" ")?;
            } else {
                at_least_one = true;
            }
            // Write the opcode
            crate::opcodes::fmt_opcode(byte, f)?;
            // Write any pushdata
            if data_len > 0 {
                f.write_str(" ")?;
                if data_len <= iter.len() {
                    for ch in iter.by_ref().take(data_len) {
                        write!(f, "{:02x}", ch)?;
                    }
                } else {
                    f.write_str("<push past end>")?;
                    break;
                }
            }
        }
        Ok(())
    }
}

impl<T> fmt::Display for ScriptBuf<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self.as_script(), f) }
}

#[cfg(feature = "hex")]
impl<T> fmt::LowerHex for Script<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl<T> fmt::LowerHex for ScriptBuf<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self.as_script(), f) }
}

#[cfg(feature = "hex")]
impl<T> fmt::UpperHex for Script<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl<T> fmt::UpperHex for ScriptBuf<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(self.as_script(), f) }
}

impl<T> Borrow<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn borrow(&self) -> &Script<T> { self }
}

impl<T> BorrowMut<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut Script<T> { self }
}

impl<T: PartialEq> PartialEq<ScriptBuf<T>> for Script<T> {
    #[inline]
    fn eq(&self, other: &ScriptBuf<T>) -> bool { self.eq(other.as_script()) }
}

impl<T: PartialEq> PartialEq<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn eq(&self, other: &Script<T>) -> bool { self.as_script().eq(other) }
}

impl<T: PartialOrd> PartialOrd<Script<T>> for ScriptBuf<T> {
    #[inline]
    fn partial_cmp(&self, other: &Script<T>) -> Option<Ordering> {
        self.as_script().partial_cmp(other)
    }
}

impl<T: PartialOrd> PartialOrd<ScriptBuf<T>> for Script<T> {
    #[inline]
    fn partial_cmp(&self, other: &ScriptBuf<T>) -> Option<Ordering> {
        self.partial_cmp(other.as_script())
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for Script<T> {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{:x}", self))
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

/// Can only deserialize borrowed bytes.
#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for &'de Script<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<T>(PhantomData<T>);
        impl<'de, T: 'de> serde::de::Visitor<'de> for Visitor<T> {
            type Value = &'de Script<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("borrowed bytes")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Script::from_bytes(v))
            }
        }

        if deserializer.is_human_readable() {
            use crate::serde::de::Error;

            return Err(D::Error::custom(
                "deserialization of `&Script` from human-readable formats is not possible",
            ));
        }

        deserializer.deserialize_bytes(Visitor(PhantomData))
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for ScriptBuf<T> {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for ScriptBuf<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        if deserializer.is_human_readable() {
            struct Visitor<T>(PhantomData<T>);
            impl<T> serde::de::Visitor<'_> for Visitor<T> {
                type Value = ScriptBuf<T>;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let v = hex::decode_to_vec(v).map_err(E::custom)?;
                    Ok(ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_str(Visitor(PhantomData))
        } else {
            struct BytesVisitor<T>(PhantomData<T>);

            impl<T> serde::de::Visitor<'_> for BytesVisitor<T> {
                type Value = ScriptBuf<T>;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script Vec<u8>")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from(v.to_vec()))
                }

                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_byte_buf(BytesVisitor(PhantomData))
        }
    }
}
