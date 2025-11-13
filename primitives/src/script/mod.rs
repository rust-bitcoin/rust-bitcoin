// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.

mod borrowed;
mod owned;
mod tag;

// FIXME: These should probably be private but `witness_program::MAX_SIZE`
// doesn't work without the module name and also the error types.
pub mod witness_program;
pub mod witness_version;

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
    witness_program::WitnessProgram,
    witness_version::WitnessVersion,
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::{format, vec};

    use hashes::{hash160, sha256};

    use super::*;

    // All tests should compile and pass no matter which script type you put here.
    type Script = ScriptSig;
    type ScriptBuf = ScriptSigBuf;

    #[test]
    fn scriptbuf_from_vec_u8() {
        let vec = vec![0x51, 0x52, 0x53];
        let script_buf: ScriptBuf = vec.clone().into();
        let result: Vec<u8> = script_buf.into();
        assert_eq!(result, vec);
    }

    #[test]
    fn scriptbuf_as_ref() {
        let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let script_ref: &[u8] = script_buf.as_ref();
        assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

        let script_ref: &Script = script_buf.as_ref();
        assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn scriptbuf_as_mut() {
        let mut script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);

        let script_mut: &mut [u8] = script_buf.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);

        let script_mut: &mut Script = script_buf.as_mut();
        script_mut.as_mut_bytes()[1] = 0x51;
        assert_eq!(script_buf.as_bytes(), &[0x50, 0x51, 0x53]);
    }

    #[test]
    fn scriptbuf_borrow_mut() {
        let mut script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let script_mut: &mut Script = script_buf.borrow_mut();
        script_mut.as_mut_bytes()[0] = 0x50;

        assert_eq!(script_buf.as_bytes(), &[0x50, 0x52, 0x53]);
    }

    #[test]
    #[allow(clippy::useless_asref)]
    fn script_as_ref() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let script_ref: &[u8] = script.as_ref();
        assert_eq!(script_ref, &[0x51, 0x52, 0x53]);

        let script_ref: &Script = script.as_ref();
        assert_eq!(script_ref.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    #[allow(clippy::useless_asref)]
    fn script_as_mut() {
        let bytes = &mut [0x51, 0x52, 0x53];
        let script = Script::from_bytes_mut(bytes);

        let script_mut: &mut [u8] = script.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);

        let script_mut: &mut Script = script.as_mut();
        script_mut.as_mut_bytes()[1] = 0x51;
        assert_eq!(script.as_bytes(), &[0x50, 0x51, 0x53]);
    }

    #[test]
    fn partial_ord() {
        let script_small = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let script_big = Script::from_bytes(&[0x54, 0x55, 0x56]);
        let script_buf_small = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let script_buf_big = ScriptBuf::from(vec![0x54, 0x55, 0x56]);

        assert!(script_small == &script_buf_small);
        assert!(script_buf_small == *script_small);
        assert!(script_small != &script_buf_big);
        assert!(script_buf_small != *script_big);

        assert!(script_small < &script_buf_big);
        assert!(script_buf_small < *script_big);
        assert!(script_big > &script_buf_small);
        assert!(script_buf_big > *script_small);
    }

    #[test]
    fn script_hash_from_script() {
        let script = RedeemScript::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::from_script(script).is_ok());

        let script = RedeemScript::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::from_script(script).is_err());
    }

    #[test]
    fn script_hash_from_script_unchecked() {
        let script = WitnessScript::from_bytes(&[0x51; 521]);

        let got = ScriptHash::from_script_unchecked(script);
        let want =
            ScriptHash::from_byte_array(hash160::Hash::hash(script.as_bytes()).to_byte_array());

        assert_eq!(got, want);
    }

    #[test]
    fn wscript_hash_from_script() {
        let script = WitnessScript::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::from_script(script).is_ok());

        let script = WitnessScript::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::from_script(script).is_err());
    }

    #[test]
    fn wscript_hash_from_script_unchecked() {
        let script = WitnessScript::from_bytes(&[0x51; 10_001]);

        let got = WScriptHash::from_script_unchecked(script);
        let want =
            WScriptHash::from_byte_array(sha256::Hash::hash(script.as_bytes()).to_byte_array());

        assert_eq!(got, want);
    }

    #[test]
    fn try_from_scriptpubkeybuf_for_scripthash() {
        let script = ScriptPubKeyBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = ScriptPubKeyBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptpubkeybuf_ref_for_scripthash() {
        let script = ScriptPubKeyBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(&script).is_ok());

        let script = ScriptPubKeyBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(&script).is_err());
    }

    #[test]
    fn try_from_script_for_scripthash() {
        let script = RedeemScript::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = RedeemScript::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_for_wscript_hash() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_ref_for_wscript_hash() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(&script).is_ok());

        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(&script).is_err());
    }

    #[test]
    fn try_from_script_for_wscript_hash() {
        let script = WitnessScript::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = WitnessScript::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn script_display() {
        let script = Script::from_bytes(&[0x00, 0xa1, 0xb2]);
        assert_eq!(format!("{}", script), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script), "00a1b2");
            assert_eq!(format!("{:X}", script), "00A1B2");
        }
        assert!(!format!("{:?}", script).is_empty());
    }

    #[test]
    fn script_display_pushdata() {
        // OP_PUSHDATA1
        let script = Script::from_bytes(&[0x4c, 0x02, 0xab, 0xcd]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA1 abcd");

        // OP_PUSHDATA2
        let script = Script::from_bytes(&[0x4d, 0x02, 0x00, 0x12, 0x34]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA2 1234");

        // OP_PUSHDATA4
        let script = Script::from_bytes(&[0x4e, 0x02, 0x00, 0x00, 0x00, 0x56, 0x78]);
        assert_eq!(format!("{}", script), "OP_PUSHDATA4 5678");
    }

    #[test]
    fn scriptbuf_display() {
        let script_buf = ScriptBuf::from(vec![0x00, 0xa1, 0xb2]);
        assert_eq!(format!("{}", script_buf), "OP_0 OP_LESSTHANOREQUAL OP_CSV");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script_buf), "00a1b2");
            assert_eq!(format!("{:X}", script_buf), "00A1B2");
        }
        assert!(!format!("{:?}", script_buf).is_empty());
    }

    #[test]
    fn cow_script_to_scriptbuf() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let cow_borrowed: Cow<Script> = Cow::Borrowed(script);
        let script_buf: ScriptBuf = cow_borrowed.into();
        assert_eq!(script_buf.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn cow_scriptbuf_to_script() {
        let cow_owned: Cow<Script> = Cow::Owned(ScriptBuf::from(vec![0x51, 0x52, 0x53]));
        let script: &Script = cow_owned.borrow();
        assert_eq!(script.as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn cow_scriptbuf_to_box_script() {
        let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<Script> = Cow::Owned(script_buf.clone());
        let boxed_script: Box<Script> = cow_owned.into();
        let script_buf2 = boxed_script.into_script_buf();
        assert_eq!(script_buf2, script_buf);
    }

    #[test]
    fn cow_owned_to_scriptbuf() {
        let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<Script> = Cow::Owned(script_buf.clone());
        let script_buf_2: ScriptBuf = cow_owned.into();
        assert_eq!(script_buf_2, script_buf);
    }

    #[test]
    fn cow_script_to_box_script() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let cow_borrowed: Cow<Script> = Cow::Borrowed(script);
        let boxed_script: Box<Script> = cow_borrowed.into();
        assert_eq!(boxed_script.as_bytes(), &[0x51, 0x52, 0x53]);

        let cow_owned: Cow<Script> = Cow::from(script.to_owned());
        assert_eq!(cow_owned.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);

        let cow_from_script: Cow<Script> = Cow::from(script);
        assert_eq!(cow_from_script.as_ref().as_bytes(), &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn redeem_script_size_error() {
        let script = RedeemScriptBuf::from(vec![0x51; 521]);
        let result = ScriptHash::try_from(script);

        let err = result.unwrap_err();
        assert_eq!(err.invalid_size(), 521);

        let err_msg = format!("{}", err);
        assert!(err_msg.contains("521"));
    }

    #[test]
    fn witness_script_size_error() {
        let script = WitnessScriptBuf::from(vec![0x51; 10_001]);
        let result = WScriptHash::try_from(script);

        let err = result.unwrap_err();
        assert_eq!(err.invalid_size(), 10_001);

        let err_msg = format!("{}", err);
        assert!(err_msg.contains("10001"));
    }

    #[test]
    #[cfg(target_has_atomic = "ptr")]
    fn script_to_arc() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let arc_script: Arc<Script> = Arc::from(script);

        assert_eq!(arc_script.as_bytes(), script.as_bytes());
        assert_eq!(Arc::strong_count(&arc_script), 1);
    }

    #[test]
    fn script_to_rc() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let rc_script: Rc<Script> = Rc::from(script);

        assert_eq!(rc_script.as_bytes(), script.as_bytes());
        assert_eq!(Rc::strong_count(&rc_script), 1);
    }

    #[test]
    fn pushdata_end_conditions() {
        let push_past_end_script = Script::from_bytes(&[0x4c, 0x02]);
        let formatted_script = format!("{}", push_past_end_script);
        assert!(formatted_script.contains("<push past end>"));

        let unexpected_end_script = Script::from_bytes(&[0x4c]);
        let formatted_script = format!("{}", unexpected_end_script);
        assert!(formatted_script.contains("<unexpected end>"));
    }

    #[test]
    fn legacy_opcode() {
        let script = Script::from_bytes(&[0x03, 0xaa, 0xbb, 0xcc]);
        assert_eq!(format!("{}", script), "OP_PUSHBYTES_3 aabbcc");
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn script_to_hex() {
        let script = Script::from_bytes(&[0xa1, 0xb2, 0xc3]);
        let hex = alloc::format!("{script:x}");
        assert_eq!(hex, "a1b2c3");
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    fn scriptbuf_to_hex() {
        let script = ScriptBuf::from_bytes(vec![0xa1, 0xb2, 0xc3]);
        let hex = alloc::format!("{script:x}");
        assert_eq!(hex, "a1b2c3");
    }
}
