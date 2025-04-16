// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.

mod borrowed;
mod owned;

use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;

use hashes::{hash160, sha256};
#[cfg(feature = "hex")]
use hex::DisplayHex;
use internals::script::{self, PushDataLenLen};

#[allow(clippy::wildcard_imports)]
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::prelude::rc::Rc;
#[cfg(target_has_atomic = "ptr")]
use crate::prelude::sync::Arc;
use crate::prelude::{Borrow, BorrowMut, Box, Cow, ToOwned, Vec};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::Script,
    owned::ScriptBuf,
};

/// The maximum allowed redeem script size for a P2SH output.
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;
/// The maximum allowed redeem script size of the witness script.
pub const MAX_WITNESS_SCRIPT_SIZE: usize = 10_000;

hashes::hash_newtype! {
    /// A 160-bit hash of Bitcoin Script bytecode.
    ///
    /// Note: there is another "script hash" object in bitcoin ecosystem (Electrum protocol) that
    /// uses 256-bit hash and hashes a semantically different script. Thus, this type cannot
    /// represent it.
    pub struct ScriptHash(hash160::Hash);

    /// SegWit (256-bit) version of a Bitcoin Script bytecode hash.
    ///
    /// Note: there is another "script hash" object in bitcoin ecosystem (Electrum protocol) that
    /// looks similar to this one also being SHA256, however, they hash semantically different
    /// scripts and have reversed representations, so this type cannot be used for both.
    pub struct WScriptHash(sha256::Hash);
}

#[cfg(feature = "hex")]
hashes::impl_hex_for_newtype!(ScriptHash, WScriptHash);
#[cfg(not(feature = "hex"))]
hashes::impl_debug_only_for_newtype!(ScriptHash, WScriptHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(ScriptHash, WScriptHash);

impl ScriptHash {
    /// Constructs a new `ScriptHash` after first checking the script size.
    ///
    /// # 520-byte limitation on serialized script size
    ///
    /// > As a consequence of the requirement for backwards compatibility the serialized script is
    /// > itself subject to the same rules as any other PUSHDATA operation, including the rule that
    /// > no data greater than 520 bytes may be pushed to the stack. Thus it is not possible to
    /// > spend a P2SH output if the redemption script it refers to is >520 bytes in length.
    ///
    /// ref: [BIP-16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size)
    #[inline]
    pub fn from_script(redeem_script: &Script) -> Result<Self, RedeemScriptSizeError> {
        if redeem_script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(RedeemScriptSizeError { size: redeem_script.len() });
        }

        // We've just checked the length
        Ok(ScriptHash::from_script_unchecked(redeem_script))
    }

    /// Constructs a new `ScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 520 bytes in size and use it to create a P2SH output
    /// then the output will be unspendable (see [BIP-16]).
    ///
    /// [BIP-16]: <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size>
    #[inline]
    pub fn from_script_unchecked(script: &Script) -> Self {
        ScriptHash(hash160::Hash::hash(script.as_bytes()))
    }
}

impl WScriptHash {
    /// Constructs a new `WScriptHash` after first checking the script size.
    ///
    /// # 10,000-byte limit on the witness script
    ///
    /// > The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the
    /// > witnessScript must match the 32-byte witness program.
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script(witness_script: &Script) -> Result<Self, WitnessScriptSizeError> {
        if witness_script.len() > MAX_WITNESS_SCRIPT_SIZE {
            return Err(WitnessScriptSizeError { size: witness_script.len() });
        }

        // We've just checked the length
        Ok(WScriptHash::from_script_unchecked(witness_script))
    }

    /// Constructs a new `WScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 10,000 bytes in size and use it to create a Segwit
    /// output then the output will be unspendable (see [BIP-141]).
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    #[inline]
    pub fn from_script_unchecked(script: &Script) -> Self {
        WScriptHash(sha256::Hash::hash(script.as_bytes()))
    }
}

impl TryFrom<ScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&redeem_script)
    }
}

impl TryFrom<&ScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: &ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl TryFrom<&Script> for ScriptHash {
    type Error = RedeemScriptSizeError;

    #[inline]
    fn try_from(redeem_script: &Script) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl TryFrom<ScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&witness_script)
    }
}

impl TryFrom<&ScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: &ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

impl TryFrom<&Script> for WScriptHash {
    type Error = WitnessScriptSizeError;

    #[inline]
    fn try_from(witness_script: &Script) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

/// Error while hashing a redeem script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemScriptSizeError {
    /// Invalid redeem script size (cannot exceed 520 bytes).
    size: usize,
}

impl RedeemScriptSizeError {
    /// Returns the invalid redeem script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

impl From<Infallible> for RedeemScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for RedeemScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "redeem script size exceeds {} bytes: {}", MAX_REDEEM_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RedeemScriptSizeError {}

/// Error while hashing a witness script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessScriptSizeError {
    /// Invalid witness script size (cannot exceed 10,000 bytes).
    size: usize,
}

impl WitnessScriptSizeError {
    /// Returns the invalid witness script size.
    pub fn invalid_size(&self) -> usize { self.size }
}

impl From<Infallible> for WitnessScriptSizeError {
    #[inline]
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for WitnessScriptSizeError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "witness script size exceeds {} bytes: {}", MAX_WITNESS_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessScriptSizeError {}

// We keep all the `Script` and `ScriptBuf` impls together since its easier to see side-by-side.

impl From<ScriptBuf> for Box<Script> {
    #[inline]
    fn from(v: ScriptBuf) -> Self { v.into_boxed_script() }
}

impl From<ScriptBuf> for Cow<'_, Script> {
    #[inline]
    fn from(value: ScriptBuf) -> Self { Cow::Owned(value) }
}

impl<'a> From<Cow<'a, Script>> for ScriptBuf {
    #[inline]
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned,
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a> From<Cow<'a, Script>> for Box<Script> {
    #[inline]
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned.into(),
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a> From<&'a Script> for Box<Script> {
    #[inline]
    fn from(value: &'a Script) -> Self { value.to_owned().into() }
}

impl<'a> From<&'a Script> for ScriptBuf {
    #[inline]
    fn from(value: &'a Script) -> Self { value.to_owned() }
}

impl<'a> From<&'a Script> for Cow<'a, Script> {
    #[inline]
    fn from(value: &'a Script) -> Self { Cow::Borrowed(value) }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(target_has_atomic = "ptr")]
impl<'a> From<&'a Script> for Arc<Script> {
    #[inline]
    fn from(value: &'a Script) -> Self { Script::from_arc_bytes(Arc::from(value.as_bytes())) }
}

impl<'a> From<&'a Script> for Rc<Script> {
    #[inline]
    fn from(value: &'a Script) -> Self { Script::from_rc_bytes(Rc::from(value.as_bytes())) }
}

impl From<Vec<u8>> for ScriptBuf {
    #[inline]
    fn from(v: Vec<u8>) -> Self { ScriptBuf::from_bytes(v) }
}

impl From<ScriptBuf> for Vec<u8> {
    #[inline]
    fn from(v: ScriptBuf) -> Self { v.into_bytes() }
}

impl AsRef<Script> for Script {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}

impl AsRef<Script> for ScriptBuf {
    #[inline]
    fn as_ref(&self) -> &Script { self }
}

impl AsRef<[u8]> for Script {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl AsRef<[u8]> for ScriptBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl AsMut<Script> for Script {
    #[inline]
    fn as_mut(&mut self) -> &mut Self { self }
}

impl AsMut<Script> for ScriptBuf {
    #[inline]
    fn as_mut(&mut self) -> &mut Script { self }
}

impl AsMut<[u8]> for Script {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl AsMut<[u8]> for ScriptBuf {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl fmt::Debug for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(self.as_script(), f) }
}

impl fmt::Display for Script {
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
        while let Some(byte) = iter.next() {
            let opcode = Opcode::from(*byte);

            let data_len = if let opcodes::Class::PushBytes(n) =
                opcode.classify(opcodes::ClassifyContext::Legacy)
            {
                n as usize
            } else {
                match opcode {
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
            if opcode == OP_PUSHBYTES_0 {
                f.write_str("OP_0")?;
            } else {
                write!(f, "{:?}", opcode)?;
            }
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

impl fmt::Display for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self.as_script(), f) }
}

#[cfg(feature = "hex")]
impl fmt::LowerHex for Script {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
internals::impl_to_hex_from_lower_hex!(Script, |script: &Self| script.len() * 2);

#[cfg(feature = "hex")]
impl fmt::LowerHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self.as_script(), f) }
}
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
internals::impl_to_hex_from_lower_hex!(ScriptBuf, |script_buf: &Self| script_buf.len() * 2);

#[cfg(feature = "hex")]
impl fmt::UpperHex for Script {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

#[cfg(feature = "hex")]
impl fmt::UpperHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(self.as_script(), f) }
}

impl Borrow<Script> for ScriptBuf {
    #[inline]
    fn borrow(&self) -> &Script { self }
}

impl BorrowMut<Script> for ScriptBuf {
    #[inline]
    fn borrow_mut(&mut self) -> &mut Script { self }
}

impl PartialEq<ScriptBuf> for Script {
    #[inline]
    fn eq(&self, other: &ScriptBuf) -> bool { self.eq(other.as_script()) }
}

impl PartialEq<Script> for ScriptBuf {
    #[inline]
    fn eq(&self, other: &Script) -> bool { self.as_script().eq(other) }
}

impl PartialOrd<Script> for ScriptBuf {
    #[inline]
    fn partial_cmp(&self, other: &Script) -> Option<Ordering> {
        self.as_script().partial_cmp(other)
    }
}

impl PartialOrd<ScriptBuf> for Script {
    #[inline]
    fn partial_cmp(&self, other: &ScriptBuf) -> Option<Ordering> {
        self.partial_cmp(other.as_script())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Script {
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
impl<'de> serde::Deserialize<'de> for &'de Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = &'de Script;

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

        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ScriptBuf {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ScriptBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        use hex::FromHex;

        if deserializer.is_human_readable() {
            struct Visitor;
            impl serde::de::Visitor<'_> for Visitor {
                type Value = ScriptBuf;

                fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                    formatter.write_str("a script hex")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let v = Vec::from_hex(v).map_err(E::custom)?;
                    Ok(ScriptBuf::from(v))
                }
            }
            deserializer.deserialize_str(Visitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = ScriptBuf;

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
            deserializer.deserialize_byte_buf(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn scriptbuf_as_mut() {
        let mut script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let script_mut: &mut [u8] = script_buf.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);
    }

    #[test]
    fn script_as_ref() {
        let script = Script::from_bytes(&[0x51, 0x52, 0x53]);
        let script_ref: &[u8] = script.as_ref();
        assert_eq!(script_ref, &[0x51, 0x52, 0x53]);
    }

    #[test]
    fn script_as_mut() {
        let bytes = &mut [0x51, 0x52, 0x53];
        let script = Script::from_bytes_mut(bytes);
        let script_mut: &mut [u8] = script.as_mut();
        script_mut[0] = 0x50;
        assert_eq!(script_mut, [0x50, 0x52, 0x53]);
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
        let script = Script::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::from_script(script).is_ok());

        let script = Script::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::from_script(script).is_err());
    }

    #[test]
    fn script_hash_from_script_unchecked() {
        let script = Script::from_bytes(&[0x51; 521]);
        let hash = ScriptHash::from_script_unchecked(script);
        assert_eq!(hash, ScriptHash(hash160::Hash::hash(script.as_bytes())));
    }

    #[test]
    fn wscript_hash_from_script() {
        let script = Script::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::from_script(script).is_ok());

        let script = Script::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::from_script(script).is_err());
    }

    #[test]
    fn wscript_hash_from_script_unchecked() {
        let script = Script::from_bytes(&[0x51; 10_001]);
        let hash = WScriptHash::from_script_unchecked(script);
        assert_eq!(hash, WScriptHash(sha256::Hash::hash(script.as_bytes())));
    }

    #[test]
    fn try_from_scriptbuf_for_scripthash() {
        let script = ScriptBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = ScriptBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_ref_for_scripthash() {
        let script = ScriptBuf::from(vec![0x51; 520]);
        assert!(ScriptHash::try_from(&script).is_ok());

        let script = ScriptBuf::from(vec![0x51; 521]);
        assert!(ScriptHash::try_from(&script).is_err());
    }
    #[test]
    fn try_from_script_for_scripthash() {
        let script = Script::from_bytes(&[0x51; 520]);
        assert!(ScriptHash::try_from(script).is_ok());

        let script = Script::from_bytes(&[0x51; 521]);
        assert!(ScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_for_wscript_hash() {
        let script = ScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = ScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn try_from_scriptbuf_ref_for_wscript_hash() {
        let script = ScriptBuf::from(vec![0x51; 10_000]);
        assert!(WScriptHash::try_from(&script).is_ok());

        let script = ScriptBuf::from(vec![0x51; 10_001]);
        assert!(WScriptHash::try_from(&script).is_err());
    }

    #[test]
    fn try_from_script_for_wscript_hash() {
        let script = Script::from_bytes(&[0x51; 10_000]);
        assert!(WScriptHash::try_from(script).is_ok());

        let script = Script::from_bytes(&[0x51; 10_001]);
        assert!(WScriptHash::try_from(script).is_err());
    }

    #[test]
    fn script_display() {
        let script = Script::from_bytes(&[0xa1, 0xb2, 0xc3]);
        assert_eq!(format!("{}", script), "OP_LESSTHANOREQUAL OP_CSV OP_RETURN_195");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script), "a1b2c3");
            assert_eq!(format!("{:X}", script), "A1B2C3");
        }
    }

    #[test]
    fn scriptbuf_display() {
        let script_buf = ScriptBuf::from(vec![0xa1, 0xb2, 0xc3]);
        assert_eq!(format!("{}", script_buf), "OP_LESSTHANOREQUAL OP_CSV OP_RETURN_195");

        #[cfg(feature = "hex")]
        {
            assert_eq!(format!("{:x}", script_buf), "a1b2c3");
            assert_eq!(format!("{:X}", script_buf), "A1B2C3");
        }
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
        let script_buf = ScriptBuf::from(vec![0x51, 0x52, 0x53]);
        let cow_owned: Cow<Script> = Cow::Owned(script_buf.clone());
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
}
