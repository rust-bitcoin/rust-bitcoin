// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Provides the two script types, one with owned inner data [`ScriptBuf`] and
//! one with borrowed inner data [`Script`].

use alloc::rc::Rc;
use alloc::sync::Arc;

use core::cmp::Ordering;
use core::borrow::{Borrow, BorrowMut};
use core::fmt;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "serde")]
use serde;

use crate::blockdata::opcodes::{self, all::*};
use crate::blockdata::script::{read_uint_iter, UintError};
use crate::consensus::{encode, Decodable, Encodable};
use crate::hash_types::{ScriptHash, WScriptHash};
use crate::hashes::{hex};
use crate::io;
use crate::prelude::*;

mod borrowed;
mod owned;

pub use borrowed::*;
pub use owned::*;

impl From<ScriptBuf> for Box<Script> {
    fn from(v: ScriptBuf) -> Self {
        v.into_boxed_script()
    }
}

impl From<ScriptBuf> for Cow<'_, Script> {
    fn from(value: ScriptBuf) -> Self {
        Cow::Owned(value)
    }
}

impl<'a> From<Cow<'a, Script>> for ScriptBuf {
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned,
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a> From<Cow<'a, Script>> for Box<Script> {
    fn from(value: Cow<'a, Script>) -> Self {
        match value {
            Cow::Owned(owned) => owned.into(),
            Cow::Borrowed(borrwed) => borrwed.into(),
        }
    }
}

impl<'a> From<&'a Script> for Box<Script> {
    fn from(value: &'a Script) -> Self {
        value.to_owned().into()
    }
}

impl<'a> From<&'a Script> for ScriptBuf {
    fn from(value: &'a Script) -> Self {
        value.to_owned()
    }
}

impl<'a> From<&'a Script> for Cow<'a, Script> {
    fn from(value: &'a Script) -> Self {
        Cow::Borrowed(value)
    }
}

impl<'a> From<&'a Script> for Arc<Script> {
    fn from(value: &'a Script) -> Self {
        let rw: *const [u8] = Arc::into_raw(Arc::from(&value.0));
        // SAFETY: copied from `std`
        // The pointer was just created from an Arc without deallocating
        // Casting a slice to a transparent struct wrapping that slice is sound (same
        // layout).
        unsafe { Arc::from_raw(rw as *const Script) }
    }
}

impl<'a> From<&'a Script> for Rc<Script> {
    fn from(value: &'a Script) -> Self {
        let rw: *const [u8] = Rc::into_raw(Rc::from(&value.0));
        // SAFETY: copied from `std`
        // The pointer was just created from an Rc without deallocating
        // Casting a slice to a transparent struct wrapping that slice is sound (same
        // layout).
        unsafe { Rc::from_raw(rw as *const Script) }
    }
}

impl From<Vec<u8>> for ScriptBuf {
    fn from(v: Vec<u8>) -> Self { ScriptBuf(v) }
}

impl From<ScriptBuf> for Vec<u8> {
    fn from(v: ScriptBuf) -> Self { v.0 }
}

impl From<ScriptBuf> for ScriptHash {
    fn from(script: ScriptBuf) -> ScriptHash {
        script.script_hash()
    }
}

impl From<&ScriptBuf> for ScriptHash {
    fn from(script: &ScriptBuf) -> ScriptHash {
        script.script_hash()
    }
}

impl From<&Script> for ScriptHash {
    fn from(script: &Script) -> ScriptHash {
        script.script_hash()
    }
}

impl From<ScriptBuf> for WScriptHash {
    fn from(script: ScriptBuf) -> WScriptHash {
        script.wscript_hash()
    }
}

impl From<&ScriptBuf> for WScriptHash {
    fn from(script: &ScriptBuf) -> WScriptHash {
        script.wscript_hash()
    }
}

impl From<&Script> for WScriptHash {
    fn from(script: &Script) -> WScriptHash {
        script.wscript_hash()
    }
}

impl core::str::FromStr for ScriptBuf {
    type Err = hex::Error;
    #[inline]
    fn from_str(s: &str) -> Result<Self, hex::Error> {
        ScriptBuf::from_hex(s)
    }
}

impl AsRef<Script> for Script {
    #[inline]
    fn as_ref(&self) -> &Script {
        self
    }
}

impl AsRef<Script> for ScriptBuf {
    fn as_ref(&self) -> &Script {
        self
    }
}

impl AsRef<[u8]> for Script {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for ScriptBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<Script> for Script {
    fn as_mut(&mut self) -> &mut Script {
        self
    }
}

impl AsMut<Script> for ScriptBuf {
    fn as_mut(&mut self) -> &mut Script {
        self
    }
}

impl AsMut<[u8]> for Script {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl AsMut<[u8]> for ScriptBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        self.fmt_asm(f)?;
        f.write_str(")")
    }
}

impl fmt::Debug for ScriptBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.as_script(), f)
    }
}

impl fmt::Display for Script {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_asm(f)
    }
}

impl fmt::Display for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_script(), f)
    }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl fmt::LowerHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.as_script(), f)
    }
}

impl fmt::UpperHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl fmt::UpperHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(self.as_script(), f)
    }
}

impl Deref for ScriptBuf {
    type Target = Script;

    fn deref(&self) -> &Self::Target {
        Script::from_bytes(&self.0)
    }
}

impl DerefMut for ScriptBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Script::from_bytes_mut(&mut self.0)
    }
}

impl Borrow<Script> for ScriptBuf {
    fn borrow(&self) -> &Script {
        self
    }
}

impl BorrowMut<Script> for ScriptBuf {
    fn borrow_mut(&mut self) -> &mut Script {
        self
    }
}

impl PartialEq<ScriptBuf> for Script {
    fn eq(&self, other: &ScriptBuf) -> bool {
        self.eq(other.as_script())
    }
}

impl PartialEq<Script> for ScriptBuf {
    fn eq(&self, other: &Script) -> bool {
        self.as_script().eq(other)
    }
}

impl PartialOrd<Script> for ScriptBuf {
    fn partial_cmp(&self, other: &Script) -> Option<Ordering> {
        self.as_script().partial_cmp(other)
    }
}

impl PartialOrd<ScriptBuf> for Script {
    fn partial_cmp(&self, other: &ScriptBuf) -> Option<Ordering> {
        self.partial_cmp(other.as_script())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for &'de Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            use crate::serde::de::Error;

            return Err(D::Error::custom("deserialization of `&Script` from human-readable formats is not possible"));
        }

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
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> serde::Deserialize<'de> for ScriptBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt::Formatter;
        use crate::hashes::hex::FromHex;

        if deserializer.is_human_readable() {

            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
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

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
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

impl Encodable for Script {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        crate::consensus::encode::consensus_encode_with_size(&self.0, w)
    }
}

impl Encodable for ScriptBuf {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ScriptBuf {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(ScriptBuf(Decodable::consensus_decode_from_finite_reader(r)?))
    }
}

/// Writes the assembly decoding of the script bytes to the formatter.
pub(super) fn bytes_to_asm_fmt(script: &[u8], f: &mut dyn fmt::Write) -> fmt::Result {
    // This has to be a macro because it needs to break the loop
    macro_rules! read_push_data_len {
        ($iter:expr, $len:literal, $formatter:expr) => {
            match read_uint_iter($iter, $len) {
                Ok(n) => {
                    n
                },
                Err(UintError::EarlyEndOfScript) => {
                    $formatter.write_str("<unexpected end>")?;
                    break;
                }
                // We got the data in a slice which implies it being shorter than `usize::max_value()`
                // So if we got overflow, we can confidently say the number is higher than length of
                // the slice even though we don't know the exact number. This implies attempt to push
                // past end.
                Err(UintError::NumericOverflow) => {
                    $formatter.write_str("<push past end>")?;
                    break;
                }
            }
        }
    }

    let mut iter = script.iter();
    // Was at least one opcode emitted?
    let mut at_least_one = false;
    // `iter` needs to be borrowed in `read_push_data_len`, so we have to use `while let` instead
    // of `for`.
    while let Some(byte) = iter.next() {
        let opcode = opcodes::All::from(*byte);

        let data_len = if let opcodes::Class::PushBytes(n) = opcode.classify(opcodes::ClassifyContext::Legacy) {
            n as usize
        } else {
            match opcode {
                OP_PUSHDATA1 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 1, f)
                }
                OP_PUSHDATA2 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 2, f)
                }
                OP_PUSHDATA4 => {
                    // side effects: may write and break from the loop
                    read_push_data_len!(&mut iter, 4, f)
                }
                _ => 0
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
