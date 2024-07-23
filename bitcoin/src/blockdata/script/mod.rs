// SPDX-License-Identifier: CC0-1.0

//! Bitcoin scripts.
//!
//! *[See also the `Script` type](Script).*
//!
//! This module provides the structures and functions needed to support scripts.
//!
//! <details>
//! <summary>What is Bitcoin script</summary>
//!
//! Scripts define Bitcoin's digital signature scheme: a signature is formed
//! from a script (the second half of which is defined by a coin to be spent,
//! and the first half provided by the spending transaction), and is valid iff
//! the script leaves `TRUE` on the stack after being evaluated. Bitcoin's
//! script is a stack-based assembly language similar in spirit to [Forth].
//!
//! Script is represented as a sequence of bytes on the wire, each byte representing an operation,
//! or data to be pushed on the stack.
//!
//! See [Bitcoin Wiki: Script][wiki-script] for more information.
//!
//! [Forth]: https://en.wikipedia.org/wiki/Forth_(programming_language)
//!
//! [wiki-script]: https://en.bitcoin.it/wiki/Script
//! </details>
//!
//! In this library we chose to keep the byte representation in memory and decode opcodes only when
//! processing the script. This is similar to Rust choosing to represent strings as UTF-8-encoded
//! bytes rather than slice of `char`s. In both cases the individual items can have different sizes
//! and forcing them to be larger would waste memory and, in case of Bitcoin script, even some
//! performance (forcing allocations).
//!
//! ## `Script` vs `ScriptBuf` vs `Builder`
//!
//! These are the most important types in this module and they are quite similar, so it may seem
//! confusing what the differences are. `Script` is an unsized type much like `str` or `Path` are
//! and `ScriptBuf` is an owned counterpart to `Script` just like `String` is an owned counterpart
//! to `str`.
//!
//! However it is common to construct an owned script and then pass it around. For this case a
//! builder API is more convenient. To support this we provide `Builder` type which is very similar
//! to `ScriptBuf` but its methods take `self` instead of `&mut self` and return `Self`. It also
//! contains a cache that may make some modifications faster. This cache is usually not needed
//! outside of creating the script.
//!
//! At the time of writing there's only one operation using the cache - `push_verify`, so the cache
//! is minimal but we may extend it in the future if needed.

mod borrowed;
mod builder;
mod instruction;
mod owned;
mod push_bytes;
#[cfg(test)]
mod tests;
pub mod witness_program;
pub mod witness_version;

use alloc::rc::Rc;
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
use alloc::sync::Arc;
use core::cmp::Ordering;
use core::fmt;
use core::ops::{Deref, DerefMut};

use hashes::{hash160, sha256};
use io::{BufRead, Write};

use crate::consensus::{encode, Decodable, Encodable};
use crate::constants::{MAX_REDEEM_SCRIPT_SIZE, MAX_WITNESS_SCRIPT_SIZE};
use crate::internal_macros::impl_asref_push_bytes;
use crate::opcodes::all::*;
use crate::opcodes::{self, Opcode};
use crate::prelude::{Borrow, BorrowMut, Box, Cow, DisplayHex, ToOwned, Vec};
use crate::OutPoint;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::*,
    builder::*,
    instruction::*,
    owned::*,
    push_bytes::*,
};

hashes::hash_newtype! {
    /// A hash of Bitcoin Script bytecode.
    pub struct ScriptHash(hash160::Hash);
    /// SegWit version of a Bitcoin Script bytecode hash.
    pub struct WScriptHash(sha256::Hash);
}
impl_asref_push_bytes!(ScriptHash, WScriptHash);

impl ScriptHash {
    /// Creates a `ScriptHash` after first checking the script size.
    ///
    /// # 520-byte limitation on serialized script size
    ///
    /// > As a consequence of the requirement for backwards compatibility the serialized script is
    /// > itself subject to the same rules as any other PUSHDATA operation, including the rule that
    /// > no data greater than 520 bytes may be pushed to the stack. Thus it is not possible to
    /// > spend a P2SH output if the redemption script it refers to is >520 bytes in length.
    ///
    /// ref: [BIP-16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size)
    pub fn from_script(redeem_script: &Script) -> Result<Self, RedeemScriptSizeError> {
        if redeem_script.len() > MAX_REDEEM_SCRIPT_SIZE {
            return Err(RedeemScriptSizeError { size: redeem_script.len() });
        }

        Ok(ScriptHash(hash160::Hash::hash(redeem_script.as_bytes())))
    }

    /// Creates a `ScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 520 bytes in size and use it to create a P2SH output
    /// then the output will be unspendable (see [BIP-16]).
    ///
    /// [BIP-16]: <https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#user-content-520byte_limitation_on_serialized_script_size>
    pub fn from_script_unchecked(script: &Script) -> Self {
        ScriptHash(hash160::Hash::hash(script.as_bytes()))
    }
}

impl WScriptHash {
    /// Creates a `WScriptHash` after first checking the script size.
    ///
    /// # 10,000-byte limit on the witness script
    ///
    /// > The witnessScript (≤ 10,000 bytes) is popped off the initial witness stack. SHA256 of the
    /// > witnessScript must match the 32-byte witness program.
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    pub fn from_script(witness_script: &Script) -> Result<Self, WitnessScriptSizeError> {
        if witness_script.len() > MAX_WITNESS_SCRIPT_SIZE {
            return Err(WitnessScriptSizeError { size: witness_script.len() });
        }

        Ok(WScriptHash(sha256::Hash::hash(witness_script.as_bytes())))
    }

    /// Creates a `WScriptHash` from any script irrespective of script size.
    ///
    /// If you hash a script that exceeds 10,000 bytes in size and use it to create a Segwit
    /// output then the output will be unspendable (see [BIP-141]).
    ///
    /// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    pub fn from_script_unchecked(script: &Script) -> Self {
        WScriptHash(sha256::Hash::hash(script.as_bytes()))
    }
}

impl TryFrom<ScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    fn try_from(redeem_script: ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&redeem_script)
    }
}

impl TryFrom<&ScriptBuf> for ScriptHash {
    type Error = RedeemScriptSizeError;

    fn try_from(redeem_script: &ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl TryFrom<&Script> for ScriptHash {
    type Error = RedeemScriptSizeError;

    fn try_from(redeem_script: &Script) -> Result<Self, Self::Error> {
        Self::from_script(redeem_script)
    }
}

impl TryFrom<ScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    fn try_from(witness_script: ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(&witness_script)
    }
}

impl TryFrom<&ScriptBuf> for WScriptHash {
    type Error = WitnessScriptSizeError;

    fn try_from(witness_script: &ScriptBuf) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

impl TryFrom<&Script> for WScriptHash {
    type Error = WitnessScriptSizeError;

    fn try_from(witness_script: &Script) -> Result<Self, Self::Error> {
        Self::from_script(witness_script)
    }
}

/// Encodes an integer in script(minimal CScriptNum) format.
///
/// Writes bytes into the buffer and returns the number of bytes written.
///
/// Note that `write_scriptint`/`read_scriptint` do not roundtrip if the value written requires
/// more than 4 bytes, this is in line with Bitcoin Core (see [`CScriptNum::serialize`]).
///
/// [`CScriptNum::serialize`]: <https://github.com/bitcoin/bitcoin/blob/8ae2808a4354e8dcc697f76bacc5e2f2befe9220/src/script/script.h#L345>
pub fn write_scriptint(out: &mut [u8; 8], n: i64) -> usize {
    let mut len = 0;
    if n == 0 {
        return len;
    }

    let neg = n < 0;

    let mut abs = n.unsigned_abs();
    while abs > 0xFF {
        out[len] = (abs & 0xFF) as u8;
        len += 1;
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        out[len] = abs as u8;
        len += 1;
        out[len] = if neg { 0x80u8 } else { 0u8 };
        len += 1;
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        out[len] = abs as u8;
        len += 1;
    }
    len
}

/// Decodes an integer in script format without non-minimal error.
///
/// The overflow error for slices over 4 bytes long is still there.
///
/// See [`push_bytes::PushBytes::read_scriptint`] for a description of some subtleties of
/// this function.
pub fn read_scriptint_non_minimal(v: &[u8]) -> Result<i64, Error> {
    if v.is_empty() {
        return Ok(0);
    }
    if v.len() > 4 {
        return Err(Error::NumericOverflow);
    }

    Ok(scriptint_parse(v))
}

// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v.iter().fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

/// Decodes a boolean.
///
/// This is like "`read_scriptint` then map 0 to false and everything
/// else as true", except that the overflow rules don't apply.
#[inline]
pub fn read_scriptbool(v: &[u8]) -> bool {
    match v.split_last() {
        Some((last, rest)) => !((last & !0x80 == 0x00) && rest.iter().all(|&b| b == 0)),
        None => false,
    }
}

// We internally use implementation based on iterator so that it automatically advances as needed
// Errors are same as above, just different type.
fn read_uint_iter(data: &mut core::slice::Iter<'_, u8>, size: usize) -> Result<usize, UintError> {
    if data.len() < size {
        Err(UintError::EarlyEndOfScript)
    } else if size > usize::from(u16::MAX / 8) {
        // Casting to u32 would overflow
        Err(UintError::NumericOverflow)
    } else {
        let mut ret = 0;
        for (i, item) in data.take(size).enumerate() {
            ret = usize::from(*item)
                // Casting is safe because we checked above to not repeat the same check in a loop
                .checked_shl((i * 8) as u32)
                .ok_or(UintError::NumericOverflow)?
                .checked_add(ret)
                .ok_or(UintError::NumericOverflow)?;
        }
        Ok(ret)
    }
}

fn opcode_to_verify(opcode: Option<Opcode>) -> Option<Opcode> {
    opcode.and_then(|opcode| match opcode {
        OP_EQUAL => Some(OP_EQUALVERIFY),
        OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
        OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
        OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
        _ => None,
    })
}

// We keep all the `Script` and `ScriptBuf` impls together since its easier to see side-by-side.

impl From<ScriptBuf> for Box<Script> {
    fn from(v: ScriptBuf) -> Self { v.into_boxed_script() }
}

impl From<ScriptBuf> for Cow<'_, Script> {
    fn from(value: ScriptBuf) -> Self { Cow::Owned(value) }
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
    fn from(value: &'a Script) -> Self { value.to_owned().into() }
}

impl<'a> From<&'a Script> for ScriptBuf {
    fn from(value: &'a Script) -> Self { value.to_owned() }
}

impl<'a> From<&'a Script> for Cow<'a, Script> {
    fn from(value: &'a Script) -> Self { Cow::Borrowed(value) }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
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

impl AsRef<Script> for Script {
    #[inline]
    fn as_ref(&self) -> &Script { self }
}

impl AsRef<Script> for ScriptBuf {
    fn as_ref(&self) -> &Script { self }
}

impl AsRef<[u8]> for Script {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl AsRef<[u8]> for ScriptBuf {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl AsMut<Script> for Script {
    fn as_mut(&mut self) -> &mut Script { self }
}

impl AsMut<Script> for ScriptBuf {
    fn as_mut(&mut self) -> &mut Script { self }
}

impl AsMut<[u8]> for Script {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl AsMut<[u8]> for ScriptBuf {
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Script(")?;
        self.fmt_asm(f)?;
        f.write_str(")")
    }
}

impl fmt::Debug for ScriptBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Debug::fmt(self.as_script(), f) }
}

impl fmt::Display for Script {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { self.fmt_asm(f) }
}

impl fmt::Display for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self.as_script(), f) }
}

impl fmt::LowerHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl fmt::LowerHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self.as_script(), f) }
}

impl fmt::UpperHex for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.as_bytes().as_hex(), f)
    }
}

impl fmt::UpperHex for ScriptBuf {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::UpperHex::fmt(self.as_script(), f) }
}

impl Deref for ScriptBuf {
    type Target = Script;

    fn deref(&self) -> &Self::Target { Script::from_bytes(&self.0) }
}

impl DerefMut for ScriptBuf {
    fn deref_mut(&mut self) -> &mut Self::Target { Script::from_bytes_mut(&mut self.0) }
}

impl Borrow<Script> for ScriptBuf {
    fn borrow(&self) -> &Script { self }
}

impl BorrowMut<Script> for ScriptBuf {
    fn borrow_mut(&mut self) -> &mut Script { self }
}

impl PartialEq<ScriptBuf> for Script {
    fn eq(&self, other: &ScriptBuf) -> bool { self.eq(other.as_script()) }
}

impl PartialEq<Script> for ScriptBuf {
    fn eq(&self, other: &Script) -> bool { self.as_script().eq(other) }
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
        if deserializer.is_human_readable() {
            use crate::serde::de::Error;

            return Err(D::Error::custom(
                "deserialization of `&Script` from human-readable formats is not possible",
            ));
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        crate::consensus::encode::consensus_encode_with_size(&self.0, w)
    }
}

impl Encodable for ScriptBuf {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ScriptBuf {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
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
                // We got the data in a slice which implies it being shorter than `usize::MAX`
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
        let opcode = Opcode::from(*byte);

        let data_len = if let opcodes::Class::PushBytes(n) =
            opcode.classify(opcodes::ClassifyContext::Legacy)
        {
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

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push; for more information see
    /// <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#push-operators>
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
    /// Can not find the spent output.
    UnknownSpentOutput(OutPoint),
    /// Can not serialize the spending transaction.
    Serialization,
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            NonMinimalPush => f.write_str("non-minimal datapush"),
            EarlyEndOfScript => f.write_str("unexpected end of script"),
            NumericOverflow =>
                f.write_str("numeric overflow (number on stack larger than 4 bytes)"),
            UnknownSpentOutput(ref point) => write!(f, "unknown spent output: {}", point),
            Serialization =>
                f.write_str("can not serialize the spending transaction in Transaction::verify()"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            NonMinimalPush
            | EarlyEndOfScript
            | NumericOverflow
            | UnknownSpentOutput(_)
            | Serialization => None,
        }
    }
}

// Our internal error proves that we only return these two cases from `read_uint_iter`.
// Since it's private we don't bother with trait impls besides From.
enum UintError {
    EarlyEndOfScript,
    NumericOverflow,
}

internals::impl_from_infallible!(UintError);

impl From<UintError> for Error {
    fn from(error: UintError) -> Self {
        match error {
            UintError::EarlyEndOfScript => Error::EarlyEndOfScript,
            UintError::NumericOverflow => Error::NumericOverflow,
        }
    }
}

/// Error while hashing a redeem script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemScriptSizeError {
    /// Invalid redeem script size (cannot exceed 520 bytes).
    pub size: usize,
}

internals::impl_from_infallible!(RedeemScriptSizeError);

impl fmt::Display for RedeemScriptSizeError {
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
    pub size: usize,
}

internals::impl_from_infallible!(WitnessScriptSizeError);

impl fmt::Display for WitnessScriptSizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "witness script size exceeds {} bytes: {}", MAX_WITNESS_SCRIPT_SIZE, self.size)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessScriptSizeError {}

/// Iterates the script to find the last pushdata.
///
/// Returns `None` if the instruction is an opcode or if the script is empty.
pub(crate) fn last_pushdata(script: &Script) -> Option<&PushBytes> {
    match script.instructions().last() {
        // Handles op codes up to (but excluding) OP_PUSHNUM_NEG.
        Some(Ok(Instruction::PushBytes(bytes))) => Some(bytes),
        // OP_16 (0x60) and lower are considered "pushes" by Bitcoin Core (excl. OP_RESERVED).
        // However we are only interested in the pushdata so we can ignore them.
        _ => None,
    }
}
