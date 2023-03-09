// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
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

use alloc::rc::Rc;
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
use alloc::sync::Arc;

use core::cmp::Ordering;
use core::borrow::{Borrow, BorrowMut};
use core::fmt;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "serde")]
use serde;

use crate::blockdata::opcodes::{self, all::*};
use crate::consensus::{encode, Decodable, Encodable};
use crate::hash_types::{ScriptHash, WScriptHash};
use crate::{io, OutPoint};
use crate::prelude::*;

mod borrowed;
mod builder;
mod instruction;
mod owned;
#[cfg(test)]
mod tests;
mod push_bytes;

pub use self::borrowed::*;
pub use self::builder::*;
pub use self::instruction::*;
pub use self::owned::*;
pub use self::push_bytes::*;

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
    if n == 0 { return len; }

    let neg = n < 0;

    let mut abs = if neg { -n } else { n } as usize;
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

/// Decodes an integer in script(minimal CScriptNum) format.
///
/// Notice that this fails on overflow: the result is the same as in
/// bitcoind, that only 4-byte signed-magnitude values may be read as
/// numbers. They can be added or subtracted (and a long time ago,
/// multiplied and divided), and this may result in numbers which
/// can't be written out in 4 bytes or less. This is ok! The number
/// just can't be read as a number again.
/// This is a bit crazy and subtle, but it makes sense: you can load
/// 32-bit numbers and do anything with them, which back when mult/div
/// was allowed, could result in up to a 64-bit number. We don't want
/// overflow since that's surprising --- and we don't want numbers that
/// don't fit in 64 bits (for efficiency on modern processors) so we
/// simply say, anything in excess of 32 bits is no longer a number.
/// This is basically a ranged type implementation.
///
/// This code is based on the `CScriptNum` constructor in Bitcoin Core (see `script.h`).
pub fn read_scriptint(v: &[u8]) -> Result<i64, Error> {
    let len = v.len();
    if len > 4 { return Err(Error::NumericOverflow); }
    let last = match v.last() {
        Some(last) => last,
        None => return Ok(0),
    };
    // Comment and code copied from Bitcoin Core:
    // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if (last & 0x7f) == 0 {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
            return Err(Error::NonMinimalPush);
        }
    }

    let (mut ret, sh) = v.iter()
                         .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[len - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    Ok(ret)
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

/// Decodes a script-encoded unsigned integer.
///
/// ## Errors
///
/// This function returns an error in these cases:
///
/// * `data` is shorter than `size` => `EarlyEndOfScript`
/// * `size` is greater than `u16::max_value / 8` (8191) => `NumericOverflow`
/// * The number being read overflows `usize` => `NumericOverflow`
///
/// Note that this does **not** return an error for `size` between `core::size_of::<usize>()`
/// and `u16::max_value / 8` if there's no overflow.
#[inline]
#[deprecated(since = "0.30.0", note = "bitcoin integers are signed 32 bits, use read_scriptint")]
pub fn read_uint(data: &[u8], size: usize) -> Result<usize, Error> {
    read_uint_iter(&mut data.iter(), size).map_err(Into::into)
}

// We internally use implementation based on iterator so that it automatically advances as needed
// Errors are same as above, just different type.
fn read_uint_iter(data: &mut core::slice::Iter<'_, u8>, size: usize) -> Result<usize, UintError> {
    if data.len() < size {
        Err(UintError::EarlyEndOfScript)
    } else if size > usize::from(u16::max_value() / 8) {
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

fn opcode_to_verify(opcode: Option<opcodes::All>) -> Option<opcodes::All> {
    opcode.and_then(|opcode| {
        match opcode {
            OP_EQUAL => Some(OP_EQUALVERIFY),
            OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
            OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
            OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
            _ => None,
        }
    })
}

// We keep all the `Script` and `ScriptBuf` impls together since its easier to see side-by-side.

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

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
#[cfg_attr(docsrs, doc(cfg(target_has_atomic = "ptr")))]
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

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push; for more information see
    /// <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#push-operators>
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
    /// Error validating the script with bitcoinconsensus library.
    #[cfg(feature = "bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    BitcoinConsensus(bitcoinconsensus::Error),
    /// Can not find the spent output.
    UnknownSpentOutput(OutPoint),
    /// Can not serialize the spending transaction.
    Serialization
}

// If bitcoinonsensus-std is off but bitcoinconsensus is present we patch the error type to
// implement `std::error::Error`.
#[cfg(all(feature = "std", feature = "bitcoinconsensus", not(feature = "bitcoinconsensus-std")))]
mod bitcoinconsensus_hack {
    use core::fmt;

    #[repr(transparent)]
    pub(crate) struct Error(bitcoinconsensus::Error);

    impl fmt::Debug for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, f)
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(&self.0, f)
        }
    }

    // bitcoinconsensus::Error has no sources at this time
    impl std::error::Error for Error {}

    pub(crate) fn wrap_error(error: &bitcoinconsensus::Error) -> &Error {
        // Unfortunately, we cannot have the reference inside `Error` struct because of the 'static
        // bound on `source` return type, so we have to use unsafe to overcome the limitation.
        // SAFETY: the type is repr(transparent) and the lifetimes match
        unsafe {
            &*(error as *const _ as *const Error)
        }
    }
}

#[cfg(not(all(feature = "std", feature = "bitcoinconsensus", not(feature = "bitcoinconsensus-std"))))]
mod bitcoinconsensus_hack {
    #[allow(unused_imports)] // conditionally used
    pub(crate) use core::convert::identity as wrap_error;
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "bitcoinconsensus")]
        use bitcoin_internals::write_err;

        match *self {
            Error::NonMinimalPush => f.write_str("non-minimal datapush"),
            Error::EarlyEndOfScript => f.write_str("unexpected end of script"),
            Error::NumericOverflow => f.write_str("numeric overflow (number on stack larger than 4 bytes)"),
            #[cfg(feature = "bitcoinconsensus")]
            Error::BitcoinConsensus(ref e) => write_err!(f, "bitcoinconsensus verification failed"; bitcoinconsensus_hack::wrap_error(e)),
            Error::UnknownSpentOutput(ref point) => write!(f, "unknown spent output: {}", point),
            Error::Serialization => f.write_str("can not serialize the spending transaction in Transaction::verify()"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            NonMinimalPush
            | EarlyEndOfScript
            | NumericOverflow
            | UnknownSpentOutput(_)
            | Serialization => None,
            #[cfg(feature = "bitcoinconsensus")]
            BitcoinConsensus(ref e) => Some(bitcoinconsensus_hack::wrap_error(e)),
        }
    }
}

// Our internal error proves that we only return these two cases from `read_uint_iter`.
// Since it's private we don't bother with trait impls besides From.
enum UintError {
    EarlyEndOfScript,
    NumericOverflow,
}

impl From<UintError> for Error {
    fn from(error: UintError) -> Self {
        match error {
            UintError::EarlyEndOfScript => Error::EarlyEndOfScript,
            UintError::NumericOverflow => Error::NumericOverflow,
        }
    }
}

#[cfg(feature = "bitcoinconsensus")]
#[doc(hidden)]
impl From<bitcoinconsensus::Error> for Error {
    fn from(err: bitcoinconsensus::Error) -> Error {
        Error::BitcoinConsensus(err)
    }
}
