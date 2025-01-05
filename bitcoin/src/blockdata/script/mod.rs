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

use core::fmt;
use core::convert::Infallible;

use io::{BufRead, Write};
use primitives::opcodes::all::*;
use primitives::opcodes::Opcode;

use crate::consensus::{encode, Decodable, Encodable};
use crate::internal_macros::impl_asref_push_bytes;
use crate::key::WPubkeyHash;
use crate::prelude::Vec;
use crate::OutPoint;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::ScriptExt,
    builder::Builder,
    instruction::{Instruction, Instructions, InstructionIndices},
    owned::ScriptBufExt,
    push_bytes::{PushBytes, PushBytesBuf, PushBytesError, PushBytesErrorReport},
};
#[doc(inline)]
pub use primitives::script::{
    RedeemScriptSizeError, Script, ScriptBuf, ScriptHash, WScriptHash, WitnessScriptSizeError,
};

pub(crate) use self::borrowed::ScriptExtPriv;
pub(crate) use self::owned::ScriptBufExtPriv;

impl_asref_push_bytes!(ScriptHash, WScriptHash);

/// Constructs a new [`ScriptBuf`] containing the script code used for spending a P2WPKH output.
///
/// The `scriptCode` is described in [BIP143].
///
/// [BIP143]: <https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki>
pub fn p2wpkh_script_code(wpkh: WPubkeyHash) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(wpkh)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
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

fn opcode_to_verify(opcode: Option<Opcode>) -> Option<Opcode> {
    opcode.and_then(|opcode| match opcode {
        OP_EQUAL => Some(OP_EQUALVERIFY),
        OP_NUMEQUAL => Some(OP_NUMEQUALVERIFY),
        OP_CHECKSIG => Some(OP_CHECKSIGVERIFY),
        OP_CHECKMULTISIG => Some(OP_CHECKMULTISIGVERIFY),
        _ => None,
    })
}

impl Encodable for Script {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        crate::consensus::encode::consensus_encode_with_size(self.as_bytes(), w)
    }
}

impl Encodable for ScriptBuf {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_script().consensus_encode(w)
    }
}

impl Decodable for ScriptBuf {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let v: Vec<u8> = Decodable::consensus_decode_from_finite_reader(r)?;
        Ok(ScriptBuf::from_bytes(v))
    }
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

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

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
