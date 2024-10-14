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

use hashes::{hash160, sha256};
use io::{BufRead, Write};
use primitives::opcodes::all::*;
use primitives::opcodes::Opcode;

use crate::consensus::{encode, Decodable, Encodable};
use crate::constants::{MAX_REDEEM_SCRIPT_SIZE, MAX_WITNESS_SCRIPT_SIZE};
use crate::internal_macros::impl_asref_push_bytes;
use crate::key::WPubkeyHash;
use crate::prelude::Vec;
use crate::OutPoint;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    borrowed::ScriptExt,
    builder::*,
    instruction::*,
    owned::ScriptBufExt,
    push_bytes::*,
};
#[doc(inline)]
pub use primitives::script::*;

pub(crate) use self::borrowed::ScriptExtPriv;
pub(crate) use self::owned::ScriptBufExtPriv;

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

/// Creates the script code used for spending a P2WPKH output.
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
