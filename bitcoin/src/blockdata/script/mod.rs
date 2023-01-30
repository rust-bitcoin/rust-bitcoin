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

use core::fmt;

use crate::blockdata::opcodes::{self, all::*};
use crate::OutPoint;

mod builder;
mod instruction;
mod types;
#[cfg(test)]
mod tests;

pub use self::builder::*;
pub use self::instruction::*;
pub use self::types::*;

/// Encodes an integer in script(minimal CScriptNum) format.
///
/// Writes bytes into the buffer and returns the number of bytes written.
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

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Error {
    /// Something did a non-minimal push; for more information see
    /// `https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Push_operators`
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
