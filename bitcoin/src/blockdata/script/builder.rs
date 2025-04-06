// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use primitives::relative;

use super::{opcode_to_verify, write_scriptint, Error, PushBytes, Script, ScriptBuf};
use crate::locktime::absolute;
use crate::opcodes::all::*;
use crate::opcodes::Opcode;
use crate::prelude::Vec;
use crate::script::{ScriptBufExt as _, ScriptBufExtPriv as _, ScriptExtPriv as _};
use crate::Sequence;

/// An Object which can be used to construct a script piece by piece.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder(ScriptBuf, Option<Opcode>);

impl Builder {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { Builder(ScriptBuf::new(), None) }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    ///
    /// # Errors
    ///
    /// Only errors if `data == i32::MIN` (CScriptNum cannot have value -2^31).
    pub fn push_int(self, n: i32) -> Result<Builder, Error> {
        if n == i32::MIN {
            // ref: https://github.com/bitcoin/bitcoin/blob/cac846c2fbf6fc69bfc288fd387aa3f68d84d584/src/script/script.h#L230
            Err(Error::NumericOverflow)
        } else {
            Ok(self.push_int_unchecked(n.into()))
        }
    }

    /// Adds instructions to push an unchecked integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    ///
    /// This function implements `CScript::push_int64` from Core `script.h`.
    ///
    /// > Numeric opcodes (OP_1ADD, etc) are restricted to operating on 4-byte integers.
    /// > The semantics are subtle, though: operands must be in the range [-2^31 +1...2^31 -1],
    /// > but results may overflow (and are valid as long as they are not used in a subsequent
    /// > numeric operation). CScriptNum enforces those semantics by storing results as
    /// > an int64 and allowing out-of-range values to be returned as a vector of bytes but
    /// > throwing an exception if arithmetic is done or the result is interpreted as an integer.
    ///
    /// Does not check whether `n` is in the range of [-2^31 +1...2^31 -1].
    pub fn push_int_unchecked(self, n: i64) -> Builder {
        match n {
            -1 => self.push_opcode(OP_PUSHNUM_NEG1),
            0 => self.push_opcode(OP_PUSHBYTES_0),
            1..=16 => self.push_opcode(Opcode::from(n as u8 + (OP_PUSHNUM_1.to_u8() - 1))),
            _ => self.push_int_non_minimal(n),
        }
    }

    /// Adds instructions to push an integer onto the stack without optimization.
    ///
    /// This uses the explicit encoding regardless of the availability of dedicated opcodes.
    pub(in crate::blockdata) fn push_int_non_minimal(self, data: i64) -> Builder {
        let mut buf = [0u8; 8];
        let len = write_scriptint(&mut buf, data);
        self.push_slice(&<&PushBytes>::from(&buf)[..len])
    }

    /// Adds instructions to push some arbitrary data onto the stack.
    pub fn push_slice<T: AsRef<PushBytes>>(mut self, data: T) -> Builder {
        self.0.push_slice(data);
        self.1 = None;
        self
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(mut self, data: Opcode) -> Builder {
        self.0.push_opcode(data);
        self.1 = Some(data);
        self
    }

    /// Adds an `OP_VERIFY` to the script or replaces the last opcode with VERIFY form.
    ///
    /// Some opcodes such as `OP_CHECKSIG` have a verify variant that works as if `VERIFY` was
    /// in the script right after. To save space this function appends `VERIFY` only if
    /// the most-recently-added opcode *does not* have an alternate `VERIFY` form. If it does
    /// the last opcode is replaced. E.g., `OP_CHECKSIG` will become `OP_CHECKSIGVERIFY`.
    ///
    /// Note that existing `OP_*VERIFY` opcodes do not lead to the instruction being ignored
    /// because `OP_VERIFY` consumes an item from the stack so ignoring them would change the
    /// semantics.
    pub fn push_verify(mut self) -> Builder {
        // "duplicated code" because we need to update `1` field
        match opcode_to_verify(self.1) {
            Some(opcode) => {
                (self.0).as_byte_vec().pop();
                self.push_opcode(opcode)
            }
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Adds instructions to push an absolute lock time onto the stack.
    pub fn push_lock_time(self, lock_time: absolute::LockTime) -> Builder {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a relative lock time onto the stack.
    ///
    /// This is used when creating scripts that use CHECKSEQUENCEVERIFY (CSV) to enforce
    /// relative time locks.
    pub fn push_relative_lock_time(self, lock_time: relative::LockTime) -> Builder {
        self.push_int_unchecked(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a sequence number onto the stack.
    ///
    /// # Deprecated
    /// This method is deprecated in favor of `push_relative_lock_time`.
    ///
    /// In Bitcoin script semantics, when using CHECKSEQUENCEVERIFY, you typically
    /// want to push a relative locktime value to be compared against the input's
    /// sequence number, not the sequence number itself.
    #[deprecated(
        since = "TBD",
        note = "Use push_relative_lock_time instead for working with timelocks in scripts"
    )]
    pub fn push_sequence(self, sequence: Sequence) -> Builder {
        self.push_int_unchecked(sequence.to_consensus_u32().into())
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf { self.0 }

    /// Converts the `Builder` into script bytes
    pub fn into_bytes(self) -> Vec<u8> { self.0.into() }

    /// Returns the internal script
    pub fn as_script(&self) -> &Script { &self.0 }

    /// Returns script bytes
    pub fn as_bytes(&self) -> &[u8] { self.0.as_bytes() }
}

impl Default for Builder {
    fn default() -> Builder { Builder::new() }
}

/// Constructs a new builder from an existing vector.
impl From<Vec<u8>> for Builder {
    fn from(v: Vec<u8>) -> Builder {
        let script = ScriptBuf::from(v);
        let last_op = script.last_opcode();
        Builder(script, last_op)
    }
}

impl fmt::Display for Builder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> { fmt::Display::fmt(self, f) }
}
