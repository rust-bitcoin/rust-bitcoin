// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

#[cfg(feature="bitcoinconsensus")] use core::convert::From;
use core::default::Default;
use core::fmt;

use secp256k1::XOnlyPublicKey;

use crate::blockdata::locktime::absolute;
use crate::blockdata::opcodes::{self, all::*};
use crate::blockdata::script::{write_scriptint, opcode_to_verify, Script, ScriptBuf, PushBytes};
use crate::blockdata::transaction::Sequence;
use crate::key::PublicKey;
use crate::prelude::*;

/// An Object which can be used to construct a script piece by piece.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder(ScriptBuf, Option<opcodes::All>);

impl Builder {
    /// Creates a new empty script.
    pub fn new() -> Self {
        Builder(ScriptBuf::new(), None)
    }

    /// Returns the length in bytes of the script.
    pub fn len(&self) -> usize { self.0.len() }

    /// Checks whether the script is the empty script.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Adds instructions to push an integer onto the stack.
    ///
    /// Integers are encoded as little-endian signed-magnitude numbers, but there are dedicated
    /// opcodes to push some small integers.
    pub fn push_int(self, data: i64) -> Builder {
        // We can special-case -1, 1-16
        if data == -1 || (1..=16).contains(&data) {
            let opcode = opcodes::All::from(
                (data - 1 + opcodes::OP_TRUE.to_u8() as i64) as u8
            );
            self.push_opcode(opcode)
        }
        // We can also special-case zero
        else if data == 0 {
            self.push_opcode(opcodes::OP_0)
        }
        // Otherwise encode it as data
        else { self.push_int_non_minimal(data) }
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

    /// Adds instructions to push a public key onto the stack.
    pub fn push_key(self, key: &PublicKey) -> Builder {
        if key.compressed {
            self.push_slice(key.inner.serialize())
        } else {
            self.push_slice(key.inner.serialize_uncompressed())
        }
    }

    /// Adds instructions to push an XOnly public key onto the stack.
    pub fn push_x_only_key(self, x_only_key: &XOnlyPublicKey) -> Builder {
        self.push_slice(x_only_key.serialize())
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(mut self, data: opcodes::All) -> Builder {
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
                (self.0).0.pop();
                self.push_opcode(opcode)
            },
            None => self.push_opcode(OP_VERIFY),
        }
    }

    /// Adds instructions to push an absolute lock time onto the stack.
    pub fn push_lock_time(self, lock_time: absolute::LockTime) -> Builder {
        self.push_int(lock_time.to_consensus_u32().into())
    }

    /// Adds instructions to push a sequence number onto the stack.
    pub fn push_sequence(self, sequence: Sequence) -> Builder  {
        self.push_int(sequence.to_consensus_u32().into())
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf {
        self.0
    }

    /// Converts the `Builder` into script bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into()
    }

    /// Returns the internal script
    pub fn as_script(&self) -> &Script {
        &self.0
    }

    /// Returns script bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for Builder {
    fn default() -> Builder { Builder::new() }
}

/// Creates a new builder from an existing vector.
impl From<Vec<u8>> for Builder {
    fn from(v: Vec<u8>) -> Builder {
        let script = ScriptBuf::from(v);
        let last_op = script.last_opcode();
        Builder(script, last_op)
    }
}

impl fmt::Display for Builder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_asm(f)
    }
}

bitcoin_internals::debug_from_display!(Builder);
