// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use super::{PushBytes, Script, ScriptBuf};
use crate::opcodes::Opcode;
use crate::prelude::Vec;

/// An Object which can be used to construct a script piece by piece.
///
/// # Panics
///
/// `Builder` is backed by [`ScriptBuf`] and inherits its panic behavior. This means that
/// attempting to construct scripts larger than `isize::MAX` bytes will panic.
#[derive(PartialEq, Eq, Clone)]
pub struct Builder<T>(ScriptBuf<T>);

impl<T> Builder<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { Self(ScriptBuf::new()) }

    /// Adds instructions to push some arbitrary data onto the stack.
    ///
    /// If the data can be exactly produced by a numeric opcode, that opcode
    /// will be used, since its behavior is equivalent but will not violate minimality
    /// rules. To avoid this, use [`Builder::push_slice_non_minimal`] which will always
    /// use a push opcode.
    ///
    /// However, this method does *not* enforce any numeric minimality rules.
    /// If your pushes should be interpreted as numbers, ensure your input does
    /// not have any leading zeros. In particular, the number 0 should be encoded
    /// as an empty string rather than as a single 0 byte.
    pub fn push_slice<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice(data);
        self
    }

    /// Adds instructions to push some arbitrary data onto the stack without minimality.
    ///
    /// Standardness rules require push minimality according to [CheckMinimalPush] of core.
    ///
    /// [CheckMinimalPush]: <https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.cpp#L366>
    pub fn push_slice_non_minimal<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice_non_minimal(data);
        self
    }

    /// Adds a single opcode to the script.
    pub fn push_opcode(mut self, data: Opcode) -> Self {
        self.0.push_opcode(data);
        self
    }

    /// Converts the `Builder` into `ScriptBuf`.
    pub fn into_script(self) -> ScriptBuf<T> { self.0 }

    /// Returns the internal script
    pub fn as_script(&self) -> &Script<T> { &self.0 }
}

impl<T> Default for Builder<T> {
    fn default() -> Self { Self::new() }
}

/// Constructs a new builder from an existing vector.
impl<T> From<Vec<u8>> for Builder<T> {
    fn from(v: Vec<u8>) -> Self {
        let script = ScriptBuf::from(v);
        Self(script)
    }
}

impl<T> fmt::Display for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl<T> fmt::Debug for Builder<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}
