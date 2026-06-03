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
    #[must_use]
    pub fn push_slice<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice(data);
        self
    }

    /// Adds instructions to push some arbitrary data onto the stack without minimality.
    ///
    /// Standardness rules require push minimality according to [CheckMinimalPush] of core.
    ///
    /// [CheckMinimalPush]: <https://github.com/bitcoin/bitcoin/blob/99a4ddf5ab1b3e514d08b90ad8565827fda7b63b/src/script/script.cpp#L366>
    #[must_use]
    pub fn push_slice_non_minimal<D: AsRef<PushBytes>>(mut self, data: D) -> Self {
        self.0.push_slice_non_minimal(data);
        self
    }

    /// Adds a single opcode to the script.
    #[must_use]
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

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use super::Builder;
    use crate::script::{PushBytes, ScriptSigTag as Tag};

    #[test]
    fn push_slice_minimal() {
        let script = Builder::<Tag>::new().push_slice([0x81]).into_script();
        assert_eq!(script.as_bytes(), &[0x4f]);

        for n in 1u8..=16 {
            let script = Builder::<Tag>::new().push_slice([n]).into_script();
            assert_eq!(script.as_bytes(), &[0x50 + n]);
        }

        let script = Builder::<Tag>::new().push_slice([0u8]).into_script();
        assert_eq!(script.as_bytes(), &[1, 0]);
        let script = Builder::<Tag>::new().push_slice([17u8]).into_script();
        assert_eq!(script.as_bytes(), &[1, 17]);
        let script = Builder::<Tag>::new().push_slice(b"NRA4VR").into_script();
        assert_eq!(script.as_bytes(), &[6, b'N', b'R', b'A', b'4', b'V', b'R']);
    }

    #[test]
    fn push_slice_non_minimal() {
        let script = Builder::<Tag>::new().push_slice_non_minimal([0x81]).into_script();
        assert_eq!(script.as_bytes(), &[1, 0x81]);

        let script = Builder::<Tag>::new().push_slice_non_minimal([1u8]).into_script();
        assert_eq!(script.as_bytes(), &[1, 1]);
    }

    #[test]
    fn push_slice_pushdata1_and_pushdata2() {
        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from([0xab; 0x4b].as_slice()).unwrap())
            .into_script();
        assert_eq!(script.as_bytes()[0], 0x4b);
        assert_eq!(script.len(), 1 + 0x4b);

        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from([0xab; 0x4c].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..2], &[0x4c, 0x4c]);
        assert_eq!(script.len(), 2 + 0x4c);

        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from([0xab; 0xff].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..2], &[0x4c, 0xff]);
        assert_eq!(script.len(), 2 + 0xff);

        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from([0xab; 0x100].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..3], &[0x4d, 0x00, 0x01]);
        assert_eq!(script.len(), 3 + 0x100);

        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from([0xab; 0x102].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..3], &[0x4d, 0x02, 0x01]);
        assert_eq!(script.len(), 3 + 0x102);

        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from(vec![0xab; 0xffff].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..3], &[0x4d, 0xff, 0xff]);
        assert_eq!(script.len(), 3 + 0xffff);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn push_slice_pushdata4_boundary() {
        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from(vec![0u8; 0x10000].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..5], &[0x4e, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(script.len(), 5 + 0x10000);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    #[cfg_attr(miri, ignore)]
    fn push_slice_pushdata4_length_bytes() {
        let len = 0x0102_0304;
        let script = Builder::<Tag>::new()
            .push_slice(<&PushBytes>::try_from(vec![0u8; len].as_slice()).unwrap())
            .into_script();
        assert_eq!(&script.as_bytes()[..5], &[0x4e, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(script.len(), 5 + len);
    }

    #[test]
    fn from_vec() {
        let script = Builder::<Tag>::from(vec![0xac, 0x51]).into_script();
        assert_eq!(script.as_bytes(), &[0xac, 0x51]);
    }

    #[test]
    fn display_delegates_to_script() {
        let builder = Builder::<Tag>::from(vec![0x51, 0x52]);
        let displayed = format!("{}", builder);
        assert!(!displayed.is_empty());
        assert_eq!(displayed, format!("{}", builder.as_script()));
    }
}
