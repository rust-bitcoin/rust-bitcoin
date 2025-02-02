// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use super::Script;
use crate::prelude::{Box, Vec};

/// An owned, growable script.
///
/// `ScriptBuf` is the most common script type that has the ownership over the contents of the
/// script. It has a close relationship with its borrowed counterpart, [`Script`].
///
/// Just as other similar types, this implements [`Deref`], so [deref coercions] apply. Also note
/// that all the safety/validity restrictions that apply to [`Script`] apply to `ScriptBuf` as well.
///
/// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
#[derive(Default, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptBuf(pub(in crate::script) Vec<u8>);

impl ScriptBuf {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { ScriptBuf(Vec::new()) }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate.
    pub fn from_bytes(bytes: Vec<u8>) -> Self { ScriptBuf(bytes) }

    /// Returns a reference to unsized script.
    pub fn as_script(&self) -> &Script { Script::from_bytes(&self.0) }

    /// Returns a mutable reference to unsized script.
    pub fn as_mut_script(&mut self) -> &mut Script { Script::from_bytes_mut(&mut self.0) }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    pub fn into_bytes(self) -> Vec<u8> { self.0 }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than length of the script but should not
    /// when they are equal. If you know beforehand that you need to create a script of exact size
    /// use [`reserve_exact`](Self::reserve_exact) before adding data to the script so that the
    /// reallocation can be avoided.
    #[must_use]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script> {
        // Copied from PathBuf::into_boxed_path
        let rw = Box::into_raw(self.0.into_boxed_slice()) as *mut Script;
        unsafe { Box::from_raw(rw) }
    }

    /// Constructs a new empty script with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self { ScriptBuf(Vec::with_capacity(capacity)) }

    /// Pre-allocates at least `additional_len` bytes if needed.
    ///
    /// Reserves capacity for at least `additional_len` more bytes to be inserted in the given
    /// script. The script may reserve more space to speculatively avoid frequent reallocations.
    /// After calling `reserve`, capacity will be greater than or equal to
    /// `self.len() + additional_len`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    pub fn reserve(&mut self, additional_len: usize) { self.0.reserve(additional_len); }

    /// Pre-allocates exactly `additional_len` bytes if needed.
    ///
    /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
    /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
    /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
    ///
    /// Note that the allocator may give the collection more space than it requests. Therefore,
    /// capacity can not be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
    /// if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    pub fn reserve_exact(&mut self, additional_len: usize) { self.0.reserve_exact(additional_len); }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ScriptBuf {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = Vec::<u8>::arbitrary(u)?;
        Ok(ScriptBuf(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_buf_from_bytes() {
        let bytes = vec![1, 2, 3];
        let script = ScriptBuf::from_bytes(bytes.clone());
        assert_eq!(script.0, bytes);
    }

    #[test]
    fn script_buf_as_script() {
        let bytes = vec![1, 2, 3];
        let script = ScriptBuf::from_bytes(bytes.clone());
        let script_ref = script.as_script();
        assert_eq!(script_ref.as_bytes(), bytes);
    }

    #[test]
    fn script_buf_as_mut_script() {
        let bytes = vec![1, 2, 3];
        let mut script = ScriptBuf::from_bytes(bytes.clone());
        let script_mut_ref = script.as_mut_script();
        script_mut_ref.as_mut_bytes()[0] = 4;
        assert_eq!(script.0, vec![4, 2, 3]);
    }

    #[test]
    fn script_buf_into_bytes() {
        let bytes = vec![1, 2, 3];
        let script = ScriptBuf::from_bytes(bytes.clone());
        let result = script.into_bytes();
        assert_eq!(result, bytes);
    }

    #[test]
    fn script_buf_into_boxed_script() {
        let bytes = vec![1, 2, 3];
        let script = ScriptBuf::from_bytes(bytes.clone());
        let boxed_script = script.into_boxed_script();
        assert_eq!(boxed_script.as_bytes(), bytes);
    }

    #[test]
    fn script_buf_capacity() {
        let script = ScriptBuf::with_capacity(10);
        assert!(script.0.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve() {
        let mut script = ScriptBuf::new();
        script.reserve(10);
        assert!(script.0.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve_exact() {
        let mut script = ScriptBuf::new();
        script.reserve_exact(10);
        assert!(script.0.capacity() >= 10);
    }
}
