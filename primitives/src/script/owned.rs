// SPDX-License-Identifier: CC0-1.0

#[cfg(doc)]
use core::ops::Deref;

#[cfg(feature = "hex")]
use hex::FromHex;

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
    /// Creates a new empty script.
    #[inline]
    pub const fn new() -> Self { ScriptBuf(Vec::new()) }

    /// Creates a new empty script with pre-allocated capacity.
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

    /// Returns a reference to unsized script.
    pub fn as_script(&self) -> &Script { Script::from_bytes(&self.0) }

    /// Returns a mutable reference to unsized script.
    pub fn as_mut_script(&mut self) -> &mut Script { Script::from_bytes_mut(&mut self.0) }

    /// Creates a [`ScriptBuf`] from a hex string.
    #[cfg(feature = "hex")]
    pub fn from_hex(s: &str) -> Result<Self, hex::HexToBytesError> {
        let v = Vec::from_hex(s)?;
        Ok(ScriptBuf::from_bytes(v))
    }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate.
    pub fn from_bytes(bytes: Vec<u8>) -> Self { ScriptBuf(bytes) }

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
    #[must_use = "`self` will be dropped if the result is not used"]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script> {
        // Copied from PathBuf::into_boxed_path
        let rw = Box::into_raw(self.0.into_boxed_slice()) as *mut Script;
        unsafe { Box::from_raw(rw) }
    }

    /// Pushes `n` onto the script.
    ///
    /// Only meant for usage by the `bitcoin::script::ScriptBufExt` trait, consider using the API
    /// provided by that trait.
    #[doc(hidden)]
    pub fn push(&mut self, n: u8) { self.0.push(n) }

    /// Pops the last byte from the script if there is one.
    ///
    /// Only meant for usage by the `bitcoin::script::ScriptBufExt` trait, consider using the API
    /// provided by that trait.
    #[doc(hidden)]
    pub fn pop(&mut self) -> Option<u8> { self.0.pop() }

    /// Extends the script with bytes from `other`.
    ///
    /// Only meant for usage by the `bitcoin::script::ScriptBufExt` trait, consider using the API
    /// provided by that trait.
    #[doc(hidden)]
    pub fn extend_from_slice(&mut self, other: &[u8]) { self.0.extend_from_slice(other) }
}
