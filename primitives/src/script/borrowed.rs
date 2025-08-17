// SPDX-License-Identifier: CC0-1.0

use core::ops::{
    Bound, Index, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use super::ScriptBuf;
use crate::prelude::{Box, ToOwned, Vec};

internals::transparent_newtype! {
    /// Bitcoin script slice.
    ///
    /// *[See also the `bitcoin::script` module](super).*
    ///
    /// `Script` is a script slice, the most primitive script type. It's usually seen in its borrowed
    /// form `&Script`. It is always encoded as a series of bytes representing the opcodes and data
    /// pushes.
    ///
    /// # Validity
    ///
    /// `Script` does not have any validity invariants - it's essentially just a marked slice of
    /// bytes. This is similar to [`Path`](std::path::Path) vs [`OsStr`](std::ffi::OsStr) where they
    /// are trivially cast-able to each-other and `Path` doesn't guarantee being a usable FS path but
    /// having a newtype still has value because of added methods, readability and basic type checking.
    ///
    /// Although at least data pushes could be checked not to overflow the script, bad scripts are
    /// allowed to be in a transaction (outputs just become unspendable) and there even are such
    /// transactions in the chain. Thus we must allow such scripts to be placed in the transaction.
    ///
    /// # Slicing safety
    ///
    /// Slicing is similar to how `str` works: some ranges may be incorrect and indexing by
    /// `usize` is not supported. However, as opposed to `std`, we have no way of checking
    /// correctness without causing linear complexity so there are **no panics on invalid
    /// ranges!** If you supply an invalid range, you'll get a garbled script.
    ///
    /// The range is considered valid if it's at a boundary of instruction. Care must be taken
    /// especially with push operations because you could get a reference to arbitrary
    /// attacker-supplied bytes that look like a valid script.
    ///
    /// It is recommended to use `.instructions()` method to get an iterator over script
    /// instructions and work with that instead.
    ///
    /// # Memory safety
    ///
    /// The type is `#[repr(transparent)]` for internal purposes only!
    /// No consumer crate may rely on the representation of the struct!
    ///
    /// # Hexadecimal strings
    ///
    /// Scripts are consensus encoded with a length prefix and as a result of this in some places in
    /// the ecosystem one will encounter hex strings that include the prefix while in other places
    /// the prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch
    /// of different APIs and trait implementations. Please see [`examples/script.rs`] for a
    /// thorough example of all the APIs.
    ///
    /// # Bitcoin Core References
    ///
    /// * [CScript definition](https://github.com/bitcoin/bitcoin/blob/d492dc1cdaabdc52b0766bf4cba4bd73178325d0/src/script/script.h#L410)
    ///
    #[derive(PartialOrd, Ord, PartialEq, Eq, Hash)]
    pub struct Script([u8]);

    impl Script {
        /// Treat byte slice as `Script`
        pub const fn from_bytes(bytes: &_) -> &Self;

        /// Treat mutable byte slice as `Script`
        pub fn from_bytes_mut(bytes: &mut _) -> &mut Self;

        pub(crate) fn from_boxed_bytes(bytes: Box<_>) -> Box<Self>;
        pub(crate) fn from_rc_bytes(bytes: Rc<_>) -> Rc<Self>;
        pub(crate) fn from_arc_bytes(bytes: Arc<_>) -> Arc<Self>;
    }
}

impl Default for &Script {
    #[inline]
    fn default() -> Self { Script::new() }
}

impl ToOwned for Script {
    type Owned = ScriptBuf;

    #[inline]
    fn to_owned(&self) -> Self::Owned { ScriptBuf::from_bytes(self.to_vec()) }
}

impl Script {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> &'static Self { Self::from_bytes(&[]) }

    /// Returns the script data as a byte slice.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] { &self.0 }

    /// Returns the script data as a mutable byte slice.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] { &mut self.0 }

    /// Returns a copy of the script data.
    ///
    /// This is just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> { self.as_bytes().to_owned() }

    /// Returns a copy of the script data.
    #[inline]
    #[deprecated(since = "TBD", note = "use to_vec instead")]
    pub fn to_bytes(&self) -> Vec<u8> { self.to_vec() }

    /// Returns the length in bytes of the script.
    #[inline]
    pub const fn len(&self) -> usize { self.as_bytes().len() }

    /// Returns whether the script is the empty script.
    #[inline]
    pub const fn is_empty(&self) -> bool { self.as_bytes().is_empty() }

    /// Converts a [`Box<Script>`](Box) into a [`ScriptBuf`] without copying or allocating.
    #[must_use]
    #[inline]
    pub fn into_script_buf(self: Box<Self>) -> ScriptBuf {
        let rw = Box::into_raw(self) as *mut [u8];
        // SAFETY: copied from `std`
        // The pointer was just created from a box without deallocating
        // Casting a transparent struct wrapping a slice to the slice pointer is sound (same
        // layout).
        let inner = unsafe { Box::from_raw(rw) };
        ScriptBuf::from_bytes(Vec::from(inner))
    }

    /// Gets the hex representation of this script.
    ///
    /// # Returns
    ///
    /// Just the script bytes in hexadecimal **not** consensus encoding of the script i.e., the
    /// string will not include a length prefix.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[inline]
    #[deprecated(since = "TBD", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(&self) -> alloc::string::String { alloc::format!("{:x}", self) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for &'a Script {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = <&'a [u8]>::arbitrary(u)?;
        Ok(Script::from_bytes(v))
    }
}

macro_rules! delegate_index {
    ($($type:ty),* $(,)?) => {
        $(
            /// Script subslicing operation - read [slicing safety](#slicing-safety)!
            impl Index<$type> for Script {
                type Output = Self;

                #[inline]
                fn index(&self, index: $type) -> &Self::Output {
                    Self::from_bytes(&self.as_bytes()[index])
                }
            }
        )*
    }
}

delegate_index!(
    Range<usize>,
    RangeFrom<usize>,
    RangeTo<usize>,
    RangeFull,
    RangeInclusive<usize>,
    RangeToInclusive<usize>,
    (Bound<usize>, Bound<usize>)
);

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;

    #[test]
    fn script_from_bytes() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn script_from_bytes_mut() {
        let bytes = &mut [1, 2, 3];
        let script = Script::from_bytes_mut(bytes);
        script.as_mut_bytes()[0] = 4;
        assert_eq!(script.as_mut_bytes(), [4, 2, 3]);
    }

    #[test]
    fn script_to_vec() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn script_len() {
        let script = Script::from_bytes(&[1, 2, 3]);
        assert_eq!(script.len(), 3);
    }

    #[test]
    fn script_is_empty() {
        let script: &Script = Default::default();
        assert!(script.is_empty());

        let script = Script::from_bytes(&[1, 2, 3]);
        assert!(!script.is_empty());
    }

    #[test]
    fn script_to_owned() {
        let script = Script::from_bytes(&[1, 2, 3]);
        let script_buf = script.to_owned();
        assert_eq!(script_buf.as_bytes(), [1, 2, 3]);
    }

    #[test]
    fn test_index() {
        let script = Script::from_bytes(&[1, 2, 3, 4, 5]);

        assert_eq!(script[1..3].as_bytes(), &[2, 3]);
        assert_eq!(script[2..].as_bytes(), &[3, 4, 5]);
        assert_eq!(script[..3].as_bytes(), &[1, 2, 3]);
        assert_eq!(script[..].as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(script[1..=3].as_bytes(), &[2, 3, 4]);
        assert_eq!(script[..=2].as_bytes(), &[1, 2, 3]);
    }
}
