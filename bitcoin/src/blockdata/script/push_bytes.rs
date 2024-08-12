// SPDX-License-Identifier: CC0-1.0

//! Contains `PushBytes` & co

use core::ops::{Deref, DerefMut};

use crate::prelude::{Borrow, BorrowMut};
use crate::script;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::primitive::*;

/// This module only contains required operations so that outside functions wouldn't accidentally
/// break invariants. Therefore auditing this module should be sufficient.
mod primitive {
    use core::ops::{
        Bound, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive,
    };

    use super::PushBytesError;
    use crate::prelude::{ToOwned, Vec};

    #[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
    fn check_limit(_: usize) -> Result<(), PushBytesError> { Ok(()) }

    #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
    fn check_limit(len: usize) -> Result<(), PushBytesError> {
        if len < 0x100000000 {
            Ok(())
        } else {
            Err(PushBytesError { len })
        }
    }

    /// Byte slices that can be in Bitcoin script.
    ///
    /// The encoding of Bitcoin script restricts data pushes to be less than 2^32 bytes long.
    /// This type represents slices that are guaranteed to be within the limit so they can be put in
    /// the script safely.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    #[repr(transparent)]
    pub struct PushBytes([u8]);

    impl PushBytes {
        /// Creates `&PushBytes` without checking the length.
        ///
        /// # Safety
        ///
        /// The caller is responsible for checking that the length is less than the 2^32.
        unsafe fn from_slice_unchecked(bytes: &[u8]) -> &Self {
            // SAFETY: The caller must guarantee that bytes.len() < 2^32.
            // If that is the case the conversion is sound because &[u8] and &PushBytes
            // have the same layout (because of #[repr(transparent)] on PushBytes).
            &*(bytes as *const [u8] as *const PushBytes)
        }

        /// Creates `&mut PushBytes` without checking the length.
        ///
        /// # Safety
        ///
        /// The caller is responsible for checking that the length is less than the 2^32.
        unsafe fn from_mut_slice_unchecked(bytes: &mut [u8]) -> &mut Self {
            // SAFETY: The caller must guarantee that bytes.len() < 2^32.
            // If that is the case the conversion is sound because &mut [u8] and &mut PushBytes
            // have the same layout (because of #[repr(transparent)] on PushBytes).
            &mut *(bytes as *mut [u8] as *mut PushBytes)
        }

        /// Creates an empty `&PushBytes`.
        pub fn empty() -> &'static Self {
            // SAFETY: 0 < 2^32.
            unsafe { Self::from_slice_unchecked(&[]) }
        }

        /// Returns the underlying bytes.
        pub fn as_bytes(&self) -> &[u8] { &self.0 }

        /// Returns the underlying mutable bytes.
        pub fn as_mut_bytes(&mut self) -> &mut [u8] { &mut self.0 }
    }

    macro_rules! delegate_index {
        ($($type:ty),* $(,)?) => {
            $(
                impl Index<$type> for PushBytes {
                    type Output = Self;

                    #[inline]
                    #[track_caller]
                    fn index(&self, index: $type) -> &Self::Output {
                        // SAFETY: Slicing can not make slices longer.
                        unsafe {
                            Self::from_slice_unchecked(&self.0[index])
                        }
                    }
                }

                impl IndexMut<$type> for PushBytes {
                    #[inline]
                    #[track_caller]
                    fn index_mut(&mut self, index: $type) -> &mut Self::Output {
                        // SAFETY: Slicing can not make slices longer.
                        unsafe {
                            Self::from_mut_slice_unchecked(&mut self.0[index])
                        }
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

    impl Index<usize> for PushBytes {
        type Output = u8;

        #[inline]
        #[track_caller]
        fn index(&self, index: usize) -> &Self::Output { &self.0[index] }
    }

    impl IndexMut<usize> for PushBytes {
        #[inline]
        #[track_caller]
        fn index_mut(&mut self, index: usize) -> &mut Self::Output { &mut self.0[index] }
    }

    impl<'a> TryFrom<&'a [u8]> for &'a PushBytes {
        type Error = PushBytesError;

        fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
            check_limit(bytes.len())?;
            // SAFETY: We've just checked the length.
            Ok(unsafe { PushBytes::from_slice_unchecked(bytes) })
        }
    }

    impl<'a> TryFrom<&'a mut [u8]> for &'a mut PushBytes {
        type Error = PushBytesError;

        fn try_from(bytes: &'a mut [u8]) -> Result<Self, Self::Error> {
            check_limit(bytes.len())?;
            // SAFETY: We've just checked the length.
            Ok(unsafe { PushBytes::from_mut_slice_unchecked(bytes) })
        }
    }

    macro_rules! from_array {
        ($($len:literal),* $(,)?) => {
            $(
                impl<'a> From<&'a [u8; $len]> for &'a PushBytes {
                    fn from(bytes: &'a [u8; $len]) -> Self {
                        // Check that the macro wasn't called with a wrong number.
                        const _: () = [(); 1][($len >= 0x100000000u64) as usize];
                        // SAFETY: We know the size of array statically and we checked macro input.
                        unsafe { PushBytes::from_slice_unchecked(bytes) }
                    }
                }

                impl<'a> From<&'a mut [u8; $len]> for &'a mut PushBytes {
                    fn from(bytes: &'a mut [u8; $len]) -> Self {
                        // Macro check already above, no need to duplicate.
                        // SAFETY: We know the size of array statically and we checked macro input.
                        unsafe { PushBytes::from_mut_slice_unchecked(bytes) }
                    }
                }

                impl AsRef<PushBytes> for [u8; $len] {
                    fn as_ref(&self) -> &PushBytes {
                        self.into()
                    }
                }

                impl AsMut<PushBytes> for [u8; $len] {
                    fn as_mut(&mut self) -> &mut PushBytes {
                        self.into()
                    }
                }

                impl From<[u8; $len]> for PushBytesBuf {
                    fn from(bytes: [u8; $len]) -> Self {
                        PushBytesBuf(Vec::from(&bytes as &[_]))
                    }
                }

                impl<'a> From<&'a [u8; $len]> for PushBytesBuf {
                    fn from(bytes: &'a [u8; $len]) -> Self {
                        PushBytesBuf(Vec::from(bytes as &[_]))
                    }
                }
            )*
        }
    }

    // Sizes up to 73 to support all pubkey and signature sizes
    from_array! {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73,
    }

    /// Owned, growable counterpart to `PushBytes`.
    #[derive(Default, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct PushBytesBuf(Vec<u8>);

    impl PushBytesBuf {
        /// Creates a new empty `PushBytesBuf`.
        #[inline]
        pub const fn new() -> Self { PushBytesBuf(Vec::new()) }

        /// Creates a new empty `PushBytesBuf` with reserved capacity.
        pub fn with_capacity(capacity: usize) -> Self { PushBytesBuf(Vec::with_capacity(capacity)) }

        /// Reserve capacity for `additional_capacity` bytes.
        pub fn reserve(&mut self, additional_capacity: usize) {
            self.0.reserve(additional_capacity)
        }

        /// Try pushing a single byte.
        ///
        /// # Errors
        ///
        /// This method fails if `self` would exceed the limit.
        #[allow(deprecated)]
        pub fn push(&mut self, byte: u8) -> Result<(), PushBytesError> {
            // This is OK on 32 bit archs since vec has its own check and this check is pointless.
            check_limit(self.0.len().saturating_add(1))?;
            self.0.push(byte);
            Ok(())
        }

        /// Try appending a slice to `PushBytesBuf`
        ///
        /// # Errors
        ///
        /// This method fails if `self` would exceed the limit.
        pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), PushBytesError> {
            let len = self.0.len().saturating_add(bytes.len());
            check_limit(len)?;
            self.0.extend_from_slice(bytes);
            Ok(())
        }

        /// Remove the last byte from buffer if any.
        pub fn pop(&mut self) -> Option<u8> { self.0.pop() }

        /// Remove the byte at `index` and return it.
        ///
        /// # Panics
        ///
        /// This method panics if `index` is out of bounds.
        #[track_caller]
        pub fn remove(&mut self, index: usize) -> u8 { self.0.remove(index) }

        /// Remove all bytes from buffer without affecting capacity.
        pub fn clear(&mut self) { self.0.clear() }

        /// Remove bytes from buffer past `len`.
        pub fn truncate(&mut self, len: usize) { self.0.truncate(len) }

        /// Extracts `PushBytes` slice
        pub fn as_push_bytes(&self) -> &PushBytes {
            // length guaranteed by our invariant
            unsafe { PushBytes::from_slice_unchecked(&self.0) }
        }

        /// Extracts mutable `PushBytes` slice
        pub fn as_mut_push_bytes(&mut self) -> &mut PushBytes {
            // length guaranteed by our invariant
            unsafe { PushBytes::from_mut_slice_unchecked(&mut self.0) }
        }

        /// Accesses inner `Vec` - provided for `super` to impl other methods.
        pub(super) fn inner(&self) -> &Vec<u8> { &self.0 }
    }

    impl From<PushBytesBuf> for Vec<u8> {
        fn from(value: PushBytesBuf) -> Self { value.0 }
    }

    impl TryFrom<Vec<u8>> for PushBytesBuf {
        type Error = PushBytesError;

        fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
            // check len
            let _: &PushBytes = vec.as_slice().try_into()?;
            Ok(PushBytesBuf(vec))
        }
    }

    impl ToOwned for PushBytes {
        type Owned = PushBytesBuf;

        fn to_owned(&self) -> Self::Owned { PushBytesBuf(self.0.to_owned()) }
    }
}

impl PushBytes {
    /// Returns the number of bytes in buffer.
    pub fn len(&self) -> usize { self.as_bytes().len() }

    /// Returns true if the buffer contains zero bytes.
    pub fn is_empty(&self) -> bool { self.as_bytes().is_empty() }

    /// Decodes an integer in script(minimal CScriptNum) format.
    ///
    /// Notice that this fails on overflow: the result is the same as in bitcoind, that only 4-byte
    /// signed-magnitude values may be read as numbers. They can be added or subtracted (and a long
    /// time ago, multiplied and divided), and this may result in numbers which can't be written out
    /// in 4 bytes or less. This is ok! The number just can't be read as a number again. This is a
    /// bit crazy and subtle, but it makes sense: you can load 32-bit numbers and do anything with
    /// them, which back when mult/div was allowed, could result in up to a 64-bit number. We don't
    /// want overflow since that's surprising --- and we don't want numbers that don't fit in 64
    /// bits (for efficiency on modern processors) so we simply say, anything in excess of 32 bits
    /// is no longer a number. This is basically a ranged type implementation.
    ///
    /// This code is based on the `CScriptNum` constructor in Bitcoin Core (see `script.h`).
    pub fn read_scriptint(&self) -> Result<i64, script::Error> {
        let last = match self.as_bytes().last() {
            Some(last) => last,
            None => return Ok(0),
        };
        if self.len() > 4 {
            return Err(script::Error::NumericOverflow);
        }
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if self.len() <= 1 || (self[self.len() - 2] & 0x80) == 0 {
                return Err(script::Error::NonMinimalPush);
            }
        }

        Ok(script::scriptint_parse(self.as_bytes()))
    }
}

impl PushBytesBuf {
    /// Returns the number of bytes in buffer.
    pub fn len(&self) -> usize { self.inner().len() }

    /// Returns the number of bytes the buffer can contain without reallocating.
    pub fn capacity(&self) -> usize { self.inner().capacity() }

    /// Returns true if the buffer contains zero bytes.
    pub fn is_empty(&self) -> bool { self.inner().is_empty() }
}

impl AsRef<[u8]> for PushBytes {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl AsMut<[u8]> for PushBytes {
    fn as_mut(&mut self) -> &mut [u8] { self.as_mut_bytes() }
}

impl Deref for PushBytesBuf {
    type Target = PushBytes;

    fn deref(&self) -> &Self::Target { self.as_push_bytes() }
}

impl DerefMut for PushBytesBuf {
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_push_bytes() }
}

impl AsRef<PushBytes> for PushBytes {
    fn as_ref(&self) -> &PushBytes { self }
}

impl AsMut<PushBytes> for PushBytes {
    fn as_mut(&mut self) -> &mut PushBytes { self }
}

impl AsRef<PushBytes> for PushBytesBuf {
    fn as_ref(&self) -> &PushBytes { self.as_push_bytes() }
}

impl AsMut<PushBytes> for PushBytesBuf {
    fn as_mut(&mut self) -> &mut PushBytes { self.as_mut_push_bytes() }
}

impl Borrow<PushBytes> for PushBytesBuf {
    fn borrow(&self) -> &PushBytes { self.as_push_bytes() }
}

impl BorrowMut<PushBytes> for PushBytesBuf {
    fn borrow_mut(&mut self) -> &mut PushBytes { self.as_mut_push_bytes() }
}

/// Reports information about failed conversion into `PushBytes`.
///
/// This should not be needed by general public, except as an additional bound on `TryFrom` when
/// converting to `WitnessProgram`.
pub trait PushBytesErrorReport {
    /// How many bytes the input had.
    fn input_len(&self) -> usize;
}

impl PushBytesErrorReport for core::convert::Infallible {
    #[inline]
    fn input_len(&self) -> usize { match *self {} }
}

pub use error::*;

#[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
mod error {
    use core::fmt;

    /// Error returned on attempt to create too large `PushBytes`.
    #[allow(unused)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PushBytesError {
        never: core::convert::Infallible,
    }

    impl super::PushBytesErrorReport for PushBytesError {
        #[inline]
        fn input_len(&self) -> usize { match self.never {} }
    }

    impl fmt::Display for PushBytesError {
        fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result { match self.never {} }
    }
}

// we have 64 bits in mind, but even for esoteric sizes, this code is correct, since it's the
// conservative one that checks for errors
#[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
mod error {
    use core::fmt;

    /// Error returned on attempt to create too large `PushBytes`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PushBytesError {
        /// How long the input was.
        pub(super) len: usize,
    }

    impl super::PushBytesErrorReport for PushBytesError {
        #[inline]
        fn input_len(&self) -> usize { self.len }
    }

    impl fmt::Display for PushBytesError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "attempt to prepare {} bytes to be pushed into script but the limit is 2^32-1",
                self.len
            )
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
