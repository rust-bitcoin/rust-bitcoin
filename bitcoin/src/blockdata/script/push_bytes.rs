//! Contains `PushBytes` & co

use core::ops::{Deref, DerefMut};
use core::borrow::{Borrow, BorrowMut};
#[allow(unused)]
use crate::prelude::*;

pub use primitive::*;

/// This module only contains required operations so that outside functions wouldn't accidentally
/// break invariants. Therefore auditing this module should be sufficient.
mod primitive {
    #[allow(unused)]
    use crate::prelude::*;

    use super::PushBytesError;
    use core::convert::{TryFrom, TryInto};
    use core::ops::{Index, Range, RangeFull, RangeFrom, RangeTo, RangeInclusive, RangeToInclusive};
    #[cfg(feature = "rust_v_1_53")]
    use core::ops::Bound;

    #[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
    fn check_limit(len: usize) -> Result<(), PushBytesError> {
        Ok(())
    }

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
        /// Creates `&Self` without checking the length.
        ///
        /// ## Safety
        ///
        /// The caller is responsible for checking that the length is less than the [`LIMIT`].
        unsafe fn from_slice_unchecked(bytes: &[u8]) -> &Self {
            &*(bytes as *const [u8] as *const PushBytes)
        }

        /// Creates `&mut Self` without checking the length.
        ///
        /// ## Safety
        ///
        /// The caller is responsible for checking that the length is less than the [`LIMIT`].
        unsafe fn from_mut_slice_unchecked(bytes: &mut [u8]) -> &mut Self {
            &mut *(bytes as *mut [u8] as *mut PushBytes)
        }

        /// Creates an empty `PushBytes`.
        pub fn empty() -> &'static Self {
            // 0 < LIMIT
            unsafe { Self::from_slice_unchecked(&[]) }
        }

        /// Returns the underlying bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        /// Returns the underlying mutbale bytes.
        pub fn as_mut_bytes(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    macro_rules! delegate_index {
        ($($type:ty),* $(,)?) => {
            $(
                /// Script subslicing operation - read [slicing safety](#slicing-safety)!
                impl Index<$type> for PushBytes {
                    type Output = Self;

                    #[inline]
                    #[cfg_attr(rust_v_1_46, track_caller)]
                    fn index(&self, index: $type) -> &Self::Output {
                        // Slicing can not make slices longer
                        unsafe {
                            Self::from_slice_unchecked(&self.0[index])
                        }
                    }
                }
            )*
        }
    }

    delegate_index!(Range<usize>, RangeFrom<usize>, RangeTo<usize>, RangeFull, RangeInclusive<usize>, RangeToInclusive<usize>);
    #[cfg(feature = "rust_v_1_53")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rust_v_1_53")))]
    delegate_index!((Bound<usize>, Bound<usize>));

    impl Index<usize> for PushBytes {
        type Output = u8;

        #[inline]
        #[cfg_attr(rust_v_1_46, track_caller)]
        fn index(&self, index: usize) -> &Self::Output {
            &self.0[index]
        }
    }

    impl<'a> TryFrom<&'a [u8]> for &'a PushBytes {
        type Error = PushBytesError;

        fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
            check_limit(bytes.len())?;
            // We've just checked the length
            Ok(unsafe { PushBytes::from_slice_unchecked(bytes) })
        }
    }

    impl<'a> TryFrom<&'a mut [u8]> for &'a mut PushBytes {
        type Error = PushBytesError;

        fn try_from(bytes: &'a mut [u8]) -> Result<Self, Self::Error> {
            check_limit(bytes.len())?;
            // We've just checked the length
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
                        // We know the size of array statically and we checked macro input.
                        unsafe { PushBytes::from_slice_unchecked(bytes) }
                    }
                }

                impl<'a> From<&'a mut [u8; $len]> for &'a mut PushBytes {
                    fn from(bytes: &'a mut [u8; $len]) -> Self {
                        // Macro check already above, no need to duplicate.
                        // We know the size of array statically and we checked macro input.
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
        pub fn new() -> Self {
            PushBytesBuf(Vec::new())
        }

        /// Creates a new empty `PushBytesBuf` with reserved capacity.
        pub fn with_capacity(capacity: usize) -> Self {
            PushBytesBuf(Vec::with_capacity(capacity))
        }

        /// Reserve capacity for `additional_capacity` bytes.
        pub fn reserve(&mut self, additional_capacity: usize) {
            self.0.reserve(additional_capacity)
        }

        /// Try pushing a single byte.
        ///
        /// ## Errors
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
        /// ## Errors
        ///
        /// This method fails if `self` would exceed the limit.
        pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), PushBytesError> {
            let len = self.0.len().saturating_add(bytes.len());
            check_limit(len)?;
            self.0.extend_from_slice(bytes);
            Ok(())
        }

        /// Remove the last byte from buffer if any.
        pub fn pop(&mut self) -> Option<u8> {
            self.0.pop()
        }

        /// Remove the byte at `index` and return it.
        ///
        /// ## Panics
        ///
        /// This method panics if `index` is out of bounds.
        #[cfg_attr(rust_v_1_46, track_caller)]
        pub fn remove(&mut self, index: usize) -> u8 {
            self.0.remove(index)
        }

        /// Remove all bytes from buffer without affecting capacity.
        pub fn clear(&mut self) {
            self.0.clear()
        }

        /// Remove bytes from buffer past `len`.
        pub fn truncate(&mut self, len: usize) {
            self.0.truncate(len)
        }

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
        pub(super) fn inner(&self) -> &Vec<u8> {
            &self.0
        }
    }

    impl From<PushBytesBuf> for Vec<u8> {
        fn from(value: PushBytesBuf) -> Self {
            value.0
        }
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

        fn to_owned(&self) -> Self::Owned {
            PushBytesBuf(self.0.to_owned())
        }
    }
}

impl PushBytes {
    /// Returns the number of bytes in buffer.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns true if the buffer contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}

impl PushBytesBuf {
    /// Returns the number of bytes in buffer.
    pub fn len(&self) -> usize {
        self.inner().len()
    }

    /// Returns the number of bytes the buffer can contain without reallocating.
    pub fn capacity(&self) -> usize {
        self.inner().capacity()
    }

    /// Returns true if the buffer contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.inner().is_empty()
    }
}

impl AsRef<[u8]> for PushBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for PushBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl Deref for PushBytesBuf {
    type Target = PushBytes;

    fn deref(&self) -> &Self::Target {
        self.as_push_bytes()
    }
}

impl DerefMut for PushBytesBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_push_bytes()
    }
}

impl AsRef<PushBytes> for PushBytes {
    fn as_ref(&self) -> &PushBytes {
        self
    }
}

impl AsMut<PushBytes> for PushBytes {
    fn as_mut(&mut self) -> &mut PushBytes {
        self
    }
}

impl AsRef<PushBytes> for PushBytesBuf {
    fn as_ref(&self) -> &PushBytes {
        self.as_push_bytes()
    }
}

impl AsMut<PushBytes> for PushBytesBuf {
    fn as_mut(&mut self) -> &mut PushBytes {
        self.as_mut_push_bytes()
    }
}

impl Borrow<PushBytes> for PushBytesBuf {
    fn borrow(&self) -> &PushBytes {
        self.as_push_bytes()
    }
}

impl BorrowMut<PushBytes> for PushBytesBuf {
    fn borrow_mut(&mut self) -> &mut PushBytes {
        self.as_mut_push_bytes()
    }
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
    fn input_len(&self) -> usize {
        match *self {}
    }
}

pub use error::*;

#[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
mod error {
    use core::fmt;

    /// Error returned on attempt to create too large `PushBytes`.
    #[allow(unused)]
    #[derive(Debug, Clone)]
    pub struct PushBytesError {
        never: core::convert::Infallible,
    }

    impl super::PushBytesErrorReport for PushBytesError {
        #[inline]
        fn input_len(&self) -> usize {
            match self.never {}
        }
    }

    impl fmt::Display for PushBytesError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self.never {}
        }
    }
}

// we have 64 bits in mind, but even for esoteric sizes, this code is correct, since it's the
// conservative one that checks for errors
#[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
mod error {
    use core::fmt;

    /// Error returned on attempt to create too large `PushBytes`.
    #[derive(Debug, Clone)]
    pub struct PushBytesError {
        /// How long the input was.
        pub(super) len: usize
    }

    impl super::PushBytesErrorReport for PushBytesError {
        #[inline]
        fn input_len(&self) -> usize {
            self.len
        }
    }

    impl fmt::Display for PushBytesError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "attempt to prepare {} bytes to be pushed into script but the limit is 2^32-1", self.len)
        }
    }
}

crate::error::impl_std_error!(PushBytesError);
