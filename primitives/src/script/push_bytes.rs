// SPDX-License-Identifier: CC0-1.0

//! Contains `PushBytes` & co

use core::borrow::{Borrow, BorrowMut};
use core::convert::Infallible;
use core::ops::{Deref, DerefMut};

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
// This is not the usual re-export, `primitive` here is a code audit thing.
pub use self::primitive::{PushBytes, PushBytesBuf};

/// This module only contains required operations so that outside functions wouldn't accidentally
/// break invariants. Therefore auditing this module should be sufficient.
mod primitive {
    use alloc::borrow::ToOwned;
    use alloc::vec::Vec;
    use core::ops::{
        Bound, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive,
    };

    use super::PushBytesError;

    #[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
    fn check_limit(_: usize) -> Result<(), PushBytesError> { Ok(()) }

    #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
    fn check_limit(len: usize) -> Result<(), PushBytesError> {
        if len < 0x1_0000_0000 {
            Ok(())
        } else {
            Err(PushBytesError { len })
        }
    }

    // Defined in `REPO_DIR/include/newtype.rs`.
    crate::transparent_newtype! {
        /// Byte slices that can be in Bitcoin script.
        ///
        /// The encoding of Bitcoin script restricts data pushes to be less than 2^32 bytes long.
        /// This type represents slices that are guaranteed to be within the limit so they can be put in
        /// the script safely.
        #[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct PushBytes([u8]);

        impl PushBytes {
            /// Constructs a new `&PushBytes` without checking the length.
            ///
            /// The caller is responsible for checking that the length is less than the 2^32.
            fn from_slice_unchecked(bytes: &_) -> &Self;

            /// Constructs a new `&mut PushBytes` without checking the length.
            ///
            /// The caller is responsible for checking that the length is less than the 2^32.
            fn from_mut_slice_unchecked(bytes: &mut _) -> &mut Self;
        }
    }

    impl PushBytes {
        /// Constructs an empty `&PushBytes`.
        pub fn empty() -> &'static Self { Self::from_slice_unchecked(&[]) }

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
                        Self::from_slice_unchecked(&self.0[index])
                    }
                }

                impl IndexMut<$type> for PushBytes {
                    #[inline]
                    #[track_caller]
                    fn index_mut(&mut self, index: $type) -> &mut Self::Output {
                        Self::from_mut_slice_unchecked(&mut self.0[index])
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
            Ok(PushBytes::from_slice_unchecked(bytes))
        }
    }

    impl<'a> TryFrom<&'a mut [u8]> for &'a mut PushBytes {
        type Error = PushBytesError;

        fn try_from(bytes: &'a mut [u8]) -> Result<Self, Self::Error> {
            check_limit(bytes.len())?;
            Ok(PushBytes::from_mut_slice_unchecked(bytes))
        }
    }

    macro_rules! from_array {
        ($($len:literal),* $(,)?) => {
            $(
                impl<'a> From<&'a [u8; $len]> for &'a PushBytes {
                    fn from(bytes: &'a [u8; $len]) -> Self {
                        // Check that the macro wasn't called with a wrong number.
                        const _: () = [(); 1][($len >= 0x100000000u64) as usize];
                        PushBytes::from_slice_unchecked(bytes)
                    }
                }

                impl<'a> From<&'a mut [u8; $len]> for &'a mut PushBytes {
                    fn from(bytes: &'a mut [u8; $len]) -> Self {
                        // Macro check already above, no need to duplicate.
                        // We know the size of array statically and we checked macro input.
                        PushBytes::from_mut_slice_unchecked(bytes)
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
                        PushBytesBuf(Vec::from(&bytes))
                    }
                }

                impl<'a> From<&'a [u8; $len]> for PushBytesBuf {
                    fn from(bytes: &'a [u8; $len]) -> Self {
                        PushBytesBuf(Vec::from(bytes))
                    }
                }
            )*
        }
    }

    // Sizes up to 76 to support all pubkey and signature sizes
    from_array! {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76
    }

    /// Owned, growable counterpart to `PushBytes`.
    #[derive(Default, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct PushBytesBuf(Vec<u8>);

    impl PushBytesBuf {
        /// Constructs an empty `PushBytesBuf`.
        #[inline]
        pub const fn new() -> Self { Self(Vec::new()) }

        /// Constructs an empty `PushBytesBuf` with reserved capacity.
        pub fn with_capacity(capacity: usize) -> Self { Self(Vec::with_capacity(capacity)) }

        /// Reserve capacity for `additional_capacity` bytes.
        pub fn reserve(&mut self, additional_capacity: usize) {
            self.0.reserve(additional_capacity);
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
            PushBytes::from_slice_unchecked(&self.0)
        }

        /// Extracts mutable `PushBytes` slice
        pub fn as_mut_push_bytes(&mut self) -> &mut PushBytes {
            // length guaranteed by our invariant
            PushBytes::from_mut_slice_unchecked(&mut self.0)
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
            Ok(Self(vec))
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

impl AsRef<Self> for PushBytes {
    fn as_ref(&self) -> &Self { self }
}

impl AsMut<Self> for PushBytes {
    fn as_mut(&mut self) -> &mut Self { self }
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

crate::impl_asref_push_bytes! {
    hashes::ripemd160::Hash,
    hashes::hash160::Hash,
    hashes::sha1::Hash,
    hashes::sha256::Hash,
    hashes::sha256d::Hash,
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

#[doc(no_inline)]
pub use error::PushBytesError;

#[cfg(any(target_pointer_width = "16", target_pointer_width = "32"))]
mod error {
    use core::fmt;

    /// Error returned on attempt to create too large `PushBytes`.
    #[allow(unused)]
    #[derive(Debug, Clone, PartialEq, Eq)]
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
    #[derive(Debug, Clone, PartialEq, Eq)]
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

impl From<Infallible> for PushBytesError {
    fn from(never: Infallible) -> Self { match never {} }
}

#[cfg(feature = "std")]
impl std::error::Error for PushBytesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn push_bytes_empty_inits() {
        let pb = PushBytes::empty();
        assert!(pb.is_empty());
        assert_eq!(pb.len(), 0);
        assert_eq!(pb.as_bytes(), &[0u8; 0]);

        let pb = PushBytesBuf::new();
        assert!(pb.is_empty());
        assert_eq!(pb.len(), 0);
        assert_eq!(pb.as_bytes(), &[0u8; 0]);

        let pb = PushBytesBuf::default();
        assert!(pb.is_empty());
        assert_eq!(pb.len(), 0);
        assert_eq!(pb.as_bytes(), &[0u8; 0]);
    }

    #[test]
    fn push_bytes_try_from_slice() {
        let data = [0x01, 0x02, 0x03];
        let pb = <&PushBytes>::try_from(data.as_slice()).unwrap();
        assert_eq!(pb.as_bytes(), &data);
        assert_eq!(pb.len(), 3);
        assert!(!pb.is_empty());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    #[cfg_attr(miri, ignore)]
    fn push_bytes_check_limit_boundary() {
        // The limit is len < 2^32; a slice of exactly 2^32 bytes must be rejected.
        // It's insane to allocate that much memory for a test case, so we have to fake
        // it with unsafe pointer antics.
        // Safety: try_from only reads bytes.len(), it never accesses the pointed-to data.
        let ptr = core::ptr::NonNull::<u8>::dangling().as_ptr();
        let too_long: &[u8] = unsafe { core::slice::from_raw_parts(ptr, 0x1_0000_0000) };
        assert!(<&PushBytes>::try_from(too_long).is_err());
    }

    #[test]
    fn push_bytes_from_array() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let pb: &PushBytes = (&data).into();
        assert_eq!(pb.as_bytes(), &data);
    }

    #[test]
    fn push_bytes_asref_array() {
        let data = [0x01, 0x02];
        let pb: &PushBytes = data.as_ref();
        assert_eq!(pb.as_bytes(), &data);
    }

    #[test]
    fn push_bytes_index() {
        let data = [0x01, 0x02, 0x03];
        let pb: &PushBytes = (&data).into();
        assert_eq!(pb[0], 0x01);
        assert_eq!(pb[2], 0x03);
        let slice = &pb[1..];
        assert_eq!(slice.as_bytes(), &[0x02, 0x03]);
    }

    #[test]
    fn push_bytes_as_mut_bytes() {
        let mut data = [0x01, 0x02, 0x03];
        let pb: &mut PushBytes = (&mut data).into();
        pb.as_mut_bytes()[0] = 0xff;
        assert_eq!(data, [0xff, 0x02, 0x03]);
    }

    #[test]
    fn push_bytes_buf_with_capacity() {
        let buf = PushBytesBuf::with_capacity(16);
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 16);
    }

    #[test]
    fn push_bytes_buf_push_and_pop() {
        let mut buf = PushBytesBuf::new();
        buf.push(0x01).unwrap();
        buf.push(0x02).unwrap();
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());
        assert_eq!(buf.pop(), Some(0x02));
        assert_eq!(buf.pop(), Some(0x01));
        assert_eq!(buf.pop(), None);
        assert!(buf.is_empty());
    }

    #[test]
    fn push_bytes_buf_reserve() {
        let mut buf = PushBytesBuf::new();
        assert_eq!(buf.capacity(), 0);
        buf.reserve(32);
        assert!(buf.capacity() >= 32);
    }

    #[test]
    fn push_bytes_buf_extend_from_slice() {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(buf.as_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn push_bytes_buf_clear() {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&[0x01, 0x02]).unwrap();
        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn push_bytes_buf_truncate() {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        buf.truncate(2);
        assert_eq!(buf.as_bytes(), &[0x01, 0x02]);
    }

    #[test]
    fn push_bytes_buf_remove() {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03]).unwrap();
        let removed = buf.remove(1);
        assert_eq!(removed, 0x02);
        assert_eq!(buf.as_bytes(), &[0x01, 0x03]);
    }

    #[test]
    fn push_bytes_buf_from_array() {
        let buf = PushBytesBuf::from([0x01, 0x02, 0x03]);
        assert_eq!(buf.as_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn push_bytes_buf_try_from_vec() {
        let vec = vec![0x01, 0x02, 0x03];
        let buf = PushBytesBuf::try_from(vec.clone()).unwrap();
        assert_eq!(buf.as_bytes(), &vec[..]);
    }

    #[test]
    fn push_bytes_buf_into_vec() {
        let buf = PushBytesBuf::from([0x01, 0x02]);
        let vec: alloc::vec::Vec<u8> = buf.into();
        assert_eq!(vec, [0x01, 0x02]);
    }

    #[test]
    fn push_bytes_buf_as_push_bytes() {
        let buf = PushBytesBuf::from([0xab, 0xcd]);
        let pb: &PushBytes = buf.as_push_bytes();
        assert_eq!(pb.as_bytes(), &[0xab, 0xcd]);
    }

    #[test]
    fn push_bytes_buf_deref() {
        let buf = PushBytesBuf::from([0x01, 0x02]);
        let pb: &PushBytes = &buf;
        assert_eq!(pb.as_bytes(), buf.as_bytes());
    }

    #[test]
    fn push_bytes_buf_to_owned() {
        use alloc::borrow::ToOwned;
        let data = [0x01, 0x02, 0x03];
        let pb: &PushBytes = (&data).into();
        let owned: PushBytesBuf = pb.to_owned();
        assert_eq!(owned.as_bytes(), pb.as_bytes());
    }
}
