//! Implements [`SerializedSignature`] and related types.
//!
//! Serialized Taproot signatures have the issue that they can have different lengths.
//! We want to avoid using `Vec` since that would require allocations making the code slower and
//! unable to run on platforms without an allocator. We implement a special type to encapsulate
//! serialized signatures and since it's a bit more complicated it has its own module.

use core::borrow::Borrow;
use core::convert::TryFrom;
use core::{fmt, ops};

pub use into_iter::IntoIter;

use super::{SigFromSliceError, Signature};

pub(crate) const MAX_LEN: usize = 65; // 64 for sig, 1B sighash flag

/// A serialized Taproot Signature
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_LEN],
    len: usize,
}

impl fmt::Debug for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; MAX_LEN * 2];
        let mut encoder = hex::buf_encoder::BufEncoder::new(&mut buf);
        encoder.put_bytes(self, hex::Case::Lower);
        f.pad_integral(true, "0x", encoder.as_str())
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool { **self == **other }
}

impl PartialEq<[u8]> for SerializedSignature {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool { **self == *other }
}

impl PartialEq<SerializedSignature> for [u8] {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool { *self == **other }
}

impl PartialOrd for SerializedSignature {
    fn partial_cmp(&self, other: &SerializedSignature) -> Option<core::cmp::Ordering> {
        Some((**self).cmp(&**other))
    }
}

impl Ord for SerializedSignature {
    fn cmp(&self, other: &SerializedSignature) -> core::cmp::Ordering { (**self).cmp(&**other) }
}

impl PartialOrd<[u8]> for SerializedSignature {
    fn partial_cmp(&self, other: &[u8]) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(other)
    }
}

impl PartialOrd<SerializedSignature> for [u8] {
    fn partial_cmp(&self, other: &SerializedSignature) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&**other)
    }
}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { (**self).hash(state) }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] { self }
}

impl Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] { self }
}

impl ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] { &self.data[..self.len] }
}

impl Eq for SerializedSignature {}

impl IntoIterator for SerializedSignature {
    type IntoIter = IntoIter;
    type Item = u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { IntoIter::new(self) }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}

impl From<Signature> for SerializedSignature {
    fn from(value: Signature) -> Self { Self::from_signature(&value) }
}

impl<'a> From<&'a Signature> for SerializedSignature {
    fn from(value: &'a Signature) -> Self { Self::from_signature(value) }
}

impl TryFrom<SerializedSignature> for Signature {
    type Error = SigFromSliceError;

    fn try_from(value: SerializedSignature) -> Result<Self, Self::Error> { value.to_signature() }
}

impl<'a> TryFrom<&'a SerializedSignature> for Signature {
    type Error = SigFromSliceError;

    fn try_from(value: &'a SerializedSignature) -> Result<Self, Self::Error> {
        value.to_signature()
    }
}

impl SerializedSignature {
    /// Creates `SerializedSignature` from data and length.
    ///
    /// ## Panics
    ///
    /// If `len` > `MAX_LEN`
    #[inline]
    pub(crate) fn from_raw_parts(data: [u8; MAX_LEN], len: usize) -> Self {
        assert!(len <= MAX_LEN, "attempt to set length to {} but the maximum is {}", len, MAX_LEN);
        SerializedSignature { data, len }
    }

    /// Get the len of the used data.
    // `len` is never 0, so `is_empty` would always return `false`.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize { self.len }

    /// Set the length of the object.
    #[inline]
    pub(crate) fn set_len_unchecked(&mut self, len: usize) { self.len = len; }

    /// Convert the serialized signature into the Signature struct.
    /// (This deserializes it)
    #[inline]
    pub fn to_signature(&self) -> Result<Signature, SigFromSliceError> {
        Signature::from_slice(self)
    }

    /// Create a SerializedSignature from a Signature.
    /// (this serializes it)
    #[inline]
    pub fn from_signature(sig: &Signature) -> SerializedSignature { sig.serialize() }
}

/// Separate mod to prevent outside code from accidentally breaking invariants.
mod into_iter {
    use super::*;

    /// Owned iterator over the bytes of [`SerializedSignature`]
    ///
    /// Created by [`IntoIterator::into_iter`] method.
    // allowed because of https://github.com/rust-lang/rust/issues/98348
    #[allow(missing_copy_implementations)]
    #[derive(Debug, Clone)]
    pub struct IntoIter {
        signature: SerializedSignature,
        // invariant: pos <= signature.len()
        pos: usize,
    }

    impl IntoIter {
        #[inline]
        pub(crate) fn new(signature: SerializedSignature) -> Self {
            IntoIter {
                signature,
                // for all unsigned n: 0 <= n
                pos: 0,
            }
        }

        /// Returns the remaining bytes as a slice.
        ///
        /// This method is analogous to [`core::slice::Iter::as_slice`].
        #[inline]
        pub fn as_slice(&self) -> &[u8] { &self.signature[self.pos..] }
    }

    impl Iterator for IntoIter {
        type Item = u8;

        #[inline]
        fn next(&mut self) -> Option<Self::Item> {
            let byte = *self.signature.get(self.pos)?;
            // can't overflow or break invariant because if pos is too large we return early
            self.pos += 1;
            Some(byte)
        }

        #[inline]
        fn size_hint(&self) -> (usize, Option<usize>) {
            // can't underlflow thanks to the invariant
            let len = self.signature.len() - self.pos;
            (len, Some(len))
        }

        // override for speed
        #[inline]
        fn nth(&mut self, n: usize) -> Option<Self::Item> {
            if n >= self.len() {
                // upholds invariant becasue the values will be equal
                self.pos = self.signature.len();
                None
            } else {
                // if n < signtature.len() - self.pos then n + self.pos < signature.len() which neither
                // overflows nor breaks the invariant
                self.pos += n;
                self.next()
            }
        }
    }

    impl ExactSizeIterator for IntoIter {}

    impl core::iter::FusedIterator for IntoIter {}

    impl DoubleEndedIterator for IntoIter {
        #[inline]
        fn next_back(&mut self) -> Option<Self::Item> {
            if self.pos == self.signature.len() {
                return None;
            }

            // if len is 0 then pos is also 0 thanks to the invariant so we would return before we
            // reach this
            let new_len = self.signature.len() - 1;
            let byte = self.signature[new_len];
            self.signature.set_len_unchecked(new_len);
            Some(byte)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SerializedSignature, MAX_LEN};

    #[test]
    fn iterator_ops_are_homomorphic() {
        let mut fake_signature_data = [0; MAX_LEN];
        for (i, byte) in fake_signature_data.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let fake_signature = SerializedSignature { data: fake_signature_data, len: MAX_LEN };

        let mut iter1 = fake_signature.into_iter();
        let mut iter2 = fake_signature.iter();

        // while let so we can compare size_hint and as_slice
        while let (Some(a), Some(b)) = (iter1.next(), iter2.next()) {
            assert_eq!(a, *b);
            assert_eq!(iter1.size_hint(), iter2.size_hint());
            assert_eq!(iter1.as_slice(), iter2.as_slice());
        }

        let mut iter1 = fake_signature.into_iter();
        let mut iter2 = fake_signature.iter();

        // manual next_back instead of rev() so that we can check as_slice()
        // if next_back is implemented correctly then rev() is also correct - provided by `core`
        while let (Some(a), Some(b)) = (iter1.next_back(), iter2.next_back()) {
            assert_eq!(a, *b);
            assert_eq!(iter1.size_hint(), iter2.size_hint());
            assert_eq!(iter1.as_slice(), iter2.as_slice());
        }
    }
}
