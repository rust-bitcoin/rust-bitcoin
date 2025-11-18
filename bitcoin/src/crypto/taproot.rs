// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Taproot signatures.
//!
//! This module provides Taproot signatures used by Bitcoin that can be roundtrip (de)serialized.

use core::borrow::Borrow;
use core::convert::Infallible;
use core::{fmt, ops};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::array::ArrayExt;
use internals::{impl_to_hex_from_lower_hex, write_err};
use io::Write;

use crate::prelude::{DisplayHex, Vec};
use crate::sighash::{InvalidSighashTypeError, TapSighashType};

pub use self::into_iter::IntoIter;

const MAX_LEN: usize = 65; // 64 for sig, 1B sighash flag

/// A BIP-0340-0341 serialized Taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying schnorr signature.
    pub signature: secp256k1::schnorr::Signature,
    /// The corresponding hash type.
    pub sighash_type: TapSighashType,
}

impl Signature {
    /// Deserializes the signature from a slice.
    pub fn from_slice(sl: &[u8]) -> Result<Self, SigFromSliceError> {
        if let Ok(signature) = <[u8; 64]>::try_from(sl) {
            // default type
            let signature = secp256k1::schnorr::Signature::from_byte_array(signature);
            Ok(Self { signature, sighash_type: TapSighashType::Default })
        } else if let Ok(signature) = <[u8; 65]>::try_from(sl) {
            let (sighash_type, signature) = signature.split_last();
            let sighash_type = TapSighashType::from_consensus_u8(*sighash_type)?;
            let signature = secp256k1::schnorr::Signature::from_byte_array(*signature);
            Ok(Self { signature, sighash_type })
        } else {
            Err(SigFromSliceError::InvalidSignatureSize(sl.len()))
        }
    }

    /// Serializes the signature (without heap allocation).
    ///
    /// This returns a type with an API very similar to that of `Box<[u8]>`.
    /// You can get a slice from it using deref coercions or turn it into an iterator.
    pub fn serialize(self) -> SerializedSignature {
        let mut buf = [0; MAX_LEN];
        let ser_sig = self.signature.to_byte_array();
        buf[..64].copy_from_slice(&ser_sig);
        let len = if self.sighash_type == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
            64
        } else {
            buf[64] = self.sighash_type as u8;
            65
        };
        SerializedSignature::from_raw_parts(buf, len)
    }

    /// Serializes the signature.
    ///
    /// Note: this allocates on the heap, prefer [`serialize`](Self::serialize) if vec is not needed.
    pub fn to_vec(self) -> Vec<u8> {
        let mut ser_sig = self.signature.as_ref().to_vec();
        // If default sighash type, don't add extra sighash byte
        if self.sighash_type != TapSighashType::Default {
            ser_sig.push(self.sighash_type as u8);
        }
        ser_sig
    }

    /// Serializes the signature to `writer`.
    #[inline]
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }
}

/// A serialized Taproot Signature
///
/// Serialized Taproot signatures have the issue that they can have different lengths.
/// We want to avoid using `Vec` since that would require allocations making the code slower and
/// unable to run on platforms without an allocator.
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Constructs new `SerializedSignature` from data and length.
    ///
    /// # Panics
    ///
    /// If `len` > `MAX_LEN`
    #[inline]
    pub(crate) fn from_raw_parts(data: [u8; MAX_LEN], len: usize) -> Self {
        assert!(len <= MAX_LEN, "attempt to set length to {} but the maximum is {}", len, MAX_LEN);
        Self { data, len }
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
    pub fn to_signature(self) -> Result<Signature, SigFromSliceError> {
        Signature::from_slice(&self)
    }

    /// Constructs a new SerializedSignature from a Signature.
    /// (this serializes it)
    #[inline]
    pub fn from_signature(sig: Signature) -> Self { sig.serialize() }

    /// Writes this serialized signature to a `writer`.
    #[inline]
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(self)
    }
}

impl fmt::Debug for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for SerializedSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::fmt_hex_exact!(f, MAX_LEN, self, hex::Case::Lower)
    }
}

impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}
impl_to_hex_from_lower_hex!(SerializedSignature, |signature: &SerializedSignature| signature.len
    * 2);

impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &Self) -> bool { **self == **other }
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
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SerializedSignature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering { (**self).cmp(&**other) }
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

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { (**self).hash(state) }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.data[..self.len] }
}

impl Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] { &self.data[..self.len] }
}

impl ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] { &self.data[..self.len] }
}

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
    fn from(value: Signature) -> Self { Self::from_signature(value) }
}

impl<'a> From<&'a Signature> for SerializedSignature {
    fn from(value: &'a Signature) -> Self { Self::from_signature(*value) }
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
            Self {
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
            // can't overflow thanks to the invariant
            let len = self.signature.len() - self.pos;
            (len, Some(len))
        }

        // override for speed
        #[inline]
        fn nth(&mut self, n: usize) -> Option<Self::Item> {
            if n >= self.len() {
                // upholds invariant because the values will be equal
                self.pos = self.signature.len();
                None
            } else {
                // if n < signature.len() - self.pos then n + self.pos < signature.len() which neither
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

/// An error constructing a [`taproot::Signature`] from a byte slice.
///
/// [`taproot::Signature`]: crate::crypto::taproot::Signature
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigFromSliceError {
    /// Invalid signature hash type.
    SighashType(InvalidSighashTypeError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid Taproot signature size
    InvalidSignatureSize(usize),
}

impl From<Infallible> for SigFromSliceError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for SigFromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SigFromSliceError::*;

        match *self {
            SighashType(ref e) => write_err!(f, "sighash"; e),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
            InvalidSignatureSize(sz) => write!(f, "invalid Taproot signature size: {}", sz),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigFromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use SigFromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for SigFromSliceError {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<InvalidSighashTypeError> for SigFromSliceError {
    fn from(err: InvalidSighashTypeError) -> Self { Self::SighashType(err) }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes: [u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE] = u.arbitrary()?;

        Ok(Self {
            signature: secp256k1::schnorr::Signature::from_byte_array(arbitrary_bytes),
            sighash_type: TapSighashType::arbitrary(u)?,
        })
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
