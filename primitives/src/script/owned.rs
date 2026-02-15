// SPDX-License-Identifier: CC0-1.0

use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use encoding::{ByteVecDecoder, ByteVecDecoderError, Decodable, Decoder};
use internals::write_err;

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
/// # Hexadecimal strings
///
/// Scripts are consensus encoded with a length prefix and as a result of this in some places in the
/// ecosystem one will encounter hex strings that include the prefix while in other places the
/// prefix is excluded. To support parsing and formatting scripts as hex we provide a bunch of
/// different APIs and trait implementations. Please see [`examples/script.rs`] for a thorough
/// example of all the APIs.
///
/// [`examples/script.rs`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/script.rs>
/// [deref coercions]: https://doc.rust-lang.org/std/ops/trait.Deref.html#more-on-deref-coercion
///
/// # Panics
///
/// `ScriptBuf` is backed by [`Vec`] and inherits its panic behavior. This means that attempting to
/// construct scripts larger than `isize::MAX` bytes will panic.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ScriptBuf<T>(PhantomData<T>, Vec<u8>);

impl<T> ScriptBuf<T> {
    /// Constructs a new empty script.
    #[inline]
    pub const fn new() -> Self { Self::from_bytes(Vec::new()) }

    /// Converts byte vector into script.
    ///
    /// This method doesn't (re)allocate. `bytes` is just the script bytes **not** consensus
    /// encoding (i.e no length prefix).
    #[inline]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self { Self(PhantomData, bytes) }

    /// Returns a reference to unsized script.
    #[inline]
    pub fn as_script(&self) -> &Script<T> { Script::from_bytes(&self.1) }

    /// Returns a mutable reference to unsized script.
    #[inline]
    pub fn as_mut_script(&mut self) -> &mut Script<T> { Script::from_bytes_mut(&mut self.1) }

    /// Converts the script into a byte vector.
    ///
    /// This method doesn't (re)allocate.
    ///
    /// # Returns
    ///
    /// Just the script bytes **not** consensus encoding (which includes a length prefix).
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> { self.1 }

    /// Converts this `ScriptBuf` into a [boxed](Box) [`Script`].
    ///
    /// This method reallocates if the capacity is greater than length of the script but should not
    /// when they are equal. If you know beforehand that you need to create a script of exact size
    /// use [`reserve_exact`](Self::reserve_exact) before adding data to the script so that the
    /// reallocation can be avoided.
    #[must_use]
    #[inline]
    pub fn into_boxed_script(self) -> Box<Script<T>> {
        Script::from_boxed_bytes(self.into_bytes().into_boxed_slice())
    }

    /// Constructs a new empty script with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self { Self::from_bytes(Vec::with_capacity(capacity)) }

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
    #[inline]
    pub fn reserve(&mut self, additional_len: usize) { self.1.reserve(additional_len); }

    /// Pre-allocates exactly `additional_len` bytes if needed.
    ///
    /// Unlike `reserve`, this will not deliberately over-allocate to speculatively avoid frequent
    /// allocations. After calling `reserve_exact`, capacity will be greater than or equal to
    /// `self.len() + additional`. Does nothing if the capacity is already sufficient.
    ///
    /// Note that the allocator may give the collection more space than it requests. Therefore,
    /// capacity cannot be relied upon to be precisely minimal. Prefer [`reserve`](Self::reserve)
    /// if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX bytes`.
    #[inline]
    pub fn reserve_exact(&mut self, additional_len: usize) { self.1.reserve_exact(additional_len); }

    /// Returns the number of **bytes** available for writing without reallocation.
    ///
    /// It is guaranteed that `script.capacity() >= script.len()` always holds.
    #[inline]
    pub fn capacity(&self) -> usize { self.1.capacity() }

    /// Gets the hex representation of this script.
    ///
    /// # Returns
    ///
    /// Just the script bytes in hexadecimal **not** consensus encoding of the script i.e., the
    /// string will not include a length prefix.
    #[cfg(feature = "alloc")]
    #[cfg(feature = "hex")]
    #[inline]
    #[deprecated(since = "1.0.0-rc.0", note = "use `format!(\"{var:x}\")` instead")]
    pub fn to_hex(&self) -> alloc::string::String { alloc::format!("{:x}", self) }
}

// Cannot derive due to generics.
impl<T> Default for ScriptBuf<T> {
    fn default() -> Self { Self(PhantomData, Vec::new()) }
}

impl<T> Deref for ScriptBuf<T> {
    type Target = Script<T>;

    #[inline]
    fn deref(&self) -> &Self::Target { self.as_script() }
}

impl<T> DerefMut for ScriptBuf<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { self.as_mut_script() }
}

/// The decoder for the [`ScriptBuf`] type.
pub struct ScriptBufDecoder<T>(ByteVecDecoder, PhantomData<T>);

impl<T> ScriptBufDecoder<T> {
    /// Constructs a new [`ScriptBuf`] decoder.
    pub const fn new() -> Self { Self(ByteVecDecoder::new(), PhantomData) }
}

impl<T> Default for ScriptBufDecoder<T> {
    fn default() -> Self { Self::new() }
}

impl<T> Decoder for ScriptBufDecoder<T> {
    type Output = ScriptBuf<T>;
    type Error = ScriptBufDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        Ok(self.0.push_bytes(bytes)?)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> { Ok(ScriptBuf::from_bytes(self.0.end()?)) }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl<T> Decodable for ScriptBuf<T> {
    type Decoder = ScriptBufDecoder<T>;
    fn decoder() -> Self::Decoder { ScriptBufDecoder(ByteVecDecoder::new(), PhantomData) }
}

/// An error consensus decoding a `ScriptBuf<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptBufDecoderError(ByteVecDecoderError);

impl From<Infallible> for ScriptBufDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl From<ByteVecDecoderError> for ScriptBufDecoderError {
    fn from(e: ByteVecDecoderError) -> Self { Self(e) }
}

impl fmt::Display for ScriptBufDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write_err!(f, "decoder error"; self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for ScriptBufDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> Arbitrary<'a> for ScriptBuf<T> {
    #[inline]
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = Vec::<u8>::arbitrary(u)?;
        Ok(Self::from_bytes(v))
    }
}

#[cfg(test)]
mod tests {
    // All tests should compile and pass no matter which script type you put here.
    type ScriptBuf = super::super::ScriptSigBuf;

    #[cfg(feature = "alloc")]
    use alloc::string::ToString;
    #[cfg(feature = "alloc")]
    use alloc::vec;
    #[cfg(feature = "std")]
    use std::error::Error as _;

    use super::*;

    #[test]
    fn script_buf_from_bytes() {
        let bytes = vec![1, 2, 3];
        let script = ScriptBuf::from_bytes(bytes.clone());
        assert_eq!(script.as_bytes(), bytes);
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
        let mut script = ScriptBuf::from_bytes(vec![1, 2, 3]);
        let script_mut_ref = script.as_mut_script();
        script_mut_ref.as_mut_bytes()[0] = 4;
        assert_eq!(script.as_mut_bytes(), &[4, 2, 3]);
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
        assert!(script.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve() {
        let mut script = ScriptBuf::new();
        script.reserve(10);
        assert!(script.capacity() >= 10);
    }

    #[test]
    fn script_buf_reserve_exact() {
        let mut script = ScriptBuf::new();
        script.reserve_exact(10);
        assert!(script.capacity() >= 10);
    }

    #[test]
    fn script_buf_default() {
        let script: ScriptBuf = ScriptBuf::default();
        assert!(script.is_empty());
    }

    #[test]
    fn script_consensus_decode_empty() {
        let bytes = vec![0_u8];
        let mut push = bytes.as_slice();
        let mut decoder = ScriptBuf::decoder();
        decoder.push_bytes(&mut push).unwrap();

        let got = decoder.end().unwrap();
        let want = ScriptBuf::new();

        assert_eq!(got, want);
    }

    #[test]
    fn script_consensus_decode_empty_with_more_data() {
        // An empty script sig with a bunch of unrelated data at the end.
        let bytes = vec![0x00_u8, 0xff, 0xff, 0xff, 0xff];
        let mut push = bytes.as_slice();
        let mut decoder = ScriptBuf::decoder();
        decoder.push_bytes(&mut push).unwrap();

        let got = decoder.end().unwrap();
        let want = ScriptBuf::new();

        assert_eq!(got, want);
    }

    #[test]
    fn decoder_full_read_limit() {
        let mut decoder = ScriptBuf::decoder();
        // ByteVecDecoder length prefix is CompactSize: needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        // Script length prefix = 32.
        let mut push = [32_u8].as_slice();
        decoder.push_bytes(&mut push).unwrap();
        // Limit is 32 for the script data.
        assert_eq!(decoder.read_limit(), 32);

        // Provide 1 byte of script data decreasing the read limit by 1.
        let mut push = [0xAA_u8].as_slice();
        decoder.push_bytes(&mut push).unwrap();
        assert_eq!(decoder.read_limit(), 31);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decoder_error_display() {
        let bytes = vec![0x01_u8];
        let mut push = bytes.as_slice();
        let mut decoder = <ScriptBuf as Decodable>::Decoder::default();
        decoder.push_bytes(&mut push).unwrap();

        let err = decoder.end().unwrap_err();
        assert!(!err.to_string().is_empty());
        #[cfg(feature = "std")]
        assert!(err.source().is_some());
    }
}
