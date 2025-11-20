// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use core::convert::Infallible;
use core::fmt;
use core::ops::Index;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
#[cfg(doc)]
use encoding::Decoder4;
use encoding::{
    self, BytesEncoder, CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, Decoder,
    Encodable, Encoder, Encoder2, LengthPrefixExceedsMaxError,
};
#[cfg(feature = "hex")]
use hex::DecodeVariableLengthBytesError;
use internals::slice::SliceExt;
use internals::wrap_debug::WrapDebug;
use internals::{compact_size, write_err};

use crate::prelude::{Box, Vec};
#[cfg(doc)]
use crate::TxIn;

/// The Witness is the data used to unlock bitcoin since the [SegWit upgrade].
///
/// Can be logically seen as an array of bytestrings, i.e. `Vec<Vec<u8>>`, and it is serialized on the wire
/// in that format. You can convert between this type and `Vec<Vec<u8>>` by using [`Witness::from_slice`]
/// and [`Witness::to_vec`].
///
/// For serialization and deserialization performance it is stored internally as a single `Vec`,
/// saving some allocations.
///
/// [SegWit upgrade]: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Witness {
    /// Contains the witness `Vec<Vec<u8>>` serialization.
    ///
    /// Does not include the initial length prefix indicating the number of elements. Each element
    /// however, does include a [`CompactSize`] indicating the element length. The number of
    /// elements is stored in `witness_elements`.
    ///
    /// Concatenated onto the end of `content` is the index area. This is a `4 * witness_elements`
    /// bytes area which stores the index of the start of each witness item.
    ///
    /// [`CompactSize`]: <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
    content: Vec<u8>,

    /// The number of elements in the witness.
    ///
    /// Stored separately (instead of as a compact size encoding in the initial part of content) so
    /// that methods like [`Witness::push`] don't have to shift the entire array.
    witness_elements: usize,

    /// This is the valid index pointing to the beginning of the index area.
    ///
    /// Said another way, this is the total length of all witness elements serialized (without the
    /// element count but with their sizes serialized as compact size).
    indices_start: usize,
}

impl Witness {
    /// Constructs a new empty [`Witness`].
    #[inline]
    pub const fn new() -> Self {
        Self { content: Vec::new(), witness_elements: 0, indices_start: 0 }
    }

    /// Constructs a new [`Witness`] from inner parts.
    ///
    /// This function leaks implementation details of the `Witness`, as such it is unstable and
    /// should not be relied upon (it is primarily provided for use in `rust-bitcoin`).
    ///
    /// UNSTABLE: This function may change, break, or disappear in any release.
    #[inline]
    #[doc(hidden)]
    #[allow(non_snake_case)] // Because of `__unstable`.
    pub fn from_parts__unstable(
        content: Vec<u8>,
        witness_elements: usize,
        indices_start: usize,
    ) -> Self {
        Self { content, witness_elements, indices_start }
    }

    /// Constructs a new [`Witness`] object from a slice of bytes slices where each slice is a witness item.
    pub fn from_slice<T: AsRef<[u8]>>(slice: &[T]) -> Self {
        let witness_elements = slice.len();
        let index_size = witness_elements * 4;
        let content_size = slice
            .iter()
            .map(|elem| elem.as_ref().len() + compact_size::encoded_size(elem.as_ref().len()))
            .sum();

        let mut content = alloc::vec![0u8; content_size + index_size];
        let mut cursor = 0usize;
        for (i, elem) in slice.iter().enumerate() {
            encode_cursor(&mut content, content_size, i, cursor);
            let encoded = compact_size::encode(elem.as_ref().len());
            let encoded_size = encoded.as_slice().len();
            content[cursor..cursor + encoded_size].copy_from_slice(encoded.as_slice());
            cursor += encoded_size;
            content[cursor..cursor + elem.as_ref().len()].copy_from_slice(elem.as_ref());
            cursor += elem.as_ref().len();
        }

        Self { witness_elements, content, indices_start: content_size }
    }

    /// Convenience method to create an array of byte-arrays from this witness.
    #[inline]
    pub fn to_vec(&self) -> Vec<Vec<u8>> { self.iter().map(<[u8]>::to_vec).collect() }

    /// Returns `true` if the witness contains no element.
    #[inline]
    pub fn is_empty(&self) -> bool { self.witness_elements == 0 }

    /// Returns a struct implementing [`Iterator`].
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter { inner: self.content.as_slice(), indices_start: self.indices_start, current_index: 0 }
    }

    /// Returns the number of elements this witness holds.
    #[inline]
    pub fn len(&self) -> usize { self.witness_elements }

    /// Returns the number of bytes this witness contributes to a transactions total size.
    ///
    /// # Panics
    ///
    /// If the size calculation overflows.
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        size += compact_size::encoded_size(self.witness_elements);
        size += self
            .iter()
            .map(|witness_element| {
                let len = witness_element.len();
                compact_size::encoded_size(len) + len
            })
            .sum::<usize>();

        size
    }

    /// Clears the witness.
    #[inline]
    pub fn clear(&mut self) {
        self.content.clear();
        self.witness_elements = 0;
        self.indices_start = 0;
    }

    /// Pushes a new element on the witness, requires an allocation.
    #[inline]
    pub fn push<T: AsRef<[u8]>>(&mut self, new_element: T) {
        self.push_slice(new_element.as_ref());
    }

    /// Pushes a new element slice onto the witness stack.
    fn push_slice(&mut self, new_element: &[u8]) {
        self.witness_elements += 1;
        let previous_content_end = self.indices_start;
        let encoded = compact_size::encode(new_element.len());
        let encoded_size = encoded.as_slice().len();
        let current_content_len = self.content.len();
        let new_item_total_len = encoded_size + new_element.len();
        self.content.resize(current_content_len + new_item_total_len + 4, 0);

        self.content[previous_content_end..].rotate_right(new_item_total_len);
        self.indices_start += new_item_total_len;
        encode_cursor(
            &mut self.content,
            self.indices_start,
            self.witness_elements - 1,
            previous_content_end,
        );

        let end_compact_size = previous_content_end + encoded_size;
        self.content[previous_content_end..end_compact_size].copy_from_slice(encoded.as_slice());
        self.content[end_compact_size..end_compact_size + new_element.len()]
            .copy_from_slice(new_element);
    }

    /// Returns the last element in the witness, if any.
    #[inline]
    pub fn last(&self) -> Option<&[u8]> { self.get_back(0) }

    /// Retrieves an element from the end of the witness by its reverse index.
    ///
    /// `index` is 0-based from the end, where 0 is the last element, 1 is the second-to-last, etc.
    ///
    /// Returns `None` if the requested index is beyond the witness's elements.
    ///
    /// # Examples
    /// ```
    /// use bitcoin_primitives::witness::Witness;
    ///
    /// let mut witness = Witness::new();
    /// witness.push(b"A");
    /// witness.push(b"B");
    /// witness.push(b"C");
    /// witness.push(b"D");
    ///
    /// assert_eq!(witness.get_back(0), Some(b"D".as_slice()));
    /// assert_eq!(witness.get_back(1), Some(b"C".as_slice()));
    /// assert_eq!(witness.get_back(2), Some(b"B".as_slice()));
    /// assert_eq!(witness.get_back(3), Some(b"A".as_slice()));
    /// assert_eq!(witness.get_back(4), None);
    /// ```
    pub fn get_back(&self, index: usize) -> Option<&[u8]> {
        if self.witness_elements <= index {
            None
        } else {
            self.get(self.witness_elements - 1 - index)
        }
    }

    /// Returns a specific element from the witness by its index, if any.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        let pos = decode_cursor(&self.content, self.indices_start, index)?;

        let mut slice = &self.content[pos..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        let end = cast_to_usize_if_valid(element_len)?;
        Some(&slice[..end])
    }

    /// Constructs a new witness from a list of hex strings.
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the hex strings are invalid.
    #[cfg(feature = "hex")]
    pub fn from_hex<I, T>(iter: I) -> Result<Self, DecodeVariableLengthBytesError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let result = iter
            .into_iter()
            .map(|hex_str| crate::hex::decode_to_vec(hex_str.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::from_slice(&result))
    }
}

/// Correctness Requirements: value must always fit within u32
// This is duplicated in `bitcoin::blockdata::witness`, if you change it please do so over there also.
#[inline]
fn encode_cursor(bytes: &mut [u8], start_of_indices: usize, index: usize, value: usize) {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    bytes[start..end]
        .copy_from_slice(&u32::to_ne_bytes(value.try_into().expect("larger than u32")));
}

#[inline]
fn decode_cursor(bytes: &[u8], start_of_indices: usize, index: usize) -> Option<usize> {
    let start = start_of_indices + index * 4;
    let pos = bytes.get_array::<4>(start).map(|index_bytes| u32::from_ne_bytes(*index_bytes))?;
    usize::try_from(pos).ok()
}

/// The encoder for the [`Witness`] type.
pub struct WitnessEncoder<'a>(Encoder2<CompactSizeEncoder, BytesEncoder<'a>>);

impl Encodable for Witness {
    type Encoder<'a>
        = WitnessEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        let num_elements = CompactSizeEncoder::new(self.len());
        let witness_elements =
            BytesEncoder::without_length_prefix(&self.content[..self.indices_start]);

        WitnessEncoder(Encoder2::new(num_elements, witness_elements))
    }
}

impl Encoder for WitnessEncoder<'_> {
    #[inline]
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    #[inline]
    fn advance(&mut self) -> bool { self.0.advance() }
}

/// The decoder for the [`Witness`] type.
#[cfg(feature = "alloc")]
pub struct WitnessDecoder {
    /// The single buffer that will become the Witness content.
    /// The index entries are written at the beginning, then rotated in [`Self::end`].
    content: Vec<u8>,
    /// Current write position in the content buffer.
    cursor: usize,
    /// Decoder for the initial witness element count.
    witness_count_decoder: CompactSizeDecoder,
    /// Total number of witness elements to decode (None until initial count is read).
    witness_elements: Option<usize>,
    /// Index of the current element being decoded.
    element_idx: usize,
    /// Decoder for the current element's length.
    element_length_decoder: CompactSizeDecoder,
    /// Bytes remaining to read for the current element's data.
    /// - `None` means we're currently reading the length.
    /// - `Some(n)` means we're reading element data with `n` bytes remaining.
    element_bytes_remaining: Option<usize>,
}

impl WitnessDecoder {
    /// Constructs a new witness decoder.
    pub fn new() -> Self {
        Self {
            content: Vec::new(),
            cursor: 0,
            witness_elements: None,
            witness_count_decoder: CompactSizeDecoder::new(),
            element_idx: 0,
            element_length_decoder: CompactSizeDecoder::new(),
            element_bytes_remaining: None,
        }
    }

    /// Resizes the content buffer if needed, doubling the size each time.
    fn resize_if_needed(&mut self, required_len: usize) {
        if required_len >= self.content.len() {
            let mut new_len = self.content.len().max(1);
            while new_len <= required_len {
                new_len *= 2;
            }
            self.content.resize(new_len, 0);
        }
    }
}

impl Default for WitnessDecoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for WitnessDecoder {
    type Output = Witness;
    type Error = WitnessDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        use {WitnessDecoderError as E, WitnessDecoderErrorInner as Inner};

        // Read initial witness element count.
        if self.witness_elements.is_none() {
            if self
                .witness_count_decoder
                .push_bytes(bytes)
                .map_err(|e| E(Inner::LengthPrefixDecode(e)))?
            {
                return Ok(true);
            }
            // Take ownership of the decoder in order to consume it.
            let decoder = core::mem::take(&mut self.witness_count_decoder);
            let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;
            let witness_elements = encoding::cast_to_usize_if_valid(length)
                .map_err(|e| E(Inner::LengthPrefixInvalid(e)))?;
            self.witness_elements = Some(witness_elements);

            // Short circuit for zero witness elements.
            if witness_elements == 0 {
                return Ok(false);
            }

            // Allocate space for the index and buffer. The buffer
            // is initialized to 128 bytes which should be large enough
            // to cover most witnesses, the typical pubkey + signature
            // and some overhead (e.g. P2WPKH witness is ~100 bytes),
            // without reallocating.
            let witness_index_space = witness_elements * 4;
            self.cursor = witness_index_space;
            self.content = alloc::vec![0u8; self.cursor + 128];
        }

        let Some(witness_elements) = self.witness_elements else {
            unreachable!("witness_elements must be Some after initial read")
        };
        let witness_index_space = witness_elements * 4;

        // Read witness elements.
        loop {
            // Check if we're done processing all elements.
            if self.element_idx >= witness_elements {
                return Ok(false);
            }

            if bytes.is_empty() {
                return Ok(true);
            }

            // If we have some bytes to read, then reading element data.
            // Else we are reading the element's length.
            if let Some(bytes_to_read) = self.element_bytes_remaining {
                let copy_len = bytes.len().min(bytes_to_read);

                // Ensure we have enough space.
                let required_len = self.cursor + copy_len;
                self.resize_if_needed(required_len);

                self.content[self.cursor..self.cursor + copy_len]
                    .copy_from_slice(&bytes[..copy_len]);
                self.cursor += copy_len;
                *bytes = &bytes[copy_len..];
                let remaining = bytes_to_read - copy_len;

                if remaining == 0 {
                    // Element complete, move to next element.
                    self.element_idx += 1;
                    self.element_bytes_remaining = None;
                } else {
                    self.element_bytes_remaining = Some(remaining);
                }
            } else {
                if self
                    .element_length_decoder
                    .push_bytes(bytes)
                    .map_err(|e| E(Inner::LengthPrefixDecode(e)))?
                {
                    return Ok(true);
                }

                // Take ownership of the decoder so we can consume it.
                let decoder = core::mem::take(&mut self.element_length_decoder);
                let length = decoder.end().map_err(|e| E(Inner::LengthPrefixDecode(e)))?;
                let element_length = encoding::cast_to_usize_if_valid(length)
                    .map_err(|e| E(Inner::LengthPrefixInvalid(e)))?;

                // Store the element position in the index.
                let position_after_rotation = self.cursor - witness_index_space;
                encode_cursor(&mut self.content, 0, self.element_idx, position_after_rotation);

                // Re-encode the length back into the buffer.
                let encoded_size = compact_size::encoded_size(element_length);
                let required_len = self.cursor + encoded_size + element_length;
                self.resize_if_needed(required_len);
                let encoded_compact_size = compact_size::encode(element_length);
                self.content[self.cursor..self.cursor + encoded_size]
                    .copy_from_slice(&encoded_compact_size);
                self.cursor += encoded_size;

                if element_length == 0 {
                    // Complete immediately for zero-length element to
                    // avoid incorrectly signaling "need more data".
                    self.element_idx += 1;
                    self.element_bytes_remaining = None;
                } else {
                    self.element_bytes_remaining = Some(element_length);
                }
            }
        }
    }

    fn end(mut self) -> Result<Self::Output, Self::Error> {
        use {WitnessDecoderError as E, WitnessDecoderErrorInner as Inner};

        let Some(witness_elements) = self.witness_elements else {
            // Never read the witness element count.
            return Err(E(Inner::UnexpectedEof(UnexpectedEofError { missing_elements: 0 })));
        };

        let remaining = witness_elements - self.element_idx;

        if remaining == 0 {
            // Truncate to actual content length (remove unused allocated space).
            self.content.truncate(self.cursor);

            // Rotate the index area from beginning to end.
            let witness_index_space = witness_elements * 4;
            self.content.rotate_left(witness_index_space);

            Ok(Witness::from_parts__unstable(
                self.content,
                witness_elements,
                self.cursor - witness_index_space,
            ))
        } else {
            Err(E(Inner::UnexpectedEof(UnexpectedEofError { missing_elements: remaining })))
        }
    }

    fn read_limit(&self) -> usize {
        if self.witness_elements.is_none() {
            // Reading witness count (haven't started processing elements yet).
            self.witness_count_decoder.read_limit()
        } else {
            // Reading an element.
            match self.element_bytes_remaining {
                None => self.element_length_decoder.read_limit(),
                Some(remaining) => remaining,
            }
        }
    }
}

impl encoding::Decodable for Witness {
    type Decoder = WitnessDecoder;
    fn decoder() -> Self::Decoder { WitnessDecoder::default() }
}

// Note: we use `Borrow` in the following `PartialEq` impls specifically because of its additional
// constraints on equality semantics.
impl<T: core::borrow::Borrow<[u8]>> PartialEq<[T]> for Witness {
    fn eq(&self, rhs: &[T]) -> bool {
        if self.len() != rhs.len() {
            return false;
        }
        self.iter().zip(rhs).all(|(left, right)| left == right.borrow())
    }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<&[T]> for Witness {
    fn eq(&self, rhs: &&[T]) -> bool { *self == **rhs }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for [T] {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for &[T] {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == **self }
}

impl<const N: usize, T: core::borrow::Borrow<[u8]>> PartialEq<[T; N]> for Witness {
    fn eq(&self, rhs: &[T; N]) -> bool { *self == *rhs.as_slice() }
}

impl<const N: usize, T: core::borrow::Borrow<[u8]>> PartialEq<&[T; N]> for Witness {
    fn eq(&self, rhs: &&[T; N]) -> bool { *self == *rhs.as_slice() }
}

impl<const N: usize, T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for [T; N] {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

impl<const N: usize, T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for &[T; N] {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == **self }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Vec<T>> for Witness {
    fn eq(&self, rhs: &Vec<T>) -> bool { *self == **rhs }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for Vec<T> {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Box<[T]>> for Witness {
    fn eq(&self, rhs: &Box<[T]>) -> bool { *self == **rhs }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for Box<[T]> {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<alloc::rc::Rc<[T]>> for Witness {
    fn eq(&self, rhs: &alloc::rc::Rc<[T]>) -> bool { *self == **rhs }
}

impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for alloc::rc::Rc<[T]> {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

#[cfg(target_has_atomic = "ptr")]
impl<T: core::borrow::Borrow<[u8]>> PartialEq<alloc::sync::Arc<[T]>> for Witness {
    fn eq(&self, rhs: &alloc::sync::Arc<[T]>) -> bool { *self == **rhs }
}

#[cfg(target_has_atomic = "ptr")]
impl<T: core::borrow::Borrow<[u8]>> PartialEq<Witness> for alloc::sync::Arc<[T]> {
    fn eq(&self, rhs: &Witness) -> bool { *rhs == *self }
}

/// Debug implementation that displays the witness as a structured output containing:
/// - Number of witness elements
/// - Total bytes across all elements
/// - List of hex-encoded witness elements if `hex` feature is enabled.
#[allow(clippy::missing_fields_in_debug)] // We don't want to show `indices_start`.
impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_bytes: usize = self.iter().map(<[u8]>::len).sum();

        f.debug_struct("Witness")
            .field("num_elements", &self.witness_elements)
            .field("total_bytes", &total_bytes)
            .field(
                "elements",
                &WrapDebug(|f| {
                    #[cfg(feature = "hex")]
                    {
                        f.debug_list()
                            .entries(self.iter().map(hex_unstable::DisplayHex::as_hex))
                            .finish()
                    }
                    #[cfg(not(feature = "hex"))]
                    {
                        f.debug_list().entries(self.iter()).finish()
                    }
                }),
            )
            .finish()
    }
}

/// An iterator returning individual witness elements.
#[derive(Clone)]
pub struct Iter<'a> {
    inner: &'a [u8],
    indices_start: usize,
    current_index: usize,
}

impl Index<usize> for Witness {
    type Output = [u8];

    #[track_caller]
    #[inline]
    fn index(&self, index: usize) -> &Self::Output { self.get(index).expect("out of bounds") }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = decode_cursor(self.inner, self.indices_start, self.current_index)?;
        let mut slice = &self.inner[index..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        let end = cast_to_usize_if_valid(element_len)?;
        self.current_index += 1;
        Some(&slice[..end])
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let total_count = (self.inner.len() - self.indices_start) / 4;
        let remaining = total_count - self.current_index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Witness {
    type IntoIter = Iter<'a>;
    type Item = &'a [u8];

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}

impl<T: AsRef<[u8]>> FromIterator<T> for Witness {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let v: Vec<Vec<u8>> = iter.into_iter().map(|item| Vec::from(item.as_ref())).collect();
        Self::from(v)
    }
}

// Serde keep backward compatibility with old Vec<Vec<u8>> format
#[cfg(feature = "serde")]
impl serde::Serialize for Witness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let human_readable = serializer.is_human_readable();
        let mut seq = serializer.serialize_seq(Some(self.witness_elements))?;

        // Note that the `Iter` strips the varints out when iterating.
        for elem in self {
            if human_readable {
                seq.serialize_element(&internals::serde::SerializeBytesAsHex(elem))?;
            } else {
                seq.serialize_element(&elem)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Witness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::prelude::String;

        struct Visitor; // Human-readable visitor.
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Witness;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a sequence of hex arrays")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                use hex_unstable::{FromHex, HexToBytesError as E};
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| match e {
                        E::InvalidChar(ref e) =>
                            match core::char::from_u32(e.invalid_char().into()) {
                                Some(c) => de::Error::invalid_value(
                                    Unexpected::Char(c),
                                    &"a valid hex character",
                                ),
                                None => de::Error::invalid_value(
                                    Unexpected::Unsigned(e.invalid_char().into()),
                                    &"a valid hex character",
                                ),
                            },
                        E::OddLengthString(ref e) =>
                            de::Error::invalid_length(e.length(), &"an even length string"),
                    })?;
                    ret.push(vec);
                }
                Ok(Witness::from_slice(&ret))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_seq(Visitor)
        } else {
            let vec: Vec<Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
            Ok(Self::from_slice(&vec))
        }
    }
}

impl From<Vec<Vec<u8>>> for Witness {
    #[inline]
    fn from(vec: Vec<Vec<u8>>) -> Self { Self::from_slice(&vec) }
}

impl From<&[&[u8]]> for Witness {
    #[inline]
    fn from(slice: &[&[u8]]) -> Self { Self::from_slice(slice) }
}

impl From<&[Vec<u8>]> for Witness {
    #[inline]
    fn from(slice: &[Vec<u8>]) -> Self { Self::from_slice(slice) }
}

impl From<Vec<&[u8]>> for Witness {
    #[inline]
    fn from(vec: Vec<&[u8]>) -> Self { Self::from_slice(&vec) }
}

impl<const N: usize> From<[&[u8]; N]> for Witness {
    #[inline]
    fn from(arr: [&[u8]; N]) -> Self { Self::from_slice(&arr) }
}

impl<const N: usize> From<&[&[u8]; N]> for Witness {
    #[inline]
    fn from(arr: &[&[u8]; N]) -> Self { Self::from_slice(arr) }
}

impl<const N: usize> From<&[[u8; N]]> for Witness {
    #[inline]
    fn from(slice: &[[u8; N]]) -> Self { Self::from_slice(slice) }
}

impl<const N: usize> From<&[&[u8; N]]> for Witness {
    #[inline]
    fn from(slice: &[&[u8; N]]) -> Self { Self::from_slice(slice) }
}

impl<const N: usize, const M: usize> From<[[u8; M]; N]> for Witness {
    #[inline]
    fn from(slice: [[u8; M]; N]) -> Self { Self::from_slice(&slice) }
}

impl<const N: usize, const M: usize> From<&[[u8; M]; N]> for Witness {
    #[inline]
    fn from(slice: &[[u8; M]; N]) -> Self { Self::from_slice(slice) }
}

impl<const N: usize, const M: usize> From<[&[u8; M]; N]> for Witness {
    #[inline]
    fn from(slice: [&[u8; M]; N]) -> Self { Self::from_slice(&slice) }
}

impl<const N: usize, const M: usize> From<&[&[u8; M]; N]> for Witness {
    #[inline]
    fn from(slice: &[&[u8; M]; N]) -> Self { Self::from_slice(slice) }
}

impl Default for Witness {
    #[inline]
    fn default() -> Self { Self::new() }
}

/// An error when consensus decoding a [`Witness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessDecoderError(WitnessDecoderErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
enum WitnessDecoderErrorInner {
    /// Error decoding the vector length prefix.
    LengthPrefixDecode(CompactSizeDecoderError),
    /// Length prefix exceeds 4,000,000.
    LengthPrefixInvalid(LengthPrefixExceedsMaxError),
    /// Not enough bytes given to decoder.
    UnexpectedEof(UnexpectedEofError),
}

impl From<Infallible> for WitnessDecoderError {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for WitnessDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use WitnessDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => write_err!(f, "vec decoder error"; e),
            E::LengthPrefixInvalid(ref e) => write_err!(f, "vec decoder error"; e),
            E::UnexpectedEof(ref e) => write_err!(f, "decoder error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use WitnessDecoderErrorInner as E;

        match self.0 {
            E::LengthPrefixDecode(ref e) => Some(e),
            E::LengthPrefixInvalid(ref e) => Some(e),
            E::UnexpectedEof(ref e) => Some(e),
        }
    }
}

/// Not enough witness elements (bytes) given to decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedEofError {
    /// Number of elements missing to complete decoder.
    missing_elements: usize,
}

impl core::fmt::Display for UnexpectedEofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not enough witness elements for decoder, missing {}", self.missing_elements)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnexpectedEofError {}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Witness {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = Vec::<Vec<u8>>::arbitrary(u)?;
        Ok(Self::from_slice(&arbitrary_bytes))
    }
}

/// Cast a decoded length prefix to a `usize`.
///
/// This function is basically just defensive. For all sane use cases the length prefix should be
/// less than `MAX_VEC_SIZE` (on a 32-bit machine). If the value is bigger that `u16::MAX` and we
/// are on a 16-bit machine you'll likely hit an error later anyway, better to just check it now.
///
/// # 16-bits
///
/// The compact size may be bigger than what can be represented in a `usize` on a 16-bit machine but
/// this shouldn't happen if we created the witness because one would get an OOM error before that.
fn cast_to_usize_if_valid(n: u64) -> Option<usize> {
    /// Maximum size, in bytes, of a vector we are allowed to decode.
    const MAX_VEC_SIZE: u64 = 4_000_000;

    if n > MAX_VEC_SIZE {
        return None;
    }

    usize::try_from(n).ok()
}

#[cfg(test)]
mod test {
    #[cfg(feature = "alloc")]
    use alloc::vec;

    use super::*;

    // Appends all the indices onto the end of a list of elements.
    fn append_u32_vec(elements: &[u8], indices: &[u32]) -> Vec<u8> {
        let mut v = elements.to_vec();
        for &num in indices {
            v.extend_from_slice(&num.to_ne_bytes());
        }
        v
    }

    // A witness with a single element that is empty (zero length).
    fn single_empty_element() -> Witness { Witness::from([[0u8; 0]]) }

    #[test]
    fn witness_single_empty_element() {
        let mut got = Witness::new();
        got.push([]);
        let want = single_empty_element();
        assert_eq!(got, want);
    }

    #[test]
    fn push() {
        // Sanity check default.
        let mut witness = Witness::default();
        assert!(witness.is_empty());
        assert_eq!(witness.last(), None);
        assert_eq!(witness.get_back(1), None);

        assert_eq!(witness.get(0), None);
        assert_eq!(witness.get(1), None);
        assert_eq!(witness.get(2), None);
        assert_eq!(witness.get(3), None);

        // Push a single byte element onto the witness stack.
        let push = [11_u8];
        witness.push(push);
        assert!(!witness.is_empty());

        assert_eq!(witness, [[11_u8]]);

        let element_0 = push.as_slice();
        assert_eq!(element_0, &witness[0]);

        assert_eq!(witness.get_back(1), None);
        assert_eq!(witness.last(), Some(element_0));

        assert_eq!(witness.get(0), Some(element_0));
        assert_eq!(witness.get(1), None);
        assert_eq!(witness.get(2), None);
        assert_eq!(witness.get(3), None);

        // Now push 2 byte element onto the witness stack.
        let push = [21u8, 22u8];
        witness.push(push);

        assert_eq!(witness, [&[11_u8] as &[_], &[21, 22]]);

        let element_1 = push.as_slice();
        assert_eq!(element_1, &witness[1]);

        assert_eq!(witness.get(0), Some(element_0));
        assert_eq!(witness.get(1), Some(element_1));
        assert_eq!(witness.get(2), None);
        assert_eq!(witness.get(3), None);

        assert_eq!(witness.get_back(1), Some(element_0));
        assert_eq!(witness.last(), Some(element_1));

        // Now push another 2 byte element onto the witness stack.
        let push = [31u8, 32u8];
        witness.push(push);

        assert_eq!(witness, [&[11_u8] as &[_], &[21, 22], &[31, 32]]);

        let element_2 = push.as_slice();
        assert_eq!(element_2, &witness[2]);

        assert_eq!(witness.get(0), Some(element_0));
        assert_eq!(witness.get(1), Some(element_1));
        assert_eq!(witness.get(2), Some(element_2));
        assert_eq!(witness.get(3), None);

        assert_eq!(witness.get_back(2), Some(element_0));
        assert_eq!(witness.get_back(1), Some(element_1));
        assert_eq!(witness.last(), Some(element_2));
    }

    #[test]
    fn exact_sized_iterator() {
        let arbitrary_element = [1_u8, 2, 3];
        let num_pushes = 5; // Somewhat arbitrary.

        let mut witness = Witness::default();

        for i in 0..num_pushes {
            assert_eq!(witness.iter().len(), i);
            witness.push(arbitrary_element);
        }

        let mut iter = witness.iter();
        for i in (0..=num_pushes).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn witness_from_parts() {
        let elements = [1u8, 11, 2, 21, 22];
        let witness_elements = 2;
        let content = append_u32_vec(&elements, &[0, 2]);
        let indices_start = elements.len();
        let witness = Witness::from_parts__unstable(content, witness_elements, indices_start);
        assert_eq!(witness.get(0).unwrap(), [11_u8]);
        assert_eq!(witness.get(1).unwrap(), [21_u8, 22]);
        assert_eq!(witness.size(), 6);
    }

    #[test]
    fn witness_from_impl() {
        // Test From implementations with the same 2 elements
        let vec = vec![vec![11], vec![21, 22]];
        let slice_vec: &[Vec<u8>] = &vec;
        let slice_slice: &[&[u8]] = &[&[11u8], &[21, 22]];
        let vec_slice: Vec<&[u8]> = vec![&[11u8], &[21, 22]];

        let witness_vec_vec = Witness::from(vec.clone());
        let witness_slice_vec = Witness::from(slice_vec);
        let witness_slice_slice = Witness::from(slice_slice);
        let witness_vec_slice = Witness::from(vec_slice);

        let mut expected = Witness::from_slice(&vec);
        assert_eq!(expected.len(), 2);
        assert_eq!(expected.to_vec(), vec);

        assert_eq!(witness_vec_vec, expected);
        assert_eq!(witness_slice_vec, expected);
        assert_eq!(witness_slice_slice, expected);
        assert_eq!(witness_vec_slice, expected);

        // Test clear method
        expected.clear();
        assert!(expected.is_empty());
    }

    #[test]
    fn witness_from_array_impl() {
        const DATA_1: [u8; 3] = [1, 2, 3];
        const DATA_2: [u8; 3] = [4, 5, 6];
        let witness = Witness::from_slice(&[DATA_1, DATA_2]);

        let witness_from_array_ref = Witness::from(&[DATA_1, DATA_2]);
        let witness_from_array_of_refs = Witness::from([&DATA_1, &DATA_2]);
        let witness_from_ref_to_array_of_refs = Witness::from(&[&DATA_1, &DATA_2]);
        let witness_from_fixed_array = Witness::from([DATA_1, DATA_2]);
        let witness_from_slice_of_refs = Witness::from(&[&DATA_1, &DATA_2][..]);
        let witness_from_nested_array = Witness::from(&[DATA_1, DATA_2][..]);

        assert_eq!(witness_from_array_ref, witness);
        assert_eq!(witness_from_array_of_refs, witness);
        assert_eq!(witness_from_ref_to_array_of_refs, witness);
        assert_eq!(witness_from_fixed_array, witness);
        assert_eq!(witness_from_slice_of_refs, witness);
        assert_eq!(witness_from_nested_array, witness);
    }

    #[test]
    fn partial_eq() {
        const EMPTY_BYTES: &[u8] = &[];
        const DATA_1: &[u8] = &[42];
        const DATA_2: &[u8] = &[42, 21];

        macro_rules! ck {
            ($witness:expr, $container:expr, $different:expr) => {{
                let witness = $witness;
                let container = $container;
                let different = $different;

                assert_eq!(witness, container, stringify!($container));
                assert_eq!(container, witness, stringify!($container));

                assert_ne!(witness, different, stringify!($container));
                assert_ne!(different, witness, stringify!($container));
            }};
        }

        // &[T]
        let container: &[&[u8]] = &[EMPTY_BYTES];
        let different: &[&[u8]] = &[DATA_1];
        ck!(Witness::from(container), container, different);

        let container: &[&[u8]] = &[DATA_1];
        let different: &[&[u8]] = &[DATA_2];
        ck!(Witness::from(container), container, different);

        // &[T; N]
        let container: &[&[u8]; 2] = &[DATA_1, DATA_2];
        let different: &[&[u8]; 2] = &[DATA_2, DATA_1];
        ck!(Witness::from(container), container, different);

        // [&[T]; N]
        let container: [&[u8]; 2] = [DATA_1, DATA_2];
        let different: [&[u8]; 2] = [DATA_2, DATA_1];
        ck!(Witness::from(container), container, different);

        // Vec<T>
        let container: Vec<&[u8]> = vec![DATA_1, DATA_2];
        let different: Vec<&[u8]> = vec![DATA_2, DATA_1];
        ck!(Witness::from(container.as_slice()), container, different);

        // Box<[T]>
        let container: Box<[&[u8]]> = vec![DATA_1, DATA_2].into_boxed_slice();
        let different: Box<[&[u8]]> = vec![DATA_2, DATA_1].into_boxed_slice();
        ck!(Witness::from(&*container), container, different);

        // Rc<[T]>
        let container: alloc::rc::Rc<[&[u8]]> = vec![DATA_1, DATA_2].into();
        let different: alloc::rc::Rc<[&[u8]]> = vec![DATA_2, DATA_1].into();
        ck!(Witness::from(&*container), container, different);

        // Arc<[T]>
        let container: alloc::sync::Arc<[&[u8]]> = vec![DATA_1, DATA_2].into();
        let different: alloc::sync::Arc<[&[u8]]> = vec![DATA_2, DATA_1].into();
        ck!(Witness::from(&*container), container, different);
    }

    #[test]
    fn partial_eq_for_slice() {
        let witness = Witness::from_slice(&[vec![1, 2, 3], vec![4, 5, 6]]);
        let container: &[Vec<u8>] = &[vec![1, 2, 3], vec![4, 5, 6]];
        let different: &[Vec<u8>] = &[vec![1, 2], vec![4, 5]];

        // Explicitly dereference the slice to invoke the `[T]` implementation.
        assert_eq!(*container, witness);
        assert_ne!(*different, witness);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_backward_compatibility() {
        let old_witness_format = vec![vec![0u8], vec![2]];
        let new_witness_format = Witness::from_slice(&old_witness_format);

        let old = bincode::serialize(&old_witness_format).unwrap();
        let new = bincode::serialize(&new_witness_format).unwrap();

        assert_eq!(old, new);
    }

    #[cfg(feature = "serde")]
    fn arbitrary_witness() -> Witness {
        let mut witness = Witness::default();

        witness.push([0_u8]);
        witness.push([1_u8; 32]);
        witness.push([2_u8; 72]);

        witness
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_bincode_roundtrips() {
        let original = arbitrary_witness();
        let ser = bincode::serialize(&original).unwrap();
        let rinsed: Witness = bincode::deserialize(&ser).unwrap();
        assert_eq!(rinsed, original);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_human_roundtrips() {
        let original = arbitrary_witness();
        let ser = serde_json::to_string(&original).unwrap();
        let rinsed: Witness = serde_json::from_str(&ser).unwrap();
        assert_eq!(rinsed, original);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_human() {
        let witness = Witness::from_slice(&[vec![0u8, 123, 75], vec![2u8, 6, 3, 7, 8]]);
        let json = serde_json::to_string(&witness).unwrap();
        assert_eq!(json, r#"["007b4b","0206030708"]"#);
    }

    #[test]
    fn test_witness_from_iterator() {
        let bytes1 = [1u8, 2, 3];
        let bytes2 = [4u8, 5];
        let bytes3 = [6u8, 7, 8, 9];
        let data = [&bytes1[..], &bytes2[..], &bytes3[..]];

        // Use FromIterator directly
        let witness1 = Witness::from_iter(data);

        // Create a witness manually for comparison
        let mut witness2 = Witness::new();
        for item in &data {
            witness2.push(item);
        }
        assert_eq!(witness1, witness2);
        assert_eq!(witness1.len(), witness2.len());
        assert_eq!(witness1.to_vec(), witness2.to_vec());

        // Test with collect
        let bytes4 = [0u8, 123, 75];
        let bytes5 = [2u8, 6, 3, 7, 8];
        let data = [bytes4.to_vec(), bytes5.to_vec()];
        let witness3: Witness = data.iter().collect();
        assert_eq!(witness3.len(), 2);
        assert_eq!(witness3.to_vec(), data);

        // Test with empty iterator
        let empty_data: Vec<Vec<u8>> = vec![];
        let witness4: Witness = empty_data.iter().collect();
        assert!(witness4.is_empty());
    }

    #[cfg(feature = "hex")]
    #[test]
    fn test_from_hex() {
        let hex_strings = [
            "30440220703350f1c8be5b41b4cb03b3b680c4f3337f987514a6b08e16d5d9f81e9b5f72022018fb269ba5b82864c0e1edeaf788829eb332fe34a859cc1f99c4a02edfb5d0df01",
            "0208689fe2cca52d8726cefaf274de8fa61d5faa5e1058ad35b49fb194c035f9a4",
        ];

        let witness = Witness::from_hex(hex_strings).unwrap();
        assert_eq!(witness.len(), 2);
    }

    #[test]
    fn encode() {
        let bytes1 = [1u8, 2, 3];
        let bytes2 = [4u8, 5];
        let bytes3 = [6u8, 7, 8, 9];
        let data = [&bytes1[..], &bytes2[..], &bytes3[..]];

        // Use FromIterator directly
        let witness = Witness::from_iter(data);

        let want = [0x03, 0x03, 0x01, 0x02, 0x03, 0x02, 0x04, 0x05, 0x04, 0x06, 0x07, 0x08, 0x09];
        let got = encoding::encode_to_vec(&witness);

        assert_eq!(&got, &want);
    }

    #[test]
    fn encodes_using_correct_chunks() {
        let bytes1 = [1u8, 2, 3];
        let bytes2 = [4u8, 5];
        let data = [&bytes1[..], &bytes2[..]];

        // Use FromIterator directly
        let witness = Witness::from_iter(data);

        // Should have length prefix chunk, then the content slice, then exhausted.
        let mut encoder = witness.encoder();

        assert_eq!(encoder.current_chunk(), &[2u8][..]);
        assert!(encoder.advance());

        // We don't encode one element at a time, rather we encode the whole content slice at once.
        assert_eq!(encoder.current_chunk(), &[3u8, 1, 2, 3, 2, 4, 5][..]);
        assert!(!encoder.advance());
        assert!(encoder.current_chunk().is_empty());
    }

    #[test]
    fn encode_empty() {
        let witness = Witness::default();

        let want = [0x00];
        let got = encoding::encode_to_vec(&witness);

        assert_eq!(&got, &want);
    }

    #[cfg(feature = "alloc")]
    fn witness_test_case() -> (Witness, Vec<u8>) {
        let bytes1 = [1u8];
        let bytes2 = [2u8, 3];
        let bytes3 = [4u8, 5, 6];
        let data = [&bytes1[..], &bytes2[..], &bytes3[..]];

        let witness = Witness::from_iter(data);

        #[rustfmt::skip]
        let encoded = vec![
            0x03_u8,
            0x01, 0x01,
            0x02, 0x02, 0x03,
            0x03, 0x04, 0x05, 0x06
        ];

        (witness, encoded)
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_witness_one_single_call() {
        let (want, encoded) = witness_test_case();

        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();
        decoder.push_bytes(&mut slice).unwrap();

        let got = decoder.end().unwrap();

        assert_eq!(got, want);
    }

    #[cfg(feature = "alloc")]
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn decode_witness_many_calls() {
        let (want, encoded) = witness_test_case();

        let mut decoder = WitnessDecoder::new();

        let mut a = &encoded.as_slice()[0..1]; // [3]
        let mut b = &encoded.as_slice()[1..2]; // [1]
        let mut c = &encoded.as_slice()[2..5]; // [1, 2, 2]
        let mut d = &encoded.as_slice()[5..6]; // [3]
        let mut e = &encoded.as_slice()[6..7]; // [3]
        let mut f = &encoded.as_slice()[7..9]; // [4, 5]
        let mut g = &encoded.as_slice()[9..]; // [6]

        decoder.push_bytes(&mut a).unwrap();
        decoder.push_bytes(&mut b).unwrap();
        decoder.push_bytes(&mut c).unwrap();
        decoder.push_bytes(&mut d).unwrap();
        decoder.push_bytes(&mut e).unwrap();
        decoder.push_bytes(&mut f).unwrap();
        decoder.push_bytes(&mut g).unwrap();

        let got = decoder.end().unwrap();

        assert_eq!(got, want);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_max_length() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(compact_size::encode(1usize).as_slice());
        encoded.extend_from_slice(compact_size::encode(4_000_000usize).as_slice());
        encoded.resize(encoded.len() + 4_000_000, 0u8);

        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();
        decoder.push_bytes(&mut slice).unwrap();
        let witness = decoder.end().unwrap();
        assert_eq!(witness[0].len(), 4_000_000);

        let mut encoded = Vec::new();
        encoded.extend_from_slice(compact_size::encode(1usize).as_slice());
        encoded.extend_from_slice(compact_size::encode(4_000_001usize).as_slice());

        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();
        let err = decoder.push_bytes(&mut slice).unwrap_err();
        assert!(matches!(
            err,
            WitnessDecoderError(WitnessDecoderErrorInner::LengthPrefixInvalid(_))
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_empty_witness() {
        // Witness with 0 elements.
        let encoded = vec![0x00];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(!decoder.push_bytes(&mut slice).unwrap());
        let witness = decoder.end().unwrap();

        assert_eq!(witness.len(), 0);
        assert!(witness.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_single_element() {
        // Witness with 1 element containing [0xAB, 0xCD].
        let encoded = vec![0x01, 0x02, 0xAB, 0xCD];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(!decoder.push_bytes(&mut slice).unwrap());
        let witness = decoder.end().unwrap();

        assert_eq!(witness.len(), 1);
        assert_eq!(&witness[0], &[0xABu8, 0xCD][..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_empty_element() {
        // Witness with 1 element that is empty (0 bytes).
        let encoded = vec![0x01, 0x00];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(!decoder.push_bytes(&mut slice).unwrap());
        let witness = decoder.end().unwrap();

        assert_eq!(witness.len(), 1);
        assert_eq!(&witness[0], &[] as &[u8]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_multiple_empty_elements() {
        // Witness with 3 empty elements.
        let encoded = vec![0x03, 0x00, 0x00, 0x00];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(!decoder.push_bytes(&mut slice).unwrap());
        let witness = decoder.end().unwrap();

        assert_eq!(witness.len(), 3);
        assert_eq!(&witness[0], &[] as &[u8]);
        assert_eq!(&witness[1], &[] as &[u8]);
        assert_eq!(&witness[2], &[] as &[u8]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_incomplete_witness_count() {
        // 3-byte compact size but only provide 2 bytes.
        let encoded = vec![0xFD, 0x03];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err, WitnessDecoderError(WitnessDecoderErrorInner::UnexpectedEof(_))));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_incomplete_element_length() {
        // Witness count = 1, but element length is incomplete.
        let encoded = vec![0x01, 0xFD, 0x05]; // Element length should be 3 bytes.
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err, WitnessDecoderError(WitnessDecoderErrorInner::UnexpectedEof(_))));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_incomplete_element_data() {
        // Witness count = 1, element length = 5, but only 3 bytes of data provided.
        let encoded = vec![0x01, 0x05, 0xAA, 0xBB, 0xCC];
        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();

        assert!(decoder.push_bytes(&mut slice).unwrap());

        let err = decoder.end().unwrap_err();
        assert!(matches!(err, WitnessDecoderError(WitnessDecoderErrorInner::UnexpectedEof(_))));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn decode_buffer_resizing() {
        // Create a witness with elements larger than initial 128-byte allocation.
        let large_element = vec![0xFF; 500];
        let mut encoded = vec![0x02];
        encoded.extend_from_slice(&[0xFD, 0xF4, 0x01]);
        encoded.extend_from_slice(&large_element);
        encoded.extend_from_slice(&[0xFD, 0xF4, 0x01]);
        encoded.extend_from_slice(&large_element);

        let mut slice = encoded.as_slice();
        let mut decoder = WitnessDecoder::new();
        assert!(!decoder.push_bytes(&mut slice).unwrap());

        let witness = decoder.end().unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(&witness[0], large_element.as_slice());
        assert_eq!(&witness[1], large_element.as_slice());
    }
}
