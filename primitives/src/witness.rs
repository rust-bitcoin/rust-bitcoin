// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use core::fmt;
use core::ops::Index;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hex::DisplayHex;
use internals::compact_size;

use crate::prelude::Vec;

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
    /// Does not include the initial varint indicating the number of elements. Each element however,
    /// does include a varint indicating the element length. The number of elements is stored in
    /// `witness_elements`.
    ///
    /// Concatenated onto the end of `content` is the index area. This is a `4 * witness_elements`
    /// bytes area which stores the index of the start of each witness item.
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
        Witness { content: Vec::new(), witness_elements: 0, indices_start: 0 }
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
        Witness { content, witness_elements, indices_start }
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

        Witness { witness_elements, content, indices_start: content_size }
    }

    /// Convenience method to create an array of byte-arrays from this witness.
    pub fn to_vec(&self) -> Vec<Vec<u8>> { self.iter().map(|s| s.to_vec()).collect() }

    /// Returns `true` if the witness contains no element.
    pub fn is_empty(&self) -> bool { self.witness_elements == 0 }

    /// Returns a struct implementing [`Iterator`].
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    pub fn iter(&self) -> Iter {
        Iter { inner: self.content.as_slice(), indices_start: self.indices_start, current_index: 0 }
    }

    /// Returns the number of elements this witness holds.
    pub fn len(&self) -> usize { self.witness_elements }

    /// Returns the number of bytes this witness contributes to a transactions total size.
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

    /// Clear the witness.
    pub fn clear(&mut self) {
        self.content.clear();
        self.witness_elements = 0;
        self.indices_start = 0;
    }

    /// Push a new element on the witness, requires an allocation.
    pub fn push<T: AsRef<[u8]>>(&mut self, new_element: T) {
        self.push_slice(new_element.as_ref());
    }

    /// Push a new element slice onto the witness stack.
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

    /// Note `index` is the index into the `content` vector and should be the result of calling
    /// `decode_cursor`, which returns a valid index.
    fn element_at(&self, index: usize) -> Option<&[u8]> {
        let mut slice = &self.content[index..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        // Compact size should always fit into a u32 because of `MAX_SIZE` in Core.
        // ref: https://github.com/rust-bitcoin/rust-bitcoin/issues/3264
        let end = element_len as usize;
        Some(&slice[..end])
    }

    /// Returns the last element in the witness, if any.
    pub fn last(&self) -> Option<&[u8]> {
        if self.witness_elements == 0 {
            None
        } else {
            self.nth(self.witness_elements - 1)
        }
    }

    /// Returns the second-to-last element in the witness, if any.
    pub fn second_to_last(&self) -> Option<&[u8]> {
        if self.witness_elements <= 1 {
            None
        } else {
            self.nth(self.witness_elements - 2)
        }
    }

    /// Returns the third-to-last element in the witness, if any.
    pub fn third_to_last(&self) -> Option<&[u8]> {
        if self.witness_elements <= 2 {
            None
        } else {
            self.nth(self.witness_elements - 3)
        }
    }

    /// Return the nth element in the witness, if any
    pub fn nth(&self, index: usize) -> Option<&[u8]> {
        let pos = decode_cursor(&self.content, self.indices_start, index)?;
        self.element_at(pos)
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

// This is duplicated in `bitcoin::blockdata::witness`, if you change them do so over there also.
#[inline]
fn decode_cursor(bytes: &[u8], start_of_indices: usize, index: usize) -> Option<usize> {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    if end > bytes.len() {
        None
    } else {
        Some(u32::from_ne_bytes(bytes[start..end].try_into().expect("is u32 size")) as usize)
    }
}

/// Debug implementation that displays the witness as a structured output containing hex-encoded witness elements.
struct DebugElements<'a>(&'a Witness);

impl fmt::Debug for DebugElements<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter().map(|elem| elem.as_hex())).finish()
    }
}

/// Debug implementation that displays the witness as a structured output containing:
/// - Number of witness elements
/// - Total bytes across all elements
/// - List of hex-encoded witness elements
impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_bytes: usize = self.iter().map(|elem| elem.len()).sum();

        f.debug_struct("Witness")
            .field("num_elements", &self.witness_elements)
            .field("total_bytes", &total_bytes)
            .field("elements", &DebugElements(self))
            .finish()
    }
}

/// An iterator returning individual witness elements.
pub struct Iter<'a> {
    inner: &'a [u8],
    indices_start: usize,
    current_index: usize,
}

impl Index<usize> for Witness {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output { self.nth(index).expect("out of bounds") }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = decode_cursor(self.inner, self.indices_start, self.current_index)?;
        let mut slice = &self.inner[index..]; // Start of element.
        let element_len = compact_size::decode_unchecked(&mut slice);
        // Compact size should always fit into a u32 because of `MAX_SIZE` in Core.
        // ref: https://github.com/rust-bitcoin/rust-bitcoin/issues/3264
        let end = element_len as usize;
        self.current_index += 1;
        Some(&slice[..end])
    }

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

    fn into_iter(self) -> Self::IntoIter { self.iter() }
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
        for elem in self.iter() {
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
                use hex::{FromHex as _, ToBytesError};
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| match e.parse_error() {
                        ToBytesError::InvalidChar(ref e) => match core::char::from_u32(e.invalid_char().into()) {
                            Some(c) => de::Error::invalid_value(
                                Unexpected::Char(c),
                                &"a valid hex character",
                            ),
                            None => de::Error::invalid_value(
                                Unexpected::Unsigned(e.invalid_char().into()),
                                &"a valid hex character",
                            ),
                        },
                        ToBytesError::OddLengthString(ref e) =>
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
            Ok(Witness::from_slice(&vec))
        }
    }
}

impl From<Vec<Vec<u8>>> for Witness {
    fn from(vec: Vec<Vec<u8>>) -> Self { Witness::from_slice(&vec) }
}

impl From<&[&[u8]]> for Witness {
    fn from(slice: &[&[u8]]) -> Self { Witness::from_slice(slice) }
}

impl From<&[Vec<u8>]> for Witness {
    fn from(slice: &[Vec<u8>]) -> Self { Witness::from_slice(slice) }
}

impl From<Vec<&[u8]>> for Witness {
    fn from(vec: Vec<&[u8]>) -> Self { Witness::from_slice(&vec) }
}

impl Default for Witness {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Witness {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = Vec::<Vec<u8>>::arbitrary(u)?;
        Ok(Witness::from_slice(&arbitrary_bytes))
    }
}

#[cfg(test)]
mod test {
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
    fn single_empty_element() -> Witness {
        // The first is 0 serialized as a compact size integer.
        // The last four bytes represent start at index 0.
        let content = [0_u8; 5];

        Witness { witness_elements: 1, content: content.to_vec(), indices_start: 1 }
    }

    #[test]
    fn witness_debug_can_display_empty_element() {
        let witness = single_empty_element();
        println!("{:?}", witness);
    }

    #[test]
    fn witness_single_empty_element() {
        let mut got = Witness::new();
        got.push([]);
        let want = single_empty_element();
        assert_eq!(got, want)
    }

    #[test]
    fn push() {
        // Sanity check default.
        let mut witness = Witness::default();
        assert!(witness.is_empty());
        assert_eq!(witness.last(), None);
        assert_eq!(witness.second_to_last(), None);

        assert_eq!(witness.nth(0), None);
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);

        // Push a single byte element onto the witness stack.
        let push = [11_u8];
        witness.push(push);
        assert!(!witness.is_empty());

        let elements = [1u8, 11];
        let expected = Witness {
            witness_elements: 1,
            content: append_u32_vec(&elements, &[0]), // Start at index 0.
            indices_start: elements.len(),
        };
        assert_eq!(witness, expected);

        let element_0 = push.as_slice();
        assert_eq!(element_0, &witness[0]);

        assert_eq!(witness.second_to_last(), None);
        assert_eq!(witness.last(), Some(element_0));

        assert_eq!(witness.nth(0), Some(element_0));
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);

        // Now push 2 byte element onto the witness stack.
        let push = [21u8, 22u8];
        witness.push(push);

        let elements = [1u8, 11, 2, 21, 22];
        let expected = Witness {
            witness_elements: 2,
            content: append_u32_vec(&elements, &[0, 2]),
            indices_start: elements.len(),
        };
        assert_eq!(witness, expected);

        let element_1 = push.as_slice();
        assert_eq!(element_1, &witness[1]);

        assert_eq!(witness.nth(0), Some(element_0));
        assert_eq!(witness.nth(1), Some(element_1));
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);

        assert_eq!(witness.second_to_last(), Some(element_0));
        assert_eq!(witness.last(), Some(element_1));

        // Now push another 2 byte element onto the witness stack.
        let push = [31u8, 32u8];
        witness.push(push);

        let elements = [1u8, 11, 2, 21, 22, 2, 31, 32];
        let expected = Witness {
            witness_elements: 3,
            content: append_u32_vec(&elements, &[0, 2, 5]),
            indices_start: elements.len(),
        };
        assert_eq!(witness, expected);

        let element_2 = push.as_slice();
        assert_eq!(element_2, &witness[2]);

        assert_eq!(witness.nth(0), Some(element_0));
        assert_eq!(witness.nth(1), Some(element_1));
        assert_eq!(witness.nth(2), Some(element_2));
        assert_eq!(witness.nth(3), None);

        assert_eq!(witness.third_to_last(), Some(element_0));
        assert_eq!(witness.second_to_last(), Some(element_1));
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
        let witness =
            Witness::from_parts__unstable(content.clone(), witness_elements, indices_start);
        assert_eq!(witness.nth(0).unwrap(), [11_u8]);
        assert_eq!(witness.nth(1).unwrap(), [21_u8, 22]);
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
}
