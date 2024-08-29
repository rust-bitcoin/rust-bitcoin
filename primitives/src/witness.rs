// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct.

use core::fmt;
use core::ops::Index;

use internals::{compact_size, cursor, ToU64};

use crate::prelude::Vec;

/// The Witness is the data used to unlock bitcoin since the [segwit upgrade].
///
/// Can be logically seen as an array of bytestrings, i.e. `Vec<Vec<u8>>`, and it is serialized on the wire
/// in that format. You can convert between this type and `Vec<Vec<u8>>` by using [`Witness::from_slice`]
/// and [`Witness::to_vec`].
///
/// For serialization and deserialization performance it is stored internally as a single `Vec`,
/// saving some allocations.
///
/// [segwit upgrade]: <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Witness {
    /// Contains the witness `Vec<Vec<u8>>` serialization.
    ///
    /// Does not include the initial varint indicating the number of elements, instead this is
    /// stored stored in `witness_elements`. Concatenated onto the end of `content` is the index
    /// area, this is a `4 * witness_elements` bytes area which stores the index of the start of
    /// each witness item.
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
    /// Creates a new empty [`Witness`].
    #[inline]
    pub const fn new() -> Self {
        Witness { content: Vec::new(), witness_elements: 0, indices_start: 0 }
    }

    /// Creates a [`Witness`] object from a slice of bytes slices where each slice is a witness item.
    pub fn from_slice<T: AsRef<[u8]>>(slice: &[T]) -> Self {
        let witness_elements = slice.len();
        let index_size = witness_elements * 4;
        let content_size = slice
            .iter()
            .map(|elem| {
                elem.as_ref().len() + compact_size::encoded_size(elem.as_ref().len().to_u64())
            })
            .sum();

        let mut content = vec![0u8; content_size + index_size];
        let mut cursor = 0usize;
        for (i, elem) in slice.iter().enumerate() {
            cursor::encode(&mut content, content_size, i, cursor);
            let (encoded, size) = compact_size::encode(elem.as_ref().len().to_u64());
            content[cursor..cursor + size].copy_from_slice(&encoded[..size]);
            cursor += size;
            content[cursor..cursor + elem.as_ref().len()].copy_from_slice(elem.as_ref());
            cursor += elem.as_ref().len();
        }

        Witness { witness_elements, content, indices_start: content_size }
    }

    /// Convenience method to create an array of byte-arrays from this witness.
    pub fn to_bytes(&self) -> Vec<Vec<u8>> { self.iter().map(|s| s.to_vec()).collect() }

    /// Convenience method to create an array of byte-arrays from this witness.
    #[deprecated(since = "TBD", note = "Use to_bytes instead")]
    pub fn to_vec(&self) -> Vec<Vec<u8>> { self.to_bytes() }

    /// Returns `true` if the witness contains no element.
    pub fn is_empty(&self) -> bool { self.witness_elements == 0 }

    /// Returns a struct implementing [`Iterator`].
    pub fn iter(&self) -> Iter {
        Iter { inner: self.content.as_slice(), indices_start: self.indices_start, current_index: 0 }
    }

    /// Returns the number of elements this witness holds.
    pub fn len(&self) -> usize { self.witness_elements }

    /// Returns the number of bytes this witness contributes to a transactions total size.
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        size += compact_size::encoded_size(self.witness_elements.to_u64());
        size += self
            .iter()
            .map(|witness_element| {
                let len = witness_element.len();
                compact_size::encoded_size(len.to_u64()) + len
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

    /// Return the nth element in the witness, if any
    pub fn nth(&self, index: usize) -> Option<&[u8]> {
        let pos = cursor::decode(&self.content, self.indices_start, index)?;
        self.element_at(pos)
    }

    fn element_at(&self, index: usize) -> Option<&[u8]> {
        let (compact, size) = compact_size::decode(&self.content[index..]).ok()?;
        let start = index + size;
        Some(&self.content[start..start + compact as usize])
    }

    /// Creates a new `Witness` from parts.
    ///
    /// This is a low-level function, you are likely better served by the [`bitcoin::Witness`] API.
    ///
    /// [`bitcoin::Witness`]: <https://docs.rs/bitcoin/latest/bitcoin/struct.Witness.html>
    pub fn __from_parts(content: Vec<u8>, witness_elements: usize, indices_start: usize) -> Self {
        Witness { content, witness_elements, indices_start }
    }

    /// Push a new element slice onto the witness stack.
    ///
    /// This is a low-level function, you are likely better served by the [`bitcoin::Witness`] API.
    ///
    /// [`bitcoin::Witness`]: <https://docs.rs/bitcoin/latest/bitcoin/struct.Witness.html>
    pub fn __push_slice(&mut self, new_element: &[u8]) {
        self.witness_elements += 1;
        let previous_content_end = self.indices_start;
        let (encoded, size) = compact_size::encode(new_element.len().to_u64());
        let current_content_len = self.content.len();
        let new_item_total_len = size + new_element.len();
        self.content.resize(current_content_len + new_item_total_len + 4, 0);

        self.content[previous_content_end..].rotate_right(new_item_total_len);
        self.indices_start += new_item_total_len;
        cursor::encode(
            &mut self.content,
            self.indices_start,
            self.witness_elements - 1,
            previous_content_end,
        );

        let end_compact_size = previous_content_end + size;
        self.content[previous_content_end..end_compact_size].copy_from_slice(&encoded[..size]);
        self.content[end_compact_size..end_compact_size + new_element.len()]
            .copy_from_slice(new_element);
    }

    /// Gets a reference to the witness bytes excluding the initial compact variable encoding.
    ///
    /// This is a low-level function, you are likely better served by the [`bitcoin::Witness`] API.
    ///
    /// [`bitcoin::Witness`]: <https://docs.rs/bitcoin/latest/bitcoin/struct.Witness.html>
    pub fn __raw_bytes_excluding_compact_size(&self) -> &[u8] {
        let content_with_indices_len = self.content.len();
        let indices_size = self.len() * 4;
        let content_len = content_with_indices_len - indices_size;
        &self.content[..content_len]
    }
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if f.alternate() {
            fmt_debug_pretty(self, f)
        } else {
            fmt_debug(self, f)
        }
    }
}

fn fmt_debug(w: &Witness, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
    #[rustfmt::skip]
    let comma_or_close = |current_index, last_index| {
        if current_index == last_index { "]" } else { ", " }
    };

    f.write_str("Witness: { ")?;
    write!(f, "indices: {}, ", w.witness_elements)?;
    write!(f, "indices_start: {}, ", w.indices_start)?;
    f.write_str("witnesses: [")?;

    let instructions = w.iter();
    match instructions.len().checked_sub(1) {
        Some(last_instruction) => {
            for (i, instruction) in instructions.enumerate() {
                let bytes = instruction.iter();
                match bytes.len().checked_sub(1) {
                    Some(last_byte) => {
                        f.write_str("[")?;
                        for (j, byte) in bytes.enumerate() {
                            write!(f, "{:#04x}", byte)?;
                            f.write_str(comma_or_close(j, last_byte))?;
                        }
                    }
                    None => {
                        // This is possible because the varint is not part of the instruction (see Iter).
                        write!(f, "[]")?;
                    }
                }
                f.write_str(comma_or_close(i, last_instruction))?;
            }
        }
        None => {
            // Witnesses can be empty because the 0x00 var int is not stored in content.
            write!(f, "]")?;
        }
    }

    f.write_str(" }")
}

fn fmt_debug_pretty(w: &Witness, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
    f.write_str("Witness: {\n")?;
    writeln!(f, "    indices: {},", w.witness_elements)?;
    writeln!(f, "    indices_start: {},", w.indices_start)?;
    f.write_str("    witnesses: [\n")?;

    for instruction in w.iter() {
        f.write_str("        [")?;
        for (j, byte) in instruction.iter().enumerate() {
            if j > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{:#04x}", byte)?;
        }
        f.write_str("],\n")?;
    }

    writeln!(f, "    ],")?;
    writeln!(f, "}}")
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
        let index = cursor::decode(self.inner, self.indices_start, self.current_index)?;
        let (compact, size) = compact_size::decode(&self.inner[index..]).ok()?;
        let start = index + size;
        let end = start + compact as usize;
        let slice = &self.inner[start..end];
        self.current_index += 1;
        Some(slice)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let total_count = (self.inner.len() - self.indices_start) / 4;
        let remaining = total_count - self.current_index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {}

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
                use hex::FromHex;
                use hex::HexToBytesError::*;
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| match e {
                        InvalidChar(ref e) => match core::char::from_u32(e.invalid_char().into()) {
                            Some(c) => de::Error::invalid_value(
                                Unexpected::Char(c),
                                &"a valid hex character",
                            ),
                            None => de::Error::invalid_value(
                                Unexpected::Unsigned(e.invalid_char().into()),
                                &"a valid hex character",
                            ),
                        },
                        OddLengthString(ref e) =>
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
