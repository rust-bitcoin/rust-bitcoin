// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use core::fmt;
use core::ops::Index;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::compact_size;
use io::{BufRead, Write};

use crate::consensus::encode::{self, Error, ReadExt, WriteExt, MAX_VEC_SIZE};
use crate::consensus::{Decodable, Encodable};
use crate::crypto::ecdsa;
use crate::prelude::Vec;
#[cfg(doc)]
use crate::script::ScriptExt as _;
use crate::taproot::{self, TAPROOT_ANNEX_PREFIX};
use crate::Script;

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

impl Decodable for Witness {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let witness_elements = r.read_compact_size()? as usize;
        // Minimum size of witness element is 1 byte, so if the count is
        // greater than MAX_VEC_SIZE we must return an error.
        if witness_elements > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation {
                requested: witness_elements,
                max: MAX_VEC_SIZE,
            });
        }
        if witness_elements == 0 {
            Ok(Witness::default())
        } else {
            // Leave space at the head for element positions.
            // We will rotate them to the end of the Vec later.
            let witness_index_space = witness_elements * 4;
            let mut cursor = witness_index_space;

            // this number should be determined as high enough to cover most witness, and low enough
            // to avoid wasting space without reallocating
            let mut content = vec![0u8; cursor + 128];

            for i in 0..witness_elements {
                let element_size = r.read_compact_size()? as usize;
                let element_size_len = compact_size::encoded_size(element_size);
                let required_len = cursor
                    .checked_add(element_size)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    })?
                    .checked_add(element_size_len)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::MAX,
                        max: MAX_VEC_SIZE,
                    })?;

                if required_len > MAX_VEC_SIZE + witness_index_space {
                    return Err(self::Error::OversizedVectorAllocation {
                        requested: required_len,
                        max: MAX_VEC_SIZE,
                    });
                }

                // We will do content.rotate_left(witness_index_space) later.
                // Encode the position's value AFTER we rotate left.
                encode_cursor(&mut content, 0, i, cursor - witness_index_space);

                resize_if_needed(&mut content, required_len);
                cursor += (&mut content[cursor..cursor + element_size_len])
                    .emit_compact_size(element_size)?;
                r.read_exact(&mut content[cursor..cursor + element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            // Index space is now at the end of the Vec
            content.rotate_left(witness_index_space);
            Ok(Witness { content, witness_elements, indices_start: cursor - witness_index_space })
        }
    }
}

/// Correctness Requirements: value must always fit within u32
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
    let end = start + 4;
    if end > bytes.len() {
        None
    } else {
        Some(u32::from_ne_bytes(bytes[start..end].try_into().expect("is u32 size")) as usize)
    }
}

fn resize_if_needed(vec: &mut Vec<u8>, required_len: usize) {
    if required_len >= vec.len() {
        let mut new_len = vec.len().max(1);
        while new_len <= required_len {
            new_len *= 2;
        }
        vec.resize(new_len, 0);
    }
}

impl Encodable for Witness {
    // `self.content` includes the varints so encoding here includes them, as expected.
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut written = w.emit_compact_size(self.len())?;

        for element in self.iter() {
            written += encode::consensus_encode_with_size(element, w)?
        }

        Ok(written)
    }
}

impl Witness {
    /// Creates a new empty [`Witness`].
    #[inline]
    pub const fn new() -> Self {
        Witness { content: Vec::new(), witness_elements: 0, indices_start: 0 }
    }

    /// Creates a witness required to spend a P2WPKH output.
    ///
    /// The witness will be made up of the DER encoded signature + sighash_type followed by the
    /// serialized public key. Also useful for spending a P2SH-P2WPKH output.
    ///
    /// It is expected that `pubkey` is related to the secret key used to create `signature`.
    pub fn p2wpkh(signature: ecdsa::Signature, pubkey: secp256k1::PublicKey) -> Witness {
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(pubkey.serialize());
        witness
    }

    /// Creates a witness required to do a key path spend of a P2TR output.
    pub fn p2tr_key_spend(signature: &taproot::Signature) -> Witness {
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness
    }

    /// Creates a [`Witness`] object from a slice of bytes slices where each slice is a witness item.
    pub fn from_slice<T: AsRef<[u8]>>(slice: &[T]) -> Self {
        let witness_elements = slice.len();
        let index_size = witness_elements * 4;
        let content_size = slice
            .iter()
            .map(|elem| elem.as_ref().len() + compact_size::encoded_size(elem.as_ref().len()))
            .sum();

        let mut content = vec![0u8; content_size + index_size];
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

    /// Pushes, as a new element on the witness, an ECDSA signature.
    ///
    /// Pushes the DER encoded signature + sighash_type, requires an allocation.
    pub fn push_ecdsa_signature(&mut self, signature: ecdsa::Signature) {
        self.push(signature.serialize())
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

    /// Return the nth element in the witness, if any
    pub fn nth(&self, index: usize) -> Option<&[u8]> {
        let pos = decode_cursor(&self.content, self.indices_start, index)?;
        self.element_at(pos)
    }

    /// Get Tapscript following BIP341 rules regarding accounting for an annex.
    ///
    /// This does not guarantee that this represents a P2TR [`Witness`]. It
    /// merely gets the second to last or third to last element depending on
    /// the first byte of the last element being equal to 0x50.
    ///
    /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
    pub fn tapscript(&self) -> Option<&Script> {
        self.last().and_then(|last| {
            // From BIP341:
            // If there are at least two witness elements, and the first byte of
            // the last element is 0x50, this last element is called annex a
            // and is removed from the witness stack.
            if self.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                self.nth(self.len() - 3).map(Script::from_bytes)
            } else if self.len() >= 2 {
                self.nth(self.len() - 2).map(Script::from_bytes)
            } else {
                None
            }
        })
    }

    /// Get the taproot control block following BIP341 rules.
    ///
    /// This does not guarantee that this represents a P2TR [`Witness`]. It
    /// merely gets the last or second to last element depending on the first
    /// byte of the last element being equal to 0x50.
    ///
    /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
    pub fn taproot_control_block(&self) -> Option<&[u8]> {
        self.last().and_then(|last| {
            // From BIP341:
            // If there are at least two witness elements, and the first byte of
            // the last element is 0x50, this last element is called annex a
            // and is removed from the witness stack.
            if self.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                self.nth(self.len() - 2)
            } else if self.len() >= 2 {
                Some(last)
            } else {
                None
            }
        })
    }

    /// Get the taproot annex following BIP341 rules.
    ///
    /// This does not guarantee that this represents a P2TR [`Witness`].
    ///
    /// See [`Script::is_p2tr`] to check whether this is actually a Taproot witness.
    pub fn taproot_annex(&self) -> Option<&[u8]> {
        self.last().and_then(|last| {
            // From BIP341:
            // If there are at least two witness elements, and the first byte of
            // the last element is 0x50, this last element is called annex a
            // and is removed from the witness stack.
            if self.len() >= 2 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                Some(last)
            } else {
                None
            }
        })
    }

    /// Get the p2wsh witness script following BIP141 rules.
    ///
    /// This does not guarantee that this represents a P2WS [`Witness`].
    ///
    /// See [`Script::is_p2wsh`] to check whether this is actually a P2WSH witness.
    pub fn witness_script(&self) -> Option<&Script> { self.last().map(Script::from_bytes) }
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

        // Note that the `Iter` strips the varints out when iterating.
        for elem in self.iter() {
            if human_readable {
                seq.serialize_element(&crate::serde_utils::SerializeBytesAsHex(elem))?;
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

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Witness {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let arbitrary_bytes = Vec::<Vec<u8>>::arbitrary(u)?;
        Ok(Witness::from_slice(&arbitrary_bytes))
    }
}

#[cfg(test)]
mod test {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::{deserialize, encode, serialize};
    use crate::hex::DisplayHex;
    use crate::sighash::EcdsaSighashType;
    use crate::Transaction;

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
        got.push(&[]);
        let want = single_empty_element();
        assert_eq!(got, want)
    }

    #[test]
    fn push() {
        // Sanity check default.
        let mut witness = Witness::default();
        assert_eq!(witness.last(), None);
        assert_eq!(witness.second_to_last(), None);

        assert_eq!(witness.nth(0), None);
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);

        // Push a single byte element onto the witness stack.
        let push = [0_u8];
        witness.push(&push);

        let elements = [1u8, 0];
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
        let push = [2u8, 3u8];
        witness.push(&push);

        let elements = [1u8, 0, 2, 2, 3];
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
        let push = [4u8, 5u8];
        witness.push(&push);

        let elements = [1u8, 0, 2, 2, 3, 2, 4, 5];
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

        assert_eq!(witness.second_to_last(), Some(element_1));
        assert_eq!(witness.last(), Some(element_2));
    }

    #[test]
    fn exact_sized_iterator() {
        let mut witness = Witness::default();
        for i in 0..5 {
            assert_eq!(witness.iter().len(), i);
            witness.push(&vec![0u8]);
        }
        let mut iter = witness.iter();
        for i in (0..=5).rev() {
            assert_eq!(iter.len(), i);
            iter.next();
        }
    }

    #[test]
    fn test_push_ecdsa_sig() {
        // The very first signature in block 734,958
        let sig_bytes =
            hex!("304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b541");
        let signature = secp256k1::ecdsa::Signature::from_der(&sig_bytes).unwrap();
        let mut witness = Witness::default();
        let signature = crate::ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All };
        witness.push_ecdsa_signature(signature);
        let expected_witness = vec![hex!(
            "304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b54101")
            ];
        assert_eq!(witness.to_vec(), expected_witness);
    }

    #[test]
    fn consensus_serialize() {
        let el_0 = hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105");
        let el_1 = hex!("000000");

        let mut want_witness = Witness::default();
        want_witness.push(&el_0);
        want_witness.push(&el_1);

        let vec = vec![el_0.clone(), el_1.clone()];

        // Puts a CompactSize at the front as well as one at the front of each element.
        let want_ser: Vec<u8> = encode::serialize(&vec);

        // `from_slice` expects bytes slices _without_ leading `CompactSize`.
        let got_witness = Witness::from_slice(&vec);
        assert_eq!(got_witness, want_witness);

        let got_ser = encode::serialize(&got_witness);
        assert_eq!(got_ser, want_ser);

        let rinsed: Witness = encode::deserialize(&got_ser).unwrap();
        assert_eq!(rinsed, want_witness)
    }

    #[test]
    fn test_get_tapscript() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block, annex];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.tapscript(), Some(Script::from_bytes(&tapscript[..])));
        assert_eq!(witness_annex.tapscript(), Some(Script::from_bytes(&tapscript[..])));
    }

    #[test]
    fn test_get_control_block() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block.clone(), annex];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_control_block(), Some(&control_block[..]));
        assert_eq!(witness_annex.taproot_control_block(), Some(&control_block[..]));
    }

    #[test]
    fn test_get_annex() {
        let tapscript = hex!("deadbeef");
        let control_block = hex!("02");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![tapscript.clone(), control_block.clone()];
        let witness_vec_annex = vec![tapscript.clone(), control_block.clone(), annex.clone()];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));

        // Now for keyspend
        let signature = hex!("deadbeef");
        // annex starting with 0x50 causes the branching logic.
        let annex = hex!("50");

        let witness_vec = vec![signature.clone()];
        let witness_vec_annex = vec![signature.clone(), annex.clone()];

        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness_serialized_annex: Vec<u8> = serialize(&witness_vec_annex);

        let witness = deserialize::<Witness>(&witness_serialized[..]).unwrap();
        let witness_annex = deserialize::<Witness>(&witness_serialized_annex[..]).unwrap();

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.taproot_annex(), None);
        assert_eq!(witness_annex.taproot_annex(), Some(&annex[..]));
    }

    #[test]
    fn test_tx() {
        const S: &str = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = hex!(S);
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i, wit_el) in tx.input[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_lower_hex_string());
        }
        assert_eq!(expected_wit[1], tx.input[0].witness.last().unwrap().to_lower_hex_string());
        assert_eq!(
            expected_wit[0],
            tx.input[0].witness.second_to_last().unwrap().to_lower_hex_string()
        );
        assert_eq!(expected_wit[0], tx.input[0].witness.nth(0).unwrap().to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.input[0].witness.nth(1).unwrap().to_lower_hex_string());
        assert_eq!(None, tx.input[0].witness.nth(2));
        assert_eq!(expected_wit[0], tx.input[0].witness[0].to_lower_hex_string());
        assert_eq!(expected_wit[1], tx.input[0].witness[1].to_lower_hex_string());

        let tx_bytes_back = serialize(&tx);
        assert_eq!(tx_bytes_back, tx_bytes);
    }

    #[test]
    fn fuzz_cases() {
        let bytes = hex!("26ff0000000000c94ce592cf7a4cbb68eb00ce374300000057cd0000000000000026");
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation

        let bytes = hex!("24000000ffffffffffffffffffffffff");
        assert!(deserialize::<Witness>(&bytes).is_err()); // OversizedVectorAllocation
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

        witness.push(&[0_u8]);
        witness.push(&[1_u8; 32]);
        witness.push(&[2_u8; 72]);

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

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Witness;

    #[bench]
    pub fn bench_big_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = [[1u8]; 5];
        let witness = Witness::from_slice(&raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }

    #[bench]
    pub fn bench_witness_to_vec(bh: &mut Bencher) {
        let raw_witness = vec![vec![1u8]; 3];
        let witness = Witness::from_slice(&raw_witness);

        bh.iter(|| {
            black_box(witness.to_vec());
        });
    }
}
