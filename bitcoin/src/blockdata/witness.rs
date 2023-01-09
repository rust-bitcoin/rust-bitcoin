// SPDX-License-Identifier: CC0-1.0

//! Witness
//!
//! This module contains the [`Witness`] struct and related methods to operate on it
//!

use core::convert::TryInto;
use core::ops::Index;

use secp256k1::ecdsa;

use crate::consensus::encode::{Error, MAX_VEC_SIZE};
use crate::consensus::{Decodable, Encodable, WriteExt};
use crate::sighash::EcdsaSighashType;
use crate::io::{self, Read, Write};
use crate::prelude::*;
use crate::{Script, VarInt};
use crate::taproot::TAPROOT_ANNEX_PREFIX;

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
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Witness {
    /// Contains the witness `Vec<Vec<u8>>` serialization without the initial varint indicating the
    /// number of elements (which is stored in `witness_elements`).
    content: Vec<u8>,

    /// The number of elements in the witness.
    ///
    /// Stored separately (instead of as a VarInt in the initial part of content) so that methods
    /// like [`Witness::push`] don't have to shift the entire array.
    witness_elements: usize,

    /// This is the valid index pointing to the beginning of the index area. This area is 4 *
    /// stack_size bytes at the end of the content vector which stores the indices of each item.
    indices_start: usize,
}

/// An iterator returning individual witness elements.
pub struct Iter<'a> {
    inner: &'a [u8],
    indices_start: usize,
    current_index: usize,
}

impl Decodable for Witness {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let witness_elements = VarInt::consensus_decode(r)?.0 as usize;
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
                let element_size_varint = VarInt::consensus_decode(r)?;
                let element_size_varint_len = element_size_varint.len();
                let element_size = element_size_varint.0 as usize;
                let required_len = cursor
                    .checked_add(element_size)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::max_value(),
                        max: MAX_VEC_SIZE,
                    })?
                    .checked_add(element_size_varint_len)
                    .ok_or(self::Error::OversizedVectorAllocation {
                        requested: usize::max_value(),
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
                element_size_varint
                    .consensus_encode(&mut &mut content[cursor..cursor + element_size_varint_len])?;
                cursor += element_size_varint_len;
                r.read_exact(&mut content[cursor..cursor + element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            // Index space is now at the end of the Vec
            content.rotate_left(witness_index_space);
            Ok(Witness {
                content,
                witness_elements,
                indices_start: cursor - witness_index_space,
            })
        }
    }
}


/// Correctness Requirements: value must always fit within u32
#[inline]
fn encode_cursor(bytes: &mut [u8], start_of_indices: usize, index: usize, value: usize) {
    let start = start_of_indices + index * 4;
    let end = start + 4;
    bytes[start..end].copy_from_slice(&u32::to_ne_bytes(value.try_into().expect("Larger than u32")));
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
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = VarInt(self.witness_elements as u64);
        len.consensus_encode(w)?;
        let content_with_indices_len = self.content.len();
        let indices_size = self.witness_elements * 4;
        let content_len = content_with_indices_len - indices_size;
        w.emit_slice(&self.content[..content_len])?;
        Ok(content_len + len.len())
    }
}

impl Witness {
    /// Creates a new empty [`Witness`].
    pub fn new() -> Self {
        Witness::default()
    }

    /// Creates [`Witness`] object from an array of byte-arrays
    #[deprecated(since="0.30.0", note="use `Witness::from_slice()` instead")]
    pub fn from_vec(vec: Vec<Vec<u8>>) -> Self {
        Witness::from_slice(&vec)
    }

    /// Creates a [`Witness`] object from a slice of bytes slices where each slice is a witness item.
    pub fn from_slice<T: AsRef<[u8]>>(slice: &[T]) -> Self {
        let witness_elements = slice.len();
        let index_size = witness_elements * 4;
        let content_size = slice
            .iter()
            .map(|elem| elem.as_ref().len() + VarInt(elem.as_ref().len() as u64).len())
            .sum();

        let mut content = vec![0u8; content_size + index_size];
        let mut cursor = 0usize;
        for (i, elem) in slice.iter().enumerate() {
            encode_cursor(&mut content, content_size, i, cursor);
            let elem_len_varint = VarInt(elem.as_ref().len() as u64);
            elem_len_varint
                .consensus_encode(&mut &mut content[cursor..cursor + elem_len_varint.len()])
                .expect("writers on vec don't errors, space granted by content_size");
            cursor += elem_len_varint.len();
            content[cursor..cursor + elem.as_ref().len()].copy_from_slice(elem.as_ref());
            cursor += elem.as_ref().len();
        }

        Witness {
            witness_elements,
            content,
            indices_start: content_size,
        }
    }

    /// Convenience method to create an array of byte-arrays from this witness.
    pub fn to_vec(&self) -> Vec<Vec<u8>> {
        self.iter().map(|s| s.to_vec()).collect()
    }

    /// Returns `true` if the witness contains no element.
    pub fn is_empty(&self) -> bool {
        self.witness_elements == 0
    }

    /// Returns a struct implementing [`Iterator`].
    pub fn iter(&self) -> Iter {
        Iter {
            inner: self.content.as_slice(),
            indices_start: self.indices_start,
            current_index: 0,
        }
    }

    /// Returns the number of elements this witness holds.
    pub fn len(&self) -> usize {
        self.witness_elements
    }

    /// Returns the bytes required when this Witness is consensus encoded.
    pub fn serialized_len(&self) -> usize {
        self.iter()
            .map(|el| VarInt(el.len() as u64).len() + el.len())
            .sum::<usize>()
            + VarInt(self.witness_elements as u64).len()
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
        let element_len_varint = VarInt(new_element.len() as u64);
        let current_content_len = self.content.len();
        let new_item_total_len = element_len_varint.len() + new_element.len();
        self.content
            .resize(current_content_len + new_item_total_len + 4, 0);

        self.content[previous_content_end..].rotate_right(new_item_total_len);
        self.indices_start += new_item_total_len;
        encode_cursor(&mut self.content, self.indices_start, self.witness_elements - 1, previous_content_end);

        let end_varint = previous_content_end + element_len_varint.len();
        element_len_varint
            .consensus_encode(&mut &mut self.content[previous_content_end..end_varint])
            .expect("writers on vec don't error, space granted through previous resize");
        self.content[end_varint..end_varint + new_element.len()].copy_from_slice(new_element);
    }

    /// Pushes a DER-encoded ECDSA signature with a signature hash type as a new element on the
    /// witness, requires an allocation.
    pub fn push_bitcoin_signature(&mut self, signature: &ecdsa::SerializedSignature, hash_type: EcdsaSighashType) {
        // Note that a maximal length ECDSA signature is 72 bytes, plus the sighash type makes 73
        let mut sig = [0; 73];
        sig[..signature.len()].copy_from_slice(signature);
        sig[signature.len()] = hash_type as u8;
        self.push(&sig[..signature.len() + 1]);
    }


    fn element_at(&self, index: usize) -> Option<&[u8]> {
        let varint = VarInt::consensus_decode(&mut &self.content[index..]).ok()?;
        let start = index + varint.len();
        Some(&self.content[start..start + varint.0 as usize])
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
    /// the first byte of the last element being equal to 0x50. See
    /// [Script::is_v1_p2tr](crate::blockdata::script::Script::is_v1_p2tr) to
    /// check whether this is actually a Taproot witness.
    pub fn tapscript(&self) -> Option<&Script> {
        let len = self.len();
        self
            .last()
            .map(|last_elem| {
                // From BIP341:
                // If there are at least two witness elements, and the first byte of
                // the last element is 0x50, this last element is called annex a
                // and is removed from the witness stack.
                if len >= 2 && last_elem.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                    // account for the extra item removed from the end
                    3
                } else {
                    // otherwise script is 2nd from last
                    2
                }
            })
            .filter(|&script_pos_from_last| len >= script_pos_from_last)
            .and_then(|script_pos_from_last| {
                self.nth(len - script_pos_from_last)
            })
            .map(Script::from_bytes)
    }
}

impl Index<usize> for Witness {
    type Output = [u8];

    fn index(&self, index: usize) -> &Self::Output {
        self.nth(index).expect("Out of Bounds")
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let index = decode_cursor(self.inner, self.indices_start, self.current_index)?;
        let varint = VarInt::consensus_decode(&mut &self.inner[index..]).ok()?;
        let start = index + varint.len();
        let end = start + varint.0 as usize;
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

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
        struct Visitor;         // Human-readable visitor.
        impl<'de> serde::de::Visitor<'de> for Visitor
        {
            type Value = Witness;

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "a sequence of hex arrays")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error>
            {
                use crate::hashes::hex::FromHex;
                use crate::hashes::hex::Error::*;
                use serde::de::{self, Unexpected};

                let mut ret = match a.size_hint() {
                    Some(len) => Vec::with_capacity(len),
                    None => Vec::new(),
                };

                while let Some(elem) = a.next_element::<String>()? {
                    let vec = Vec::<u8>::from_hex(&elem).map_err(|e| {
                        match e {
                            InvalidChar(b) => {
                                match core::char::from_u32(b.into()) {
                                    Some(c) => de::Error::invalid_value(Unexpected::Char(c), &"a valid hex character"),
                                    None => de::Error::invalid_value(Unexpected::Unsigned(b.into()), &"a valid hex character")
                                }
                            }
                            OddLengthString(len) => de::Error::invalid_length(len, &"an even length string"),
                            InvalidLength(expected, got) => {
                                let exp = format!("expected length: {}", expected);
                                de::Error::invalid_length(got, &exp.as_str())
                            }
                        }
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
    fn from(vec: Vec<Vec<u8>>) -> Self {
        Witness::from_slice(&vec)
    }
}

impl From<&[&[u8]]> for Witness {
    fn from(slice: &[&[u8]]) -> Self {
        Witness::from_slice(slice)
    }
}

impl From<&[Vec<u8>]> for Witness {
    fn from(slice: &[Vec<u8>]) -> Self {
        Witness::from_slice(slice)
    }
}

impl From<Vec<&[u8]>> for Witness {
    fn from(vec: Vec<&[u8]>) -> Self {
        Witness::from_slice(&vec)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::consensus::{deserialize, serialize};
    use crate::internal_macros::hex;
    use crate::Transaction;
    use crate::secp256k1::ecdsa;

    fn append_u32_vec(mut v: Vec<u8>, n: &[u32]) -> Vec<u8> {
        for &num in n {
            v.extend_from_slice(&num.to_ne_bytes());
        }
        v
    }

    #[test]
    fn test_push() {
        let mut witness = Witness::default();
        assert_eq!(witness.last(), None);
        assert_eq!(witness.second_to_last(), None);
        assert_eq!(witness.nth(0), None);
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        witness.push(&vec![0u8]);
        let expected = Witness {
            witness_elements: 1,
            content: append_u32_vec(vec![1u8, 0], &[0]),
            indices_start: 2,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[0u8][..]));
        assert_eq!(witness.second_to_last(), None);
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), None);
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        witness.push(&vec![2u8, 3u8]);
        let expected = Witness {
            witness_elements: 2,
            content: append_u32_vec(vec![1u8, 0, 2, 2, 3], &[0, 2]),
            indices_start: 5,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.second_to_last(), Some(&[0u8][..]));
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(2), None);
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        assert_eq!(&witness[1], &[2u8, 3u8][..]);
        witness.push(&vec![4u8, 5u8]);
        let expected = Witness {
            witness_elements: 3,
            content: append_u32_vec(vec![1u8, 0, 2, 2, 3, 2, 4, 5], &[0, 2, 5]),
            indices_start: 8,
        };
        assert_eq!(witness, expected);
        assert_eq!(witness.last(), Some(&[4u8, 5u8][..]));
        assert_eq!(witness.second_to_last(), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(0), Some(&[0u8][..]));
        assert_eq!(witness.nth(1), Some(&[2u8, 3u8][..]));
        assert_eq!(witness.nth(2), Some(&[4u8, 5u8][..]));
        assert_eq!(witness.nth(3), None);
        assert_eq!(&witness[0], &[0u8][..]);
        assert_eq!(&witness[1], &[2u8, 3u8][..]);
        assert_eq!(&witness[2], &[4u8, 5u8][..]);
    }


    #[test]
    fn test_iter_len() {
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
        let sig = ecdsa::Signature::from_der(&sig_bytes).unwrap();
        let mut witness = Witness::default();
        witness.push_bitcoin_signature(&sig.serialize_der(), EcdsaSighashType::All);
        let expected_witness = vec![hex!(
            "304402207c800d698f4b0298c5aac830b822f011bb02df41eb114ade9a6702f364d5e39c0220366900d2a60cab903e77ef7dd415d46509b1f78ac78906e3296f495aa1b1b54101")
            ];
        assert_eq!(witness.to_vec(), expected_witness);
    }

    #[test]
    fn test_witness() {
        let w0 =
            hex!("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105");
        let w1 = hex!("000000");
        let witness_vec = vec![w0.clone(), w1.clone()];
        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness = Witness {
            content: append_u32_vec(witness_serialized[1..].to_vec(), &[0, 34]),
            witness_elements: 2,
            indices_start: 38,
        };
        for (i, el) in witness.iter().enumerate() {
            assert_eq!(witness_vec[i], el);
        }
        assert_eq!(witness.last(), Some(&w1[..]));
        assert_eq!(witness.second_to_last(), Some(&w0[..]));
        assert_eq!(witness.nth(0), Some(&w0[..]));
        assert_eq!(witness.nth(1), Some(&w1[..]));
        assert_eq!(witness.nth(2), None);
        assert_eq!(&witness[0], &w0[..]);
        assert_eq!(&witness[1], &w1[..]);

        let w_into = Witness::from_slice(&witness_vec);
        assert_eq!(w_into, witness);

        assert_eq!(witness_serialized, serialize(&witness));
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

        let witness = Witness {
            content: append_u32_vec(witness_serialized[1..].to_vec(), &[0, 5]),
            witness_elements: 2,
            indices_start: 7,
        };
        let witness_annex = Witness {
            content: append_u32_vec(witness_serialized_annex[1..].to_vec(), &[0, 5, 7]),
            witness_elements: 3,
            indices_start: 9,
        };

        // With or without annex, the tapscript should be returned.
        assert_eq!(witness.tapscript(), Some(Script::from_bytes(&tapscript[..])));
        assert_eq!(witness_annex.tapscript(), Some(Script::from_bytes(&tapscript[..])));
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
        assert_eq!(expected_wit[0], tx.input[0].witness.second_to_last().unwrap().to_lower_hex_string());
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

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_bincode() {
        use bincode;

        let old_witness_format = vec![vec![0u8], vec![2]];
        let new_witness_format = Witness::from_slice(&old_witness_format);

        let old = bincode::serialize(&old_witness_format).unwrap();
        let new = bincode::serialize(&new_witness_format).unwrap();

        assert_eq!(old, new);

        let back: Witness = bincode::deserialize(&new).unwrap();
        assert_eq!(new_witness_format, back);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_human() {
        use serde_json;

        let witness = Witness::from_slice(&[vec![0u8, 123, 75], vec![2u8, 6, 3, 7, 8]]);

        let json = serde_json::to_string(&witness).unwrap();

        assert_eq!(json, r#"["007b4b","0206030708"]"#);

        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, back);
    }
}


#[cfg(bench)]
mod benches {
    use test::{Bencher, black_box};
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
