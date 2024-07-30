// SPDX-License-Identifier: CC0-1.0

//! A witness.
//!
//! This module contains the [`Witness`] struct and related methods to operate on it

use core::fmt;
use core::ops::Index;

use crate::prelude::Vec;
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
    /// Does not include the initial varint indicating the number of elements, instead this is
    /// stored stored in `witness_elements`. Concatenated onto the end of `content` is the index
    /// area, this is a `4 * witness_elements` bytes area which stores the index of the start of
    /// each witness item.
    content: Vec<u8>,

    /// The number of elements in the witness.
    ///
    /// Stored separately (instead of as a VarInt in the initial part of content) so that methods
    /// like [`Witness::push`] don't have to shift the entire array.
    witness_elements: usize,

    /// This is the valid index pointing to the beginning of the index area.
    ///
    /// Said another way, this is the total length of all witness elements serialized (without the
    /// element count but with their sizes serialized as compact size).
    indices_start: usize,
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        todo!()
    }
}

impl Witness {
    /// Creates a new empty [`Witness`].
    #[inline]
    pub const fn new() -> Self {
        Witness { content: Vec::new(), witness_elements: 0, indices_start: 0 }
    }

    /// Convenience method to create an array of byte-arrays from this witness.
    pub fn to_bytes(&self) -> Vec<Vec<u8>> { self.iter().map(|s| s.to_vec()).collect() }

    /// Convenience method to create an array of byte-arrays from this witness.
    #[deprecated(since = "TBD", note = "Use to_bytes instead")]
    pub fn to_vec(&self) -> Vec<Vec<u8>> { self.to_bytes() }

    /// Returns `true` if the witness contains no element.
    pub fn is_empty(&self) -> bool { self.witness_elements == 0 }

    /// Returns the number of elements this witness holds.
    pub fn len(&self) -> usize { self.witness_elements }

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
        let pos = decode_cursor(&self.content, self.indices_start, index)?;
        self.element_at(pos)
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
