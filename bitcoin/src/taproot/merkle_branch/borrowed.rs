use core::borrow::{Borrow, BorrowMut};

use internals::slice::SliceExt;
pub use privacy_boundary::TaprootMerkleBranch;

use super::{
    DecodeError, InvalidMerkleBranchSizeError, InvalidMerkleTreeDepthError, TapNodeHash,
    TaprootMerkleBranchBuf, TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_NODE_SIZE,
};

/// Makes sure only the allowed conversions are accessible to external code.
mod privacy_boundary {
    use super::*;

    /// The Merkle proof for inclusion of a tree in a Taproot tree hash.
    #[repr(transparent)]
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TaprootMerkleBranch([TapNodeHash]);

    impl TaprootMerkleBranch {
        /// Returns a reference to the slice of hashes.
        #[inline]
        pub const fn as_slice(&self) -> &[TapNodeHash] { &self.0 }

        /// Returns a reference to the mutable slice of hashes.
        #[inline]
        pub fn as_mut_slice(&mut self) -> &mut [TapNodeHash] { &mut self.0 }

        pub(super) const fn from_hashes_unchecked(hashes: &[TapNodeHash]) -> &Self {
            unsafe { &*(hashes as *const _ as *const Self) }
        }

        pub(super) fn from_mut_hashes_unchecked(hashes: &mut [TapNodeHash]) -> &mut Self {
            unsafe { &mut *(hashes as *mut _ as *mut Self) }
        }
    }
}

impl TaprootMerkleBranch {
    /// Returns an empty branch.
    pub const fn new() -> &'static Self { Self::from_hashes_unchecked(&[]) }

    /// Returns the number of nodes in this Merkle proof.
    #[inline]
    pub fn len(&self) -> usize { self.as_slice().len() }

    /// Checks if this Merkle proof is empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.as_slice().is_empty() }

    /// Creates an iterator over the node hashes.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, TapNodeHash> { self.into_iter() }

    /// Creates an iterator over the mutable node hashes.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, TapNodeHash> { self.into_iter() }

    /// Casts `TaprootMerkleBranch` to a byte slice.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        let ptr = self.as_slice().as_ptr();
        let num_bytes = self.len() * TAPROOT_CONTROL_NODE_SIZE;
        // SAFETY:
        // The pointer points to memory that's borrowed and the returned slice has the same
        // lifetime. The alignment is of the types is the same (as checked in the test), the
        // length is within the bounds - as computed above by multiplication.
        unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), num_bytes) }
    }

    /// Serializes to a writer.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the writer.
    pub fn encode<Write: io::Write + ?Sized>(&self, writer: &mut Write) -> io::Result<usize> {
        let bytes = self.as_bytes();
        writer.write_all(bytes)?;
        Ok(bytes.len())
    }

    /// Zero-copy decodes `bytes` as Taproot Merkle branch.
    ///
    /// Note that "decoding" is quite trivial: it only performs appropriate bound checks and casts
    /// the reference.
    pub fn decode(bytes: &[u8]) -> Result<&Self, DecodeError> {
        let (nodes, remainder) = bytes.bitcoin_as_chunks();
        if remainder.is_empty() {
            Self::decode_exact(nodes).map_err(Into::into)
        } else {
            Err(InvalidMerkleBranchSizeError(bytes.len()).into())
        }
    }

    /// Decodes a byte slice that is statically known to be multiple of 32.
    ///
    /// This can be used as a building block for other ways of decoding.
    fn decode_exact(
        nodes: &[[u8; TAPROOT_CONTROL_NODE_SIZE]],
    ) -> Result<&Self, InvalidMerkleTreeDepthError> {
        // SAFETY:
        // The lifetime of the returned reference is the same as the lifetime of the input
        // reference, the size of `TapNodeHash` is equal to `TAPROOT_CONTROL_NODE_SIZE` and the
        // alignment of `TapNodeHash` is equal to the alignment of `u8` (see tests below).
        Self::from_hashes(unsafe { &*(nodes as *const _ as *const [TapNodeHash]) })
    }

    fn from_hashes(nodes: &[TapNodeHash]) -> Result<&Self, InvalidMerkleTreeDepthError> {
        if nodes.len() <= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Ok(Self::from_hashes_unchecked(nodes))
        } else {
            Err(InvalidMerkleTreeDepthError(nodes.len()))
        }
    }
}

impl Default for &'_ TaprootMerkleBranch {
    fn default() -> Self { TaprootMerkleBranch::new() }
}

impl AsRef<TaprootMerkleBranch> for TaprootMerkleBranch {
    fn as_ref(&self) -> &TaprootMerkleBranch { self }
}

impl AsMut<TaprootMerkleBranch> for TaprootMerkleBranch {
    fn as_mut(&mut self) -> &mut TaprootMerkleBranch { self }
}

impl AsRef<TaprootMerkleBranch> for TaprootMerkleBranchBuf {
    fn as_ref(&self) -> &TaprootMerkleBranch {
        // TaprootMerkleBranchBuf maintains the invariant that the node count is in range.
        TaprootMerkleBranch::from_hashes_unchecked(self.as_slice())
    }
}

impl AsMut<TaprootMerkleBranch> for TaprootMerkleBranchBuf {
    fn as_mut(&mut self) -> &mut TaprootMerkleBranch {
        // TaprootMerkleBranchBuf maintains the invariant that the node count is in range.
        TaprootMerkleBranch::from_mut_hashes_unchecked(self.as_mut_slice())
    }
}

impl Borrow<TaprootMerkleBranch> for TaprootMerkleBranchBuf {
    #[inline]
    fn borrow(&self) -> &TaprootMerkleBranch { self.as_ref() }
}

impl BorrowMut<TaprootMerkleBranch> for TaprootMerkleBranchBuf {
    #[inline]
    fn borrow_mut(&mut self) -> &mut TaprootMerkleBranch { self.as_mut() }
}

impl<'a> TryFrom<&'a [TapNodeHash]> for &'a TaprootMerkleBranch {
    type Error = InvalidMerkleTreeDepthError;

    fn try_from(value: &'a [TapNodeHash]) -> Result<Self, Self::Error> {
        TaprootMerkleBranch::from_hashes(value)
    }
}

macro_rules! impl_from_array {
    ($($len:expr),* $(,)?) => {
        $(
            impl AsRef<TaprootMerkleBranch> for [TapNodeHash; $len] {
                fn as_ref(&self) -> &TaprootMerkleBranch {
                    #[allow(unused_comparisons)]
                    const _: () = { assert!($len <= TAPROOT_CONTROL_MAX_NODE_COUNT) };
                    // There's a static check to ensure correct macro usage above.
                    TaprootMerkleBranch::from_hashes_unchecked(self)
                }
            }

            impl AsMut<TaprootMerkleBranch> for [TapNodeHash; $len] {
                fn as_mut(&mut self) -> &mut TaprootMerkleBranch {
                    #[allow(unused_comparisons)]
                    const _: () = { assert!($len <= TAPROOT_CONTROL_MAX_NODE_COUNT) };
                    // There's a static check to ensure correct macro usage above.
                    TaprootMerkleBranch::from_mut_hashes_unchecked(self)
                }
            }

            impl Borrow<TaprootMerkleBranch> for [TapNodeHash; $len] {
                fn borrow(&self) -> &TaprootMerkleBranch {
                    self.as_ref()
                }
            }

            impl BorrowMut<TaprootMerkleBranch> for [TapNodeHash; $len] {
                fn borrow_mut(&mut self) -> &mut TaprootMerkleBranch {
                    self.as_mut()
                }
            }

            impl<'a> From<&'a [TapNodeHash; $len]> for &'a TaprootMerkleBranch {
                #[inline]
                fn from(branch: &'a [TapNodeHash; $len]) -> Self {
                    branch.as_ref()
                }
            }

            impl<'a> From<&'a mut [TapNodeHash; $len]> for &'a mut TaprootMerkleBranch {
                #[inline]
                fn from(branch: &'a mut [TapNodeHash; $len]) -> Self {
                    branch.as_mut()
                }
            }
        )*
    }
}

// Implement for all values [0, 128] inclusive.
//
// The reason zero is included is that `TaprootMerkleBranchBuf` doesn't contain the hash of the node
// that's being proven - it's not needed because the script is already right before control block.
impl_from_array!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128
);

impl AsRef<[TapNodeHash]> for TaprootMerkleBranch {
    #[inline]
    fn as_ref(&self) -> &[TapNodeHash] { self.as_slice() }
}

impl AsMut<[TapNodeHash]> for TaprootMerkleBranch {
    #[inline]
    fn as_mut(&mut self) -> &mut [TapNodeHash] { self.as_mut_slice() }
}

impl Borrow<[TapNodeHash]> for TaprootMerkleBranch {
    #[inline]
    fn borrow(&self) -> &[TapNodeHash] { self.as_ref() }
}

impl BorrowMut<[TapNodeHash]> for TaprootMerkleBranch {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [TapNodeHash] { self.as_mut() }
}

impl alloc::borrow::ToOwned for TaprootMerkleBranch {
    // It could be argued that this should've been a stack-allocated type.
    // However such type would be huge and this trait interacts with `Cow`.
    // If someone wants to pass it around they're better off just always copying rather than using
    // `Cow`.
    type Owned = TaprootMerkleBranchBuf;

    fn to_owned(&self) -> Self::Owned { self.into() }
}

impl<'a> IntoIterator for &'a TaprootMerkleBranch {
    type IntoIter = core::slice::Iter<'a, TapNodeHash>;
    type Item = &'a TapNodeHash;

    fn into_iter(self) -> Self::IntoIter { self.as_slice().iter() }
}

impl<'a> IntoIterator for &'a mut TaprootMerkleBranch {
    type IntoIter = core::slice::IterMut<'a, TapNodeHash>;
    type Item = &'a mut TapNodeHash;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.as_mut_slice().iter_mut() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn alignment() {
        assert!(
            core::mem::align_of_val(super::TaprootMerkleBranch::new())
                == core::mem::align_of::<u8>()
        );
    }

    const _: () = {
        assert!(core::mem::size_of::<super::TapNodeHash>() == super::TAPROOT_CONTROL_NODE_SIZE);
        assert!(core::mem::align_of::<super::TapNodeHash>() == core::mem::align_of::<u8>());
    };
}
